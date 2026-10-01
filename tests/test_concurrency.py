"""Concurrency snapshot tests for KeyRing.load.

Covers the acceptance surface:
* same-instance threads: revoke/set-active cannot commit while a load has the
  document snapshot open;
* multiple processes: a revoke started during a load completes only after the
  load's pre-revocation result, and a later load sees RevokedVersionError;
* pre-completed changes are observed in full, in-flight loads never see a
  middle state;
* write-lock TimeoutError and every pre-existing error type/wording, plus the
  CLI exit codes (revoked -> 2) and the unchanged report JSON shape.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from seal_derive import core
from seal_derive.__main__ import main as cli_main

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKER = Path(__file__).resolve().parent / "_load_worker.py"
LOCK_HOLDER = Path(__file__).resolve().parent / "_lock_holder.py"
KEY = "k"
PASSWORD = "correct horse"


class KeyRingTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def seal_pair(self, first: str = "one", second: str = "two") -> tuple[int, int]:
        v1 = self.ring.seal(KEY, first, PASSWORD, iterations=2_000)
        v2 = self.ring.seal(KEY, second, PASSWORD, iterations=2_000)
        return v1, v2

    @staticmethod
    def _wait_for(marker: Path, label: str) -> None:
        deadline = time.monotonic() + 5
        while not marker.is_file() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.is_file(), f"{label} never happened"


class ThreadSnapshotTests(KeyRingTestBase):
    """revoke/set-active must wait for an in-flight load to finish."""

    def _blocking_derive(self, entered: threading.Event, release: threading.Event):
        real_derive = core._derive

        def slow_derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
            # Runs inside load's shared-lock snapshot, before the revocation
            # check that matters for the *next* load.
            entered.set()
            self.assertTrue(release.wait(timeout=5), "test harness deadlocked")
            return real_derive(password, salt, iterations, length)

        return slow_derive

    def test_revoke_cannot_commit_during_load(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=2_000)
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        result: dict[str, object] = {}
        original = core._derive
        core._derive = self._blocking_derive(entered, release)
        try:
            def loader() -> None:
                try:
                    result["material"] = self.ring.load(KEY, password=PASSWORD)
                except Exception as error:  # noqa: BLE001 - surfaced via result
                    result["error"] = error

            load_thread = threading.Thread(target=loader)
            load_thread.start()
            self.assertTrue(entered.wait(timeout=5), "load never entered its snapshot")

            def revoker() -> None:
                self.ring.revoke(KEY, 1)
                done.set()

            revoke_thread = threading.Thread(target=revoker)
            revoke_thread.start()
            # revoke is a few milliseconds of work once it holds the lock.
            # Under the old baseline the load's lock was released before
            # decryption, so this fired while the load was still in flight.
            time.sleep(0.4)
            self.assertFalse(done.is_set(), "revoke committed while load was still open")

            release.set()
            load_thread.join(timeout=5)
            revoke_thread.join(timeout=5)
        finally:
            core._derive = original
        self.assertEqual(result, {"material": b"secret"})
        self.assertTrue(done.is_set())
        # The completed load is not retroactively denied...
        self.assertEqual(result["material"], b"secret")
        # ...but every later load resolves against the post-revoke state.
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY, password=PASSWORD)

    def test_revoke_completed_before_load_is_observed(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=2_000)
        self.ring.revoke(KEY, 1)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY, password=PASSWORD)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY, version=1, password=PASSWORD)

    def test_set_active_cannot_commit_during_default_load(self) -> None:
        self.seal_pair()
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        result: dict[str, object] = {}
        original = core._derive
        core._derive = self._blocking_derive(entered, release)
        try:
            load_thread = threading.Thread(
                target=lambda: result.setdefault("material", self.ring.load(KEY, password=PASSWORD)))
            load_thread.start()
            self.assertTrue(entered.wait(timeout=5))

            def switcher() -> None:
                self.ring.set_active(KEY, 1)
                done.set()

            switch_thread = threading.Thread(target=switcher)
            switch_thread.start()
            time.sleep(0.4)
            self.assertFalse(done.is_set(), "set-active committed during a default load")
            release.set()
            load_thread.join(timeout=5)
            switch_thread.join(timeout=5)
        finally:
            core._derive = original
        # The default version (active=2) was resolved in the same snapshot that
        # produced the material: no half-resolved active.
        self.assertEqual(result["material"], b"two")
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"one")

    def test_many_threads_either_pre_or_post_state(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        # Deterministic phases: all loaders observe the pre-revoke state, then
        # one revoke commits, then every load sees the post-revoke state. Under
        # the old baseline a load that read its record before phase two could
        # still be sitting in PBKDF2 when revoke committed -- indistinguishable
        # from a revoked record handed out after the fact. The snapshot makes
        # the boundary exact; additionally each loader's view is monotone.
        loader_count = 7
        phase_one = threading.Barrier(loader_count + 1)
        phase_two = threading.Barrier(loader_count + 1)
        before: list[str] = []
        after: list[list[str]] = [[] for _ in range(loader_count)]
        state_lock = threading.Lock()

        def make_loader(slot: int):
            def run() -> None:
                material = self.ring.load(KEY, password=PASSWORD)
                with state_lock:
                    before.append(material.decode("utf-8"))
                phase_one.wait()
                phase_two.wait()
                for _ in range(20):
                    try:
                        value = self.ring.load(KEY, password=PASSWORD).decode("utf-8")
                    except core.RevokedVersionError:
                        value = "revoked"
                    after[slot].append(value)
            return run

        threads = [threading.Thread(target=make_loader(i)) for i in range(loader_count)]
        for thread in threads:
            thread.start()
        phase_one.wait()
        self.assertEqual(before, ["secret"] * loader_count)
        self.ring.revoke(KEY, 1)
        phase_two.wait()
        for thread in threads:
            thread.join(timeout=15)
        flat = [value for sequence in after for value in sequence]
        self.assertEqual(set(flat), {"revoked"})
        for sequence in after:
            self.assertTrue(sequence and all(value == "revoked" for value in sequence))


class ProcessSnapshotTests(KeyRingTestBase):
    """The same guarantee across independent Python processes."""

    def _start_load_worker(self, rounds: int, stagger: float = 0.0) -> subprocess.Popen:
        env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
        ready = self.root / "worker.ready"
        entered = self.root / "worker.entered"
        return subprocess.Popen(
            [sys.executable, str(WORKER), str(self.root), KEY, PASSWORD,
             str(ready), str(entered), str(stagger), str(rounds)],
            cwd=PROJECT_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def _cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)

    def test_revoke_during_load_commits_after_load(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=2_000)
        ready, entered = self.root / "worker.ready", self.root / "worker.entered"
        worker = self._start_load_worker(rounds=1)
        try:
            self._wait_for(ready, "worker startup")
            self._wait_for(entered, "worker load snapshot")
            # The snapshot is open (slowed PBKDF2 holds it ~0.8s). Start the
            # revoke now: under the old baseline the load's file lock was
            # released before decryption, so the revoke committed at once.
            revoke_started = time.monotonic()
            revoke = self._cli("revoke", KEY, "1")
            revoke_finished = time.monotonic()
            self.assertEqual(revoke.returncode, 0, revoke.stderr)
            stdout, stderr = worker.communicate(timeout=15)
        finally:
            worker.wait(timeout=15)
        self.assertEqual(stderr, "", stderr)
        # The in-flight load completed against its pre-revoke snapshot.
        self.assertEqual(stdout.split(), ["ok:secret"], stdout)
        # It queued behind the shared-lock snapshot for most of the ~0.8s
        # window instead of committing immediately.
        self.assertGreater(revoke_finished - revoke_started, 0.4)
        # A completed load is not retroactively denied; later loads see the
        # committed revocation (CLI default version and explicit version).
        self.assertEqual(self._cli("load", KEY, "--password", PASSWORD).returncode, 2)
        self.assertEqual(self._cli("load", KEY, "--version", "1", "--password", PASSWORD).returncode, 2)

    def test_revoke_before_separate_process_load(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=2_000)
        self.assertEqual(self._cli("revoke", KEY, "1").returncode, 0)
        ready = self.root / "worker.ready"
        worker = self._start_load_worker(rounds=1)
        try:
            stdout, stderr = worker.communicate(timeout=15)
        finally:
            worker.wait(timeout=15)
        self.assertEqual(stderr, "", stderr)
        self.assertEqual(stdout.split(), ["revoked"])


class CompatibilityTests(KeyRingTestBase):
    """Existing entry points, error types and wordings stay unchanged."""

    def test_plain_and_sealed_return_utf8_bytes(self) -> None:
        self.ring.seal("p", "材料-α", iterations=2_000)
        self.assertEqual(self.ring.load("p"), "材料-α".encode("utf-8"))
        v = self.ring.seal("s", "材料-β", PASSWORD, iterations=2_000)
        self.assertEqual(self.ring.load("s", version=v, password=PASSWORD), "材料-β".encode("utf-8"))
        self.assertEqual(self.ring.active("s"), v)
        self.assertEqual(self.ring.versions("s"), [v])
        self.assertFalse(self.ring.is_revoked("s", v))

    def test_missing_password(self) -> None:
        v = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.load(KEY, version=v)

    def test_bad_password(self) -> None:
        v = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.load(KEY, version=v, password="wrong")

    def test_tampered_record(self) -> None:
        v = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        document = json.loads(self.ring.path.read_text(encoding="utf-8"))
        record = document["keys"][KEY]["versions"][0]
        material = bytearray(base64.b64decode(record["material"]))
        material[0] ^= 0x01
        record["material"] = base64.b64encode(bytes(material)).decode("ascii")
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load(KEY, version=v, password=PASSWORD)

    def test_legacy_derived_only_record(self) -> None:
        v = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        document = json.loads(self.ring.path.read_text(encoding="utf-8"))
        document["keys"][KEY]["versions"][0] = {
            "version": v, "scheme": core.LEGACY_DERIVE_SCHEME, "revoked": False}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.load(KEY, version=v, password=PASSWORD)

    def test_unknown_key_and_version(self) -> None:
        self.ring.seal(KEY, "secret")
        with self.assertRaises(KeyError):
            self.ring.load("nope")
        with self.assertRaises(KeyError):
            self.ring.load(KEY, version=99)

    def test_corrupt_keyring_file(self) -> None:
        self.ring.seal(KEY, "secret")
        self.ring.path.write_text("{not json", encoding="utf-8")
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load(KEY)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file permissions")
    def test_unreadable_keyring_file_keeps_type(self) -> None:
        self.ring.seal(KEY, "secret")
        os.chmod(self.ring.path, 0o200)
        try:
            with self.assertRaises(PermissionError):
                self.ring.load(KEY)
        finally:
            os.chmod(self.ring.path, stat.S_IRUSR | stat.S_IWUSR)

    def test_missing_ring_keeps_filenotfound(self) -> None:
        other = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(FileNotFoundError):
            other.load(KEY)

    def test_write_lock_timeout(self) -> None:
        self.ring.seal(KEY, "secret")
        ready = self.root / "holder.ready"
        holder = subprocess.Popen(
            [sys.executable, str(LOCK_HOLDER), str(self.root), "2", str(ready)],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)})
        original_timeout = core.LOCK_TIMEOUT_SECONDS
        core.LOCK_TIMEOUT_SECONDS = 0.3
        try:
            self._wait_for(ready, "lock holder")
            with self.assertRaisesRegex(TimeoutError, "获取密钥环写锁超时"):
                self.ring.revoke(KEY, 1)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)

    def test_thread_lock_timeout(self) -> None:
        self.ring.seal(KEY, "secret")
        entered = threading.Event()
        release = threading.Event()

        def holder() -> None:
            with core._locked(self.ring, exclusive=True):
                entered.set()
                release.wait(timeout=5)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        original_timeout = core.LOCK_TIMEOUT_SECONDS
        core.LOCK_TIMEOUT_SECONDS = 0.3
        try:
            with self.assertRaises(TimeoutError):
                self.ring.versions(KEY)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            release.set()
            thread.join(timeout=5)


class CliTests(KeyRingTestBase):
    def _run(self, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20, input=input_text)

    def test_revoked_load_exit_code_two(self) -> None:
        self.ring.seal(KEY, "secret")
        self.assertEqual(self._run("revoke", KEY, "1").returncode, 0)
        result = self._run("load", KEY)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("已吊销", result.stderr)

    def test_plain_cli_load(self) -> None:
        self.ring.seal(KEY, "secret")
        result = self._run("load", KEY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "secret\n")

    def test_sealed_cli_load_and_errors(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        ok = self._run("load", KEY, "--password", PASSWORD)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(ok.stdout, "secret\n")
        self.assertEqual(self._run("load", KEY).returncode, 1)  # missing password
        self.assertEqual(self._run("load", KEY, "--password", "wrong").returncode, 1)
        self.assertEqual(self._run("load", "missing").returncode, 2)

    def test_set_active_then_default_load(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.assertEqual(self._run("set-active", KEY, "1").returncode, 0)
        result = self._run("load", KEY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "one\n")

    def test_report_shape_unchanged(self) -> None:
        result = self._run("report")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(set(payload),
                         {"domain", "version", "sourceCategories", "tags", "components", "readiness"})
        self.assertEqual(payload["components"], ["keyring", "derive"])
        self.assertEqual(payload["readiness"],
                         {"seal": True, "rotate": True, "revoke": True, "constantTime": False})
        self.assertEqual(payload["domain"], "key-management")
        # sort_keys=True output: keys appear alphabetically in the raw text.
        self.assertEqual(result.stdout.strip(), json.dumps(payload, ensure_ascii=False, sort_keys=True))

    def test_inprocess_cli_revoked_exit_two(self) -> None:
        from io import StringIO
        self.ring.seal(KEY, "secret")
        self.ring.revoke(KEY, 1)
        saved_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            code = cli_main(["--root", str(self.root), "load", KEY])
        finally:
            output = sys.stderr.getvalue()
            sys.stderr = saved_stderr
        self.assertEqual(code, 2)
        self.assertIn("已吊销", output)


if __name__ == "__main__":
    unittest.main()
