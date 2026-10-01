"""Acceptance tests for ``KeyRing.rotate_password`` and the CLI subcommand.

Covers:
* a new v2 record is appended (fresh salt, requested iterations, key/version
  binding) carrying byte-identical recovered material; version = max + 1,
  unrevoked, active; the source and every other record stay untouched;
* plain sources ignore the old passphrase; v1/v2 sources authenticate exactly
  like ``load`` (revoked, legacy derived-only, missing/wrong passphrase,
  structural damage with an otherwise correct passphrase);
* ``revoke_source`` atomically revokes only the source;
* validation precedes storage access and rejects non-strings, bool/non-positive
  iterations and non-bool revoke_source with ValueError;
* empty/Unicode material, empty new password and new == old password;
* concurrency: threads and processes serialise, committed numbers stay
  gapless and unique and active ends on the last committed version;
* failures and lock timeouts never modify keyring.json;
* the CLI: positional key_id, required --new-password, matching options and
  defaults, --revoke-source flag, version-only stdout, exit codes 0/1/2.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from seal_derive import core

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCK_HOLDER = Path(__file__).resolve().parent / "_lock_holder.py"
KEY = "k"
PASSWORD = "correct horse"


class RotateTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _record(self, version: int) -> dict:
        for item in self._document()["keys"][KEY]["versions"]:
            if item["version"] == version:
                return item
        raise KeyError(version)

    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)


class RotateRecordShapeTests(RotateTestBase):
    def test_plain_source_ignores_old_password_and_writes_v2(self) -> None:
        source = self.ring.seal(KEY, "材料-α🔐")
        new = self.ring.rotate_password(KEY, "新口令", password=None, iterations=2_000)
        self.assertEqual(new, source + 1)
        record = self._record(new)
        self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(record["iterations"], 2_000)
        self.assertFalse(record["revoked"])
        self.assertEqual(self.ring.active(KEY), new)
        self.assertEqual(self.ring.versions(KEY), [source, new])
        # Recovered bytes are unchanged and the source plain record survives.
        self.assertEqual(self.ring.load(KEY, password="新口令"), "材料-α🔐".encode("utf-8"))
        self.assertEqual(self.ring.load(KEY, version=source), "材料-α🔐".encode("utf-8"))

    def test_sealed_source_round_trips_under_new_password(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        new = self.ring.rotate_password(KEY, "next", password=PASSWORD)
        self.assertEqual(new, source + 1)
        self.assertEqual(self.ring.load(KEY, password="next"), b"secret")
        # The old password still opens the untouched source only.
        self.assertEqual(self.ring.load(KEY, version=source, password=PASSWORD), b"secret")
        with self.assertRaises(core.BadPasswordError):
            self.ring.load(KEY, version=source, password="next")
        with self.assertRaises(core.BadPasswordError):
            self.ring.load(KEY, password=PASSWORD)

    def test_new_record_gets_fresh_salt_and_bound_tag(self) -> None:
        source = self.ring.seal(KEY, "m", PASSWORD, iterations=1_000)
        new = self.ring.rotate_password(KEY, PASSWORD, password=PASSWORD, iterations=3_000)
        old, fresh = self._record(source), self._record(new)
        self.assertNotEqual(old["salt"], fresh["salt"])
        self.assertEqual(fresh["iterations"], 3_000)
        # Tag genuinely binds the new version: renumbering breaks load.
        document = self._document()
        for item in document["keys"][KEY]["versions"]:
            if item["version"] == new:
                item["version"] = 9
        document["keys"][KEY]["active"] = 9
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load(KEY, version=9, password=PASSWORD)

    def test_explicit_version_other_versions_untouched(self) -> None:
        first = self.ring.seal(KEY, "one", "p1", iterations=1_000)
        second = self.ring.seal(KEY, "two", "p2", iterations=1_000)
        self.ring.set_active(KEY, first)
        new = self.ring.rotate_password(KEY, "p1b", password="p1", version=first)
        self.assertEqual(new, second + 1)
        self.assertEqual(self.ring.active(KEY), new)
        self.assertEqual(self.ring.load(KEY, version=first, password="p1"), b"one")
        self.assertEqual(self.ring.load(KEY, version=second, password="p2"), b"two")
        self.assertEqual(self.ring.load(KEY, version=new, password="p1b"), b"one")

    def test_revoke_source_flags_only_the_source(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=1_000)
        new = self.ring.rotate_password(KEY, "three", password=PASSWORD,
                                        version=first, revoke_source=True)
        self.assertTrue(self.ring.is_revoked(KEY, first))
        self.assertFalse(self.ring.is_revoked(KEY, second))
        self.assertFalse(self.ring.is_revoked(KEY, new))
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.load(KEY, version=first, password=PASSWORD)
        self.assertEqual(self.ring.load(KEY, version=new, password="three"), b"one")

    def test_empty_material_empty_password_and_same_password(self) -> None:
        source = self.ring.seal(KEY, "", PASSWORD, iterations=1_000)
        new = self.ring.rotate_password(KEY, "", password=PASSWORD, iterations=1_000)
        self.assertEqual(self.ring.load(KEY, password=""), b"")
        again = self.ring.rotate_password(KEY, "", password="", iterations=1_000)
        self.assertEqual((source, new, again), (1, 2, 3))
        self.assertEqual(self.ring.versions(KEY), [1, 2, 3])


class RotateAuthenticationTests(RotateTestBase):
    def _replace_with_v1_record(self, plaintext: bytes) -> int:
        version = self.ring.seal(KEY, plaintext.decode(), PASSWORD, iterations=1_000)
        document = self._document()
        record = document["keys"][KEY]["versions"][0]
        salt = base64.b64decode(record["salt"])
        iterations = record["iterations"]
        derived = core._derive(PASSWORD, salt, iterations, 3 * core._KEY_BYTES)
        enc_key, mac_key, check_key = (derived[:core._KEY_BYTES],
                                       derived[core._KEY_BYTES:2 * core._KEY_BYTES],
                                       derived[2 * core._KEY_BYTES:])
        ciphertext = core._xor(plaintext, core._keystream(enc_key, len(plaintext)))
        check = hmac.new(check_key, core._CHECK_LABEL, hashlib.sha256).digest()
        tag = hmac.new(mac_key,
                       core._aad(version, salt, iterations, check) + ciphertext,
                       hashlib.sha256).digest()
        record.update(scheme=core.SEALED_SCHEME,
                      material=base64.b64encode(ciphertext).decode("ascii"),
                      check=base64.b64encode(check).decode("ascii"),
                      tag=base64.b64encode(tag).decode("ascii"))
        self.ring.path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        return version

    def test_v1_source_authenticates_and_reseals_as_v2(self) -> None:
        version = self._replace_with_v1_record(b"legacy-secret")
        new = self.ring.rotate_password(KEY, "fresh", password=PASSWORD)
        self.assertEqual(self.ring.load(KEY, password="fresh"), b"legacy-secret")
        self.assertEqual(self._record(new)["scheme"], core.SEALED_V2_SCHEME)
        # The v1 source is neither rewritten nor revoked.
        self.assertEqual(self._record(version)["scheme"], core.SEALED_SCHEME)
        self.assertEqual(self.ring.load(KEY, version=version, password=PASSWORD),
                         b"legacy-secret")

    def test_unknown_key_and_version(self) -> None:
        self.ring.seal(KEY, "secret")
        with self.assertRaises(KeyError):
            self.ring.rotate_password("ghost", "x")
        with self.assertRaises(KeyError):
            self.ring.rotate_password(KEY, "x", version=99)

    def test_revoked_source(self) -> None:
        version = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.ring.revoke(KEY, version)
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.rotate_password(KEY, "x", password=PASSWORD)

    def test_legacy_derived_only_source_unrecoverable(self) -> None:
        version = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        document = self._document()
        document["keys"][KEY]["versions"][0] = {
            "version": version, "scheme": core.LEGACY_DERIVE_SCHEME, "revoked": False}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.rotate_password(KEY, "x", password=PASSWORD)

    def test_missing_and_bad_old_password(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.rotate_password(KEY, "x")
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.rotate_password(KEY, "x", password="wrong")

    def test_correct_password_against_tampered_record_is_corruption(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        document = self._document()
        raw = bytearray(base64.b64decode(document["keys"][KEY]["versions"][0]["material"]))
        raw[0] ^= 0x01
        document["keys"][KEY]["versions"][0]["material"] = base64.b64encode(bytes(raw)).decode()
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.rotate_password(KEY, "x", password=PASSWORD)

    def test_failures_never_modify_keyring(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        snapshot = self.ring.path.read_bytes()
        for call in (
            lambda: self.ring.rotate_password("ghost", "x"),
            lambda: self.ring.rotate_password(KEY, "x"),
            lambda: self.ring.rotate_password(KEY, "x", password="wrong"),
            lambda: self.ring.rotate_password(KEY, "x", password=5),  # type: ignore[arg-type]
        ):
            with self.assertRaises((KeyError, ValueError)):
                call()
            self.assertEqual(self.ring.path.read_bytes(), snapshot)


class RotateValidationTests(RotateTestBase):
    def test_input_is_validated_before_storage(self) -> None:
        # A ring that does not exist still reports the bad argument, not a
        # missing-file error.
        missing = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            missing.rotate_password(KEY, 1)  # type: ignore[arg-type]

    def test_bad_arguments(self) -> None:
        self.ring.seal(KEY, "secret")
        for kwargs in (
            dict(new_password=1),                    # type: ignore[dict-item]
            dict(new_password=None),                 # type: ignore[dict-item]
            dict(new_password="p", password=5),      # type: ignore[dict-item]
            dict(new_password="p", iterations=0),
            dict(new_password="p", iterations=-3),
            dict(new_password="p", iterations=True),
            dict(new_password="p", iterations=1.5),  # type: ignore[dict-item]
            dict(new_password="p", revoke_source=1), # type: ignore[dict-item]
            dict(new_password="p", revoke_source="yes"),  # type: ignore[dict-item]
            dict(new_password="p", version=0),
            dict(new_password="p", version=True),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(KEY, **kwargs)

    def test_bad_key_id_keeps_value_error_rule(self) -> None:
        with self.assertRaises(ValueError):
            self.ring.rotate_password("", "p")


class RotateConcurrencyTests(RotateTestBase):
    def test_threads_serialise_with_gapless_unique_versions(self) -> None:
        self.ring.seal(KEY, "m", "same", iterations=500)
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                for _ in range(10):
                    self.ring.rotate_password(KEY, "same", password="same", iterations=500)
            except BaseException as error:  # noqa: BLE001 - surfaced below
                errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        # 1 seal + 60 rotations, numbers gapless and unique, active on the last.
        self.assertEqual(self.ring.versions(KEY), list(range(1, 62)))
        self.assertEqual(self.ring.active(KEY), 61)
        self.assertEqual(self.ring.load(KEY, password="same"), b"m")

    def test_write_lock_timeout_leaves_file_untouched(self) -> None:
        self.ring.seal(KEY, "m", PASSWORD, iterations=1_000)
        snapshot = self.ring.path.read_bytes()
        ready = self.root / "holder.ready"
        env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
        holder = subprocess.Popen(
            [sys.executable, str(LOCK_HOLDER), str(self.root), "2", str(ready)],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        original_timeout = core.LOCK_TIMEOUT_SECONDS
        core.LOCK_TIMEOUT_SECONDS = 0.3
        try:
            deadline = time.monotonic() + 5
            while not ready.is_file() and time.monotonic() < deadline:
                time.sleep(0.02)
            with self.assertRaisesRegex(TimeoutError, "获取密钥环写锁超时"):
                self.ring.rotate_password(KEY, "x", password=PASSWORD)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)
        self.assertEqual(self.ring.path.read_bytes(), snapshot)


class RotateCliTests(RotateTestBase):
    def test_success_prints_only_version(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        result = self._run_cli("rotate-password", KEY, "--new-password", "next",
                               "--password", PASSWORD)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, f"{source + 1}\n")

    def test_default_iterations_and_revoke_source_flag(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        result = self._run_cli("rotate-password", KEY, "--new-password", "next",
                               "--password", PASSWORD, "--revoke-source")
        self.assertEqual(result.returncode, 0, result.stderr)
        new = int(result.stdout.strip())
        self.assertEqual(new, 2)
        document = self._document()
        fresh = next(item for item in document["keys"][KEY]["versions"]
                     if item["version"] == new)
        self.assertEqual(fresh["iterations"], 200_000)
        self.assertTrue(document["keys"][KEY]["versions"][0]["revoked"])
        self.assertFalse(fresh["revoked"])

    def test_plain_source_without_old_password_option(self) -> None:
        self.ring.seal(KEY, "secret")
        result = self._run_cli("rotate-password", KEY, "--new-password", "next")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2\n")

    def test_exit_codes(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        # Missing required option -> argparse usage error.
        self.assertEqual(self._run_cli("rotate-password", KEY).returncode, 2)
        # Bad input types (--iterations 0) and unknown key/version and a
        # revoked source are usage errors.
        self.assertEqual(self._run_cli(
            "rotate-password", KEY, "--new-password", "x", "--iterations", "0").returncode, 2)
        self.assertEqual(self._run_cli(
            "rotate-password", "ghost", "--new-password", "x").returncode, 2)
        self.assertEqual(self._run_cli(
            "rotate-password", KEY, "--new-password", "x", "--version", "99").returncode, 2)
        self.ring.revoke(KEY, 1)
        revoked = self._run_cli("rotate-password", KEY, "--new-password", "x",
                                "--password", PASSWORD)
        self.assertEqual(revoked.returncode, 2)
        self.assertIn("已吊销", revoked.stderr)

    def test_verification_errors_exit_one_with_empty_stdout(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        missing = self._run_cli("rotate-password", KEY, "--new-password", "x")
        self.assertEqual((missing.returncode, missing.stdout), (1, ""))
        wrong = self._run_cli("rotate-password", KEY, "--new-password", "x",
                              "--password", "bad")
        self.assertEqual((wrong.returncode, wrong.stdout), (1, ""))
        self.assertTrue(wrong.stderr)

    def test_missing_ring_exits_one(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "seal_derive",
             "--root", str(self.root / "never-initialised"),
             "rotate-password", KEY, "--new-password", "x"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertNotEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
