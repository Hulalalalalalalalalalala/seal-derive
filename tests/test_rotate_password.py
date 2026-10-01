"""Tests for ``KeyRing.rotate_password`` and the ``rotate-password`` CLI.

Acceptance surface:
* plain sources ignore the old password; v1/v2 sources authenticate exactly
  like ``load``; the recovered material bytes are re-sealed unchanged as a
  fresh ``pbkdf2-sha256-sealed-v2`` record with a new salt, the requested
  iteration count, and the key name/version bound into the tag;
* the new version is max+1, unrevoked and active; ``revoke_source`` revokes
  only the source; everything else is left untouched;
* concurrent rotations serialise: returned numbers are unique and gapless;
* input validation mirrors the documented rules (``ValueError``) and the
  load-ordered error chain (KeyError/Revoked/Unrecoverable/Missing/Bad/Corrupt)
  leaves keyring.json untouched;
* the CLI prints only ``<version>\\n`` on success and maps failures to exit
  codes 2 (usage/unknown/revoked) and 1 (everything else).

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
NEW_PASSWORD = "battery staple"


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
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30)

    def _replace_with_v1(self, version: int, plaintext: bytes, password: str = PASSWORD) -> None:
        document = self._document()
        record = next(item for item in document["keys"][KEY]["versions"]
                      if item["version"] == version)
        salt = base64.b64decode(record["salt"])
        iterations = record["iterations"]
        derived = core._derive(password, salt, iterations, 3 * core._KEY_BYTES)
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


class HappyPathTests(RotateTestBase):
    def test_plain_source_ignores_old_password_and_writes_v2(self) -> None:
        source = self.ring.seal(KEY, "材料-α")
        new_version = self.ring.rotate_password(KEY, NEW_PASSWORD)
        self.assertEqual(new_version, source + 1)
        record = self._record(new_version)
        self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
        self.assertFalse(record["revoked"])
        self.assertEqual(record["iterations"], 200_000)
        # Material bytes survive unchanged; only the new password opens it.
        self.assertEqual(self.ring.load(KEY, password=NEW_PASSWORD), "材料-α".encode("utf-8"))
        with self.assertRaises(core.BadPasswordError):
            self.ring.load(KEY, version=new_version, password=PASSWORD)
        with self.assertRaises(core.MissingPasswordError):
            self.ring.load(KEY, version=new_version)
        # The new version is active; the plain source is kept and readable.
        self.assertEqual(self.ring.active(KEY), new_version)
        self.assertEqual(self.ring.versions(KEY), [source, new_version])
        self.assertEqual(self.ring.load(KEY, version=source), "材料-α".encode("utf-8"))
        self.assertFalse(self.ring.is_revoked(KEY, source))

    def test_plain_source_with_explicit_password_argument(self) -> None:
        # The old password is simply irrelevant for plain, even when supplied.
        source = self.ring.seal(KEY, "secret")
        new_version = self.ring.rotate_password(KEY, NEW_PASSWORD, password=PASSWORD)
        self.assertEqual(self.ring.load(KEY, version=new_version, password=NEW_PASSWORD), b"secret")
        self.assertFalse(self.ring.is_revoked(KEY, source))

    def test_v2_source_round_trips_and_uses_fresh_salt(self) -> None:
        source = self.ring.seal(KEY, "材料-β", PASSWORD, iterations=2_000)
        before = self._record(source)
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, iterations=4_000)
        after = self._record(new_version)
        self.assertEqual(after["iterations"], 4_000)
        self.assertNotEqual(after["salt"], before["salt"])
        self.assertNotEqual(after["material"], before["material"])
        self.assertEqual(
            self.ring.load(KEY, version=source, password=PASSWORD), "材料-β".encode("utf-8"))
        self.assertEqual(
            self.ring.load(KEY, version=new_version, password=NEW_PASSWORD), "材料-β".encode("utf-8"))

    def test_v1_source_authenticates_then_becomes_v2(self) -> None:
        source = self.ring.seal(KEY, "legacy-secret", PASSWORD, iterations=1_000)
        self._replace_with_v1(source, b"legacy-secret")
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000)
        self.assertEqual(self._record(new_version)["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(
            self.ring.load(KEY, version=new_version, password=NEW_PASSWORD), b"legacy-secret")
        # The v1 source is neither upgraded nor rewritten.
        self.assertEqual(self._record(source)["scheme"], core.SEALED_SCHEME)
        self.assertEqual(
            self.ring.load(KEY, version=source, password=PASSWORD), b"legacy-secret")

    def test_explicit_non_active_version_is_the_source(self) -> None:
        first = self.ring.seal(KEY, "一", PASSWORD, iterations=1_000)
        second = self.ring.seal(KEY, "二", PASSWORD, iterations=1_000)
        self.assertEqual(self.ring.active(KEY), second)
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=first, iterations=1_000)
        self.assertEqual(new_version, 3)
        # The new copy carries the *first* version's material, not active's.
        self.assertEqual(self.ring.load(KEY, version=new_version, password=NEW_PASSWORD),
                         "一".encode("utf-8"))
        self.assertEqual(self.ring.active(KEY), new_version)
        self.assertEqual(self.ring.versions(KEY), [first, second, new_version])

    def test_new_version_is_max_plus_one_even_with_gaps_in_active(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=1_000)
        third = self.ring.seal(KEY, "three", PASSWORD, iterations=1_000)
        self.ring.set_active(KEY, first)
        rotated = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=second, iterations=1_000)
        self.assertEqual(rotated, third + 1)
        self.assertEqual(self.ring.active(KEY), rotated)

    def test_revoke_source_flag(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000, revoke_source=True)
        self.assertTrue(self.ring.is_revoked(KEY, source))
        self.assertFalse(self.ring.is_revoked(KEY, new_version))
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY, version=source, password=PASSWORD)
        self.assertEqual(self.ring.load(KEY, password=NEW_PASSWORD), b"secret")
        # Explicitly loading the fresh version works even though it is active.
        self.assertEqual(
            self.ring.load(KEY, version=new_version, password=NEW_PASSWORD), b"secret")

    def test_revoke_source_default_is_false(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000)
        self.assertFalse(self.ring.is_revoked(KEY, source))

    def test_sibling_versions_and_keys_are_untouched(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=1_000)
        other = self.ring.seal("other", "别的", PASSWORD, iterations=1_000)
        self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=first, iterations=1_000)
        self.assertEqual(self.ring.load(KEY, version=second, password=PASSWORD), b"two")
        self.assertEqual(self.ring.load("other", version=other, password=PASSWORD), "别的".encode("utf-8"))

    def test_edge_materials_and_passwords(self) -> None:
        for material in ("", "é" * 100, "😀‍‍"):
            with self.subTest(material=material):
                source = self.ring.seal(KEY + "-u", material, PASSWORD, iterations=1_000)
                rotated = self.ring.rotate_password(
                    KEY + "-u", "", password=PASSWORD, iterations=1_000)
                self.assertEqual(
                    self.ring.load(KEY + "-u", version=rotated, password=""),
                    material.encode("utf-8"))
                self.assertEqual(
                    self.ring.load(KEY + "-u", version=source, password=PASSWORD),
                    material.encode("utf-8"))

    def test_same_old_and_new_password(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        new_version = self.ring.rotate_password(
            KEY, PASSWORD, password=PASSWORD, iterations=1_000)
        self.assertEqual(
            self.ring.load(KEY, version=new_version, password=PASSWORD), b"secret")
        self.assertEqual(
            self.ring.load(KEY, version=source, password=PASSWORD), b"secret")
        self.assertNotEqual(self._record(new_version)["salt"], self._record(source)["salt"])

    def test_empty_material_plain_source(self) -> None:
        source = self.ring.seal(KEY, "")
        rotated = self.ring.rotate_password(KEY, NEW_PASSWORD)
        self.assertEqual(self.ring.load(KEY, version=rotated, password=NEW_PASSWORD), b"")
        self.assertEqual(self.ring.load(KEY, version=source), b"")

    def test_new_record_binds_key_name(self) -> None:
        import copy
        source = self.ring.seal(KEY, "secret", iterations=1_000)
        rotated = self.ring.rotate_password(KEY, NEW_PASSWORD)
        document = self._document()
        record = copy.deepcopy(self._record(rotated))
        document["keys"]["impostor"] = {"versions": [record], "active": rotated}
        self.ring.path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load("impostor", password=NEW_PASSWORD)


class InputValidationTests(RotateTestBase):
    def _assert_value_error(self, **kwargs) -> None:
        with self.assertRaises(ValueError):
            self.ring.rotate_password(KEY, NEW_PASSWORD, **kwargs)

    def test_bad_key_id(self) -> None:
        for bad in ("", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(bad, NEW_PASSWORD)  # type: ignore[arg-type]

    def test_new_password_must_be_string(self) -> None:
        for bad in (None, 1, b"x", True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(KEY, bad)  # type: ignore[arg-type]

    def test_old_password_must_be_string_or_none(self) -> None:
        for bad in (1, True, b"x"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(KEY, NEW_PASSWORD, password=bad)  # type: ignore[arg-type]

    def test_version_rules(self) -> None:
        self._assert_value_error(version=0)
        self._assert_value_error(version=-2)
        self._assert_value_error(version=True)
        self._assert_value_error(version="1")  # type: ignore[arg-type]

    def test_iterations_must_be_non_bool_positive_int(self) -> None:
        for bad in (0, -1, 1.5, True, "2000", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(KEY, NEW_PASSWORD, iterations=bad)  # type: ignore[arg-type]

    def test_revoke_source_must_be_bool(self) -> None:
        for bad in (0, 1, "true", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(KEY, NEW_PASSWORD, revoke_source=bad)  # type: ignore[arg-type]

    def test_validation_happens_before_touching_storage(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        for call in (
            lambda: self.ring.rotate_password(KEY, NEW_PASSWORD, iterations=0),
            lambda: self.ring.rotate_password(KEY, NEW_PASSWORD, revoke_source=1),
            lambda: self.ring.rotate_password(KEY, NEW_PASSWORD, version=True),
            lambda: self.ring.rotate_password(KEY, None),
            lambda: self.ring.rotate_password("", NEW_PASSWORD),
        ):
            with self.assertRaises(ValueError):
                call()
        self.assertEqual(self.ring.path.read_bytes(), before)


class ErrorOrderTests(RotateTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.sealed = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)

    def _assert_unchanged(self, before: bytes, call) -> None:
        with self.assertRaises(call[0]):
            call[1]()
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_key_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rotate_password("missing", NEW_PASSWORD)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_version_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, version=99, iterations=1_000)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_revoked_source(self) -> None:
        self.ring.revoke(KEY, self.sealed)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000)
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.rotate_password(KEY, NEW_PASSWORD, password=PASSWORD,
                                      version=self.sealed, iterations=1_000)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_legacy_derived_source_is_unrecoverable(self) -> None:
        document = self._document()
        document["keys"][KEY]["versions"][0] = {
            "version": self.sealed, "scheme": core.LEGACY_DERIVE_SCHEME, "revoked": False}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_old_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.rotate_password(KEY, NEW_PASSWORD, iterations=1_000)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_wrong_old_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password="wrong", iterations=1_000)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_correct_password_against_tampered_record_is_corrupt(self) -> None:
        document = self._document()
        material = bytearray(base64.b64decode(document["keys"][KEY]["versions"][0]["material"]))
        material[0] ^= 0x01
        document["keys"][KEY]["versions"][0]["material"] = \
            base64.b64encode(bytes(material)).decode("ascii")
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_keyring_is_corrupt_and_unchanged(self) -> None:
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.rotate_password(KEY, NEW_PASSWORD)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_revoked_check_precedes_password_check(self) -> None:
        self.ring.revoke(KEY, self.sealed)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.rotate_password(KEY, NEW_PASSWORD, iterations=1_000)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password="wrong", iterations=1_000)


class ConcurrencyTests(RotateTestBase):
    def test_parallel_rotations_serialise_to_gapless_unique_versions(self) -> None:
        # A plain, non-active source stays openable throughout: each rotation
        # copies version 1 (plain ignores the old password) and the source is
        # never revoked, so every worker can authenticate despite earlier
        # rotations repointing active.
        self.ring.seal(KEY, "secret")
        count = 8
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        results: dict[int, int] = {}
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                number = self.ring.rotate_password(
                    KEY, f"pw-{i}", password=PASSWORD, version=1, iterations=200)
                with lock:
                    results[number] = i
            except BaseException as error:  # noqa: BLE001 - surfaced to assertions
                with lock:
                    errors.append(error)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), list(range(2, 2 + count)))
        self.assertEqual(set(results.values()), set(range(count)))
        # Every rotated version opens under its own password; active is the
        # winner and is unrevoked, as are all produced versions.
        document = self._document()
        active = document["keys"][KEY]["active"]
        self.assertIn(active, results)
        for number, winner in results.items():
            self.assertFalse(self.ring.is_revoked(KEY, number))
            self.assertEqual(
                self.ring.load(KEY, version=number, password=f"pw-{winner}"),
                b"secret")

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
            deadline = time.monotonic() + 5
            while not ready.is_file() and time.monotonic() < deadline:
                time.sleep(0.02)
            before = self.ring.path.read_bytes()
            with self.assertRaisesRegex(TimeoutError, "获取密钥环写锁超时"):
                self.ring.rotate_password(KEY, NEW_PASSWORD)
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)


class CliTests(RotateTestBase):
    def test_success_prints_only_version(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        result = self._run_cli("rotate-password", KEY, "--new-password", NEW_PASSWORD,
                               "--password", PASSWORD, "--iterations", "1000")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2\n")
        self.assertEqual(result.stderr, "")

    def test_plain_source_cli(self) -> None:
        self.ring.seal(KEY, "secret")
        result = self._run_cli("rotate-password", KEY, "--new-password", NEW_PASSWORD)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2\n")
        loaded = self._run_cli("load", KEY, "--password", NEW_PASSWORD)
        self.assertEqual(loaded.stdout, "secret\n")

    def test_revoke_source_switch(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        result = self._run_cli("rotate-password", KEY, "--new-password", NEW_PASSWORD,
                               "--password", PASSWORD, "--iterations", "1000",
                               "--revoke-source")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2\n")
        self.assertEqual(self._run_cli("load", KEY, "--version", "1",
                                       "--password", PASSWORD).returncode, 2)

    def test_new_password_is_required(self) -> None:
        self.ring.seal(KEY, "secret")
        result = self._run_cli("rotate-password", KEY)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--new-password", result.stderr)

    def test_exit_codes(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        # Usage/identity/revocation -> 2.
        self.assertEqual(self._run_cli(
            "rotate-password", "missing", "--new-password", "x").returncode, 2)
        revoked = self._run_cli("rotate-password", KEY, "--new-password", "x",
                                "--password", PASSWORD, "--iterations", "1000",
                                "--revoke-source")
        self.assertEqual(revoked.returncode, 0)
        # The source version is now revoked; naming it explicitly is exit 2.
        self.assertEqual(self._run_cli("rotate-password", KEY, "--new-password", "y",
                                       "--password", PASSWORD, "--iterations", "1000",
                                       "--version", "1").returncode, 2)
        # Unknown version -> 2 as well.
        self.assertEqual(self._run_cli("rotate-password", KEY, "--new-password", "y",
                                       "--version", "99").returncode, 2)
        # Verification failures -> 1.
        self.assertEqual(self._run_cli("rotate-password", KEY, "--new-password", "x",
                                       "--iterations", "1000").returncode, 1)
        self.assertEqual(self._run_cli("rotate-password", KEY, "--new-password", "x",
                                       "--password", "wrong",
                                       "--iterations", "1000").returncode, 1)
        # Bad input types via argparse -> 2.
        self.assertEqual(self._run_cli("rotate-password", KEY, "--new-password", "x",
                                       "--version", "0").returncode, 2)

    def test_missing_ring_is_exit_one_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        result = subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(ring.directory),
             "rotate-password", KEY, "--new-password", "x"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no key ring", result.stderr)

    def test_failures_print_nothing_to_stdout(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        for invocation in (
            ["rotate-password", "missing", "--new-password", "x"],
            ["rotate-password", KEY, "--new-password", "x", "--iterations", "1000"],
            ["rotate-password", KEY, "--new-password", "x", "--password", "wrong",
             "--iterations", "1000"],
        ):
            with self.subTest(invocation=invocation):
                result = self._run_cli(*invocation)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertNotEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
