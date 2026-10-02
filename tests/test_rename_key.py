"""Tests for ``KeyRing.rename_key``.

Acceptance surface:
* the source key's whole history moves to a not-yet-existing target
  atomically: version numbers, list order, active pointer, revocation marks
  and material bytes are preserved; sealed records are re-sealed as
  ``pbkdf2-sha256-sealed-v2`` bound to the target name with the original
  passphrase, original iteration count and a fresh salt per version; plain
  records, other keys and extension fields are untouched;
* check order: whole-store validation, source existence (KeyError), the
  ``expected_active`` precondition (ActiveVersionConflictError), target
  absence (ValueError naming "目标键已存在"), password-map versions
  (KeyError), then per-record processing in ascending order -- plain
  ignores passphrases, legacy derived records are unrecoverable, v1/v2
  authenticate exactly like ``load`` (Missing/Bad/Corrupt), revoked records
  participate; the first failure aborts and leaves keyring.json untouched;
* input validation (ValueError) happens before any storage access and never
  mutates the caller's mapping;
* concurrent renames serialise: callers observe only the state before or
  after the rename; a missing store raises FileNotFoundError and waiting
  over five seconds for the write lock raises TimeoutError.

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
SOURCE = "old-key"
TARGET = "new-key"
PASSWORD = "correct horse"
OTHER_PASSWORD = "battery staple"


class RenameTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _put_document(self, document: dict) -> None:
        self.ring.path.write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8")

    def _record(self, version: int, key: str = TARGET) -> dict:
        for item in self._document()["keys"][key]["versions"]:
            if item["version"] == version:
                return item
        raise KeyError(version)

    def _replace_with_v1(self, version: int, plaintext: bytes,
                         password: str = PASSWORD, key: str = SOURCE) -> None:
        document = self._document()
        record = next(item for item in document["keys"][key]["versions"]
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
        self._put_document(document)


class HappyPathTests(RenameTestBase):
    def test_mixed_history_moves_wholesale(self) -> None:
        plain = self.ring.seal(SOURCE, "明文-α")
        sealed = self.ring.seal(SOURCE, "秘密-β", PASSWORD, iterations=2_000)
        before_plain = self._record(plain, key=SOURCE)
        before_sealed = self._record(sealed, key=SOURCE)
        result = self.ring.rename_key(
            SOURCE, TARGET, passwords={sealed: PASSWORD})
        self.assertIsNone(result)
        document = self._document()
        # The source key is gone; the target carries both versions in order.
        self.assertNotIn(SOURCE, document["keys"])
        self.assertEqual(self.ring.versions(TARGET), [plain, sealed])
        self.assertEqual(self.ring.active(TARGET), sealed)
        # The plain record is byte-identical and ignores the password map.
        self.assertEqual(self._record(plain), before_plain)
        self.assertEqual(self.ring.load(TARGET, version=plain), "明文-α".encode("utf-8"))
        # The sealed record is v2 bound to the target: fresh salt, same
        # iteration count, same material bytes under the original password.
        after_sealed = self._record(sealed)
        self.assertEqual(after_sealed["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(after_sealed["iterations"], 2_000)
        self.assertNotEqual(after_sealed["salt"], before_sealed["salt"])
        self.assertNotEqual(after_sealed["material"], before_sealed["material"])
        self.assertEqual(
            self.ring.load(TARGET, version=sealed, password=PASSWORD),
            "秘密-β".encode("utf-8"))

    def test_v1_record_is_resealed_as_v2_bound_to_target(self) -> None:
        sealed = self.ring.seal(SOURCE, "legacy-secret", PASSWORD, iterations=1_000)
        self._replace_with_v1(sealed, b"legacy-secret")
        self.ring.rename_key(SOURCE, TARGET, passwords={sealed: PASSWORD})
        record = self._record(sealed)
        self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(record["iterations"], 1_000)
        self.assertEqual(
            self.ring.load(TARGET, version=sealed, password=PASSWORD),
            b"legacy-secret")

    def test_renamed_record_is_bound_to_the_target_name(self) -> None:
        import copy
        sealed = self.ring.seal(SOURCE, "secret", PASSWORD, iterations=1_000)
        self.ring.rename_key(SOURCE, TARGET, passwords={sealed: PASSWORD})
        document = self._document()
        impostor = copy.deepcopy(self._record(sealed))
        document["keys"]["impostor"] = {"versions": [impostor], "active": sealed}
        self._put_document(document)
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load("impostor", password=PASSWORD)
        # ... while the real target still opens.
        self.assertEqual(
            self.ring.load(TARGET, version=sealed, password=PASSWORD), b"secret")

    def test_revoked_versions_rename_and_stay_revoked(self) -> None:
        first = self.ring.seal(SOURCE, "一", PASSWORD, iterations=1_000)
        second = self.ring.seal(SOURCE, "二", OTHER_PASSWORD, iterations=1_000)
        self.ring.revoke(SOURCE, first)
        self.ring.rename_key(
            SOURCE, TARGET, passwords={first: PASSWORD, second: OTHER_PASSWORD})
        self.assertTrue(self.ring.is_revoked(TARGET, first))
        self.assertFalse(self.ring.is_revoked(TARGET, second))
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(TARGET, version=first, password=PASSWORD)
        self.assertEqual(
            self.ring.load(TARGET, version=second, password=OTHER_PASSWORD), "二".encode("utf-8"))

    def test_revoked_record_with_wrong_password_fails_the_rename(self) -> None:
        sealed = self.ring.seal(SOURCE, "secret", PASSWORD, iterations=1_000)
        self.ring.revoke(SOURCE, sealed)
        before = self.ring.path.read_bytes()
        # Revocation neither skips nor excuses authentication.
        with self.assertRaises(core.BadPasswordError):
            self.ring.rename_key(SOURCE, TARGET, passwords={sealed: "wrong"})
        with self.assertRaises(core.MissingPasswordError):
            self.ring.rename_key(SOURCE, TARGET)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_expected_active_match_and_mismatch(self) -> None:
        first = self.ring.seal(SOURCE, "one")
        second = self.ring.seal(SOURCE, "two")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rename_key(SOURCE, TARGET, expected_active=first)
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.ring.rename_key(SOURCE, TARGET, expected_active=second)
        self.assertEqual(self.ring.versions(TARGET), [first, second])

    def test_active_pointer_other_than_newest_is_preserved(self) -> None:
        first = self.ring.seal(SOURCE, "one", PASSWORD, iterations=1_000)
        second = self.ring.seal(SOURCE, "two", PASSWORD, iterations=1_000)
        self.ring.set_active(SOURCE, first)
        self.ring.rename_key(
            SOURCE, TARGET, passwords={first: PASSWORD, second: PASSWORD},
            expected_active=first)
        self.assertEqual(self.ring.active(TARGET), first)
        self.assertEqual(
            self.ring.load(TARGET, password=PASSWORD), b"one")

    def test_plain_record_ignores_mapped_password(self) -> None:
        plain = self.ring.seal(SOURCE, "plain-data")
        self.ring.rename_key(SOURCE, TARGET, passwords={plain: "ignored"})
        self.assertEqual(self.ring.load(TARGET), b"plain-data")
        self.assertEqual(self._record(plain)["scheme"], core.PLAIN_SCHEME)

    def test_seal_after_rename_continues_from_history_max(self) -> None:
        self.ring.seal(SOURCE, "one")
        self.ring.seal(SOURCE, "two")
        self.ring.rename_key(SOURCE, TARGET)
        self.assertEqual(self.ring.seal(TARGET, "three"), 3)
        self.assertEqual(self.ring.versions(TARGET), [1, 2, 3])

    def test_other_keys_and_extension_fields_untouched(self) -> None:
        sealed = self.ring.seal(SOURCE, "secret", PASSWORD, iterations=1_000)
        other = self.ring.seal("other", "别的", OTHER_PASSWORD, iterations=1_000)
        document = self._document()
        document["keys"][SOURCE]["label"] = "入口扩展"
        document["keys"][SOURCE]["versions"][0]["note"] = "记录扩展"
        self._put_document(document)
        before_other = json.dumps(
            self._document()["keys"]["other"], sort_keys=True, ensure_ascii=False)
        self.ring.rename_key(SOURCE, TARGET, passwords={sealed: PASSWORD})
        document = self._document()
        self.assertEqual(document["keys"][TARGET]["label"], "入口扩展")
        self.assertEqual(self._record(sealed)["note"], "记录扩展")
        self.assertEqual(
            json.dumps(document["keys"]["other"], sort_keys=True, ensure_ascii=False),
            before_other)
        self.assertEqual(
            self.ring.load("other", version=other, password=OTHER_PASSWORD),
            "别的".encode("utf-8"))

    def test_empty_password_empty_material_and_unicode_names(self) -> None:
        unicode_source = "旧键-😀"
        unicode_target = "新键-😀"
        sealed = self.ring.seal(unicode_source, "", "", iterations=1_000)
        self.ring.rename_key(unicode_source, unicode_target, passwords={sealed: ""})
        self.assertEqual(self.ring.load(unicode_target, password=""), b"")
        self.assertNotIn(unicode_source, self._document()["keys"])

    def test_empty_passwords_map_behaves_like_none(self) -> None:
        self.ring.seal(SOURCE, "plain")
        self.ring.rename_key(SOURCE, TARGET, passwords={})
        self.assertEqual(self.ring.load(TARGET), b"plain")


class InputValidationTests(RenameTestBase):
    def test_source_and_target_must_be_non_empty_strings(self) -> None:
        for bad in ("", None, 7, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rename_key(bad, TARGET)  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    self.ring.rename_key(SOURCE, bad)  # type: ignore[arg-type]

    def test_source_and_target_must_differ(self) -> None:
        with self.assertRaises(ValueError):
            self.ring.rename_key(SOURCE, SOURCE)

    def test_passwords_must_be_a_dict_or_none(self) -> None:
        for bad in ([], "pw", 1, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rename_key(SOURCE, TARGET, passwords=bad)  # type: ignore[arg-type]

    def test_passwords_keys_must_be_non_bool_positive_ints(self) -> None:
        for bad_key in (0, -1, True, "1", 1.5):
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(ValueError):
                    self.ring.rename_key(
                        SOURCE, TARGET, passwords={bad_key: "pw"})  # type: ignore[dict-item]

    def test_passwords_values_must_be_strings(self) -> None:
        for bad_value in (None, 1, b"pw", True):
            with self.subTest(bad_value=bad_value):
                with self.assertRaises(ValueError):
                    self.ring.rename_key(
                        SOURCE, TARGET, passwords={1: bad_value})  # type: ignore[dict-item]

    def test_expected_active_rules(self) -> None:
        for bad in (0, -2, True, "1", 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rename_key(
                        SOURCE, TARGET, expected_active=bad)  # type: ignore[arg-type]

    def test_validation_precedes_storage_access(self) -> None:
        # Even with no store on disk, bad input is a ValueError, never a
        # FileNotFoundError.
        ring = core.KeyRing(self.root / "never-initialised")
        for call in (
            lambda: ring.rename_key("", TARGET),
            lambda: ring.rename_key(SOURCE, ""),
            lambda: ring.rename_key(SOURCE, SOURCE),
            lambda: ring.rename_key(SOURCE, TARGET, passwords=[]),  # type: ignore[arg-type]
            lambda: ring.rename_key(SOURCE, TARGET, passwords={0: "pw"}),
            lambda: ring.rename_key(SOURCE, TARGET, passwords={1: None}),  # type: ignore[dict-item]
            lambda: ring.rename_key(SOURCE, TARGET, expected_active=True),
        ):
            with self.assertRaises(ValueError):
                call()

    def test_validation_leaves_store_untouched(self) -> None:
        self.ring.seal(SOURCE, "secret", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        for call in (
            lambda: self.ring.rename_key("", TARGET),
            lambda: self.ring.rename_key(SOURCE, SOURCE),
            lambda: self.ring.rename_key(SOURCE, TARGET, passwords={1: 2}),  # type: ignore[dict-item]
            lambda: self.ring.rename_key(SOURCE, TARGET, expected_active=0),
        ):
            with self.assertRaises(ValueError):
                call()
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_callers_mapping_is_never_mutated(self) -> None:
        sealed = self.ring.seal(SOURCE, "secret", PASSWORD, iterations=1_000)
        passwords = {sealed: PASSWORD}
        snapshot = dict(passwords)
        self.ring.rename_key(SOURCE, TARGET, passwords=passwords)
        self.assertEqual(passwords, snapshot)


class ErrorOrderTests(RenameTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.sealed = self.ring.seal(SOURCE, "secret", PASSWORD, iterations=1_000)

    def _assert_unchanged(self, before: bytes, call) -> None:
        with self.assertRaises(call[0]):
            call[1]()
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_source_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rename_key("missing", TARGET)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_source_check_precedes_target_check(self) -> None:
        # TARGET is created so both checks could fire; the missing source
        # wins.
        self.ring.seal(TARGET, "taken")
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rename_key("missing", TARGET)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_active_conflict_precedes_existing_target(self) -> None:
        self.ring.seal(TARGET, "taken")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rename_key(SOURCE, TARGET, expected_active=99)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_existing_target_is_value_error(self) -> None:
        self.ring.seal(TARGET, "taken")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "目标键已存在"):
            self.ring.rename_key(SOURCE, TARGET)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_target_check_precedes_password_map_check(self) -> None:
        self.ring.seal(TARGET, "taken")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "目标键已存在"):
            self.ring.rename_key(SOURCE, TARGET, passwords={99: "pw"})
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_password_map_versions_must_exist(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rename_key(SOURCE, TARGET, passwords={99: "pw"})
        with self.assertRaises(KeyError):
            self.ring.rename_key(
                SOURCE, TARGET, passwords={self.sealed: PASSWORD, 99: "pw"})
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_legacy_derived_record_is_unrecoverable(self) -> None:
        document = self._document()
        document["keys"][SOURCE]["versions"][0] = {
            "version": self.sealed, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": False}
        self._put_document(document)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.rename_key(SOURCE, TARGET, passwords={self.sealed: PASSWORD})
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.rename_key(SOURCE, TARGET)
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.rename_key(SOURCE, TARGET, passwords={})
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_wrong_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.rename_key(SOURCE, TARGET, passwords={self.sealed: "wrong"})
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_correct_password_against_tampered_record_is_corrupt(self) -> None:
        document = self._document()
        material = bytearray(base64.b64decode(
            document["keys"][SOURCE]["versions"][0]["material"]))
        material[0] ^= 0x01
        document["keys"][SOURCE]["versions"][0]["material"] = \
            base64.b64encode(bytes(material)).decode("ascii")
        self._put_document(document)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.rename_key(SOURCE, TARGET, passwords={self.sealed: PASSWORD})
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_first_failure_in_ascending_order_aborts(self) -> None:
        # Versions 1 and 2 would authenticate; version 3 has the wrong
        # password. The rename aborts at version 3 and nothing is committed.
        first = self.ring.seal(SOURCE, "one", PASSWORD, iterations=1_000)
        second = self.ring.seal(SOURCE, "two", OTHER_PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.BadPasswordError):
            self.ring.rename_key(
                SOURCE, TARGET,
                passwords={self.sealed: PASSWORD, first: PASSWORD, second: "wrong"})
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertNotIn(TARGET, self._document()["keys"])
        self.assertEqual(self.ring.versions(SOURCE), [self.sealed, first, second])
        # Ascending order: version 1's bad password outranks version 3's
        # missing one.
        with self.assertRaises(core.BadPasswordError):
            self.ring.rename_key(
                SOURCE, TARGET,
                passwords={self.sealed: "wrong", first: PASSWORD})
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_store_is_corrupt_and_unchanged(self) -> None:
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.rename_key(SOURCE, TARGET)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_store_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(FileNotFoundError):
            ring.rename_key(SOURCE, TARGET)


class ConcurrencyTests(RenameTestBase):
    def test_concurrent_renames_of_one_source_exactly_one_wins(self) -> None:
        self.ring.seal(SOURCE, "one")
        self.ring.seal(SOURCE, "two", PASSWORD, iterations=1_000)
        count = 6
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        winners: list[str] = []
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                self.ring.rename_key(
                    SOURCE, f"target-{i}", passwords={2: PASSWORD})
                with lock:
                    winners.append(f"target-{i}")
            except KeyError:
                pass  # the loser observes the source already gone
            except BaseException as error:  # noqa: BLE001 - surfaced to assertions
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(winners), 1)
        document = self._document()
        self.assertNotIn(SOURCE, document["keys"])
        self.assertEqual(
            self.ring.versions(winners[0]), [1, 2])
        self.assertEqual(
            self.ring.load(winners[0], version=2, password=PASSWORD), b"two")

    def test_write_lock_timeout(self) -> None:
        self.ring.seal(SOURCE, "secret")
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
                self.ring.rename_key(SOURCE, TARGET)
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
