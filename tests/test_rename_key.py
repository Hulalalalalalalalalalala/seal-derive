"""Tests for ``KeyRing.rename_key``: atomic whole-history key renaming.

Acceptance surface:

* ``rename_key(source, target, passwords=None, expected_active=None)`` moves
  the source key's complete history onto a not-yet-existing target and
  returns ``None``; the target keeps version numbers, order, active pointer,
  revocation marks and material bytes, sealed history is re-written as v2
  bound to the target name with the original passphrase/iteration count and a
  fresh salt per version, plain records move byte-for-byte, other keys and
  document/entry extension fields are untouched;
* bad arguments raise ``ValueError`` before any storage access and the
  caller's password map is never mutated;
* in one locked snapshot the whole store is validated first, then source
  existence (``KeyError``), the active precondition
  (``ActiveVersionConflictError``), target absence (``ValueError`` containing
  “目标键已存在”) and mapped-version existence (``KeyError``) are checked in
  that order, after which the ascending history authenticates: plain ignores
  passwords, legacy derived-only records raise ``UnrecoverableRecordError``,
  v1/v2 raise ``MissingPasswordError``/``BadPasswordError``/
  ``CorruptRecordError`` exactly like ``load``, revoked records participate
  and stay revoked, and the first failure aborts with keyring.json unchanged;
* a missing store raises ``FileNotFoundError``, a lock held over five seconds
  raises ``TimeoutError``, other storage errors are ``OSError`` with no
  partial rename, and concurrent callers see only the pre- or post-rename
  document.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCK_HOLDER = Path(__file__).resolve().parent / "_lock_holder.py"
KEY = "k"
TARGET = "renamed"
OTHER = "other"
PASSWORD = "correct horse"


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
        self.ring.path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")

    def _records(self, key: str = KEY) -> list[dict]:
        return self._document()["keys"][key]["versions"]

    @staticmethod
    def _wait_for(marker: Path, label: str) -> None:
        deadline = time.monotonic() + 5
        while not marker.is_file() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.is_file(), f"{label} never happened"

    def _replace_with_v1_record(self, key: str, version: int,
                                plaintext: bytes, password: str,
                                iterations: int = 1_000) -> None:
        """Rewrite one sealed-v2 record as a legacy v1 sealed record."""
        document = self._document()
        record = next(item for item in document["keys"][key]["versions"]
                      if item["version"] == version)
        salt = base64.b64decode(record["salt"])
        derived = core._derive(password, salt, iterations, 3 * core._KEY_BYTES)
        enc_key, mac_key, check_key = (
            derived[:core._KEY_BYTES],
            derived[core._KEY_BYTES:2 * core._KEY_BYTES],
            derived[2 * core._KEY_BYTES:])
        ciphertext = core._xor(plaintext, core._keystream(enc_key, len(plaintext)))
        check = hmac.new(check_key, core._CHECK_LABEL, hashlib.sha256).digest()
        tag = hmac.new(
            mac_key, core._aad(version, salt, iterations, check) + ciphertext,
            hashlib.sha256).digest()
        record.update(
            scheme=core.SEALED_SCHEME,
            material=base64.b64encode(ciphertext).decode("ascii"),
            check=base64.b64encode(check).decode("ascii"),
            tag=base64.b64encode(tag).decode("ascii"))
        self._put_document(document)


class RenameSuccessTests(RenameTestBase):
    def test_plain_only_history_moves_without_passwords(self) -> None:
        first = self.ring.seal(KEY, "一")
        second = self.ring.seal(KEY, "二")
        self.ring.set_active(KEY, first)
        self.assertIsNone(self.ring.rename_key(KEY, TARGET))
        document = self._document()
        self.assertNotIn(KEY, document["keys"])
        entry = document["keys"][TARGET]
        self.assertEqual([item["version"] for item in entry["versions"]], [first, second])
        self.assertEqual(entry["active"], first)
        self.assertEqual(self.ring.versions(TARGET), [1, 2])
        self.assertEqual(self.ring.active(TARGET), first)
        self.assertEqual(self.ring.load(TARGET, version=first), "一".encode("utf-8"))
        self.assertEqual(self.ring.load(TARGET, version=second), "二".encode("utf-8"))
        with self.assertRaises(KeyError):
            self.ring.versions(KEY)

    def test_plain_records_move_byte_for_byte(self) -> None:
        self.ring.seal(KEY, "材料")
        before = self._records()[0]
        self.ring.rename_key(KEY, TARGET)
        after = self._records(TARGET)[0]
        self.assertEqual(before, after)
        self.assertEqual(after["scheme"], core.PLAIN_SCHEME)

    def test_mixed_history_keeps_marks_iterations_and_material(self) -> None:
        v1 = self.ring.seal(KEY, "一", "pw-1", iterations=1_000)
        v2 = self.ring.seal(KEY, "二")  # plain
        v3 = self.ring.seal(KEY, "三", "pw-3", iterations=4_000)
        self.ring.revoke(KEY, v1)
        self.ring.rename_key(KEY, TARGET, {v1: "pw-1", v3: "pw-3"})
        entry = self._document()["keys"][TARGET]
        numbers = [item["version"] for item in entry["versions"]]
        self.assertEqual(numbers, [v1, v2, v3])
        self.assertEqual(entry["active"], v3)
        marks = [item["revoked"] for item in entry["versions"]]
        self.assertEqual(marks, [True, False, False])
        schemes = [item["scheme"] for item in entry["versions"]]
        self.assertEqual(schemes, [core.SEALED_V2_SCHEME, core.PLAIN_SCHEME,
                                   core.SEALED_V2_SCHEME])
        iterations = [item["iterations"] for item in entry["versions"][::2]]
        self.assertEqual(iterations, [1_000, 4_000])
        # Material bytes survive the rename.
        self.assertEqual(self.ring.load(TARGET, version=v2), "二".encode("utf-8"))
        self.assertEqual(
            self.ring.load(TARGET, version=v3, password="pw-3"), "三".encode("utf-8"))

    def test_revoked_version_stays_revoked_after_rename(self) -> None:
        v1 = self.ring.seal(KEY, "一", "pw", iterations=1_000)
        self.ring.revoke(KEY, v1)
        self.ring.rename_key(KEY, TARGET, {v1: "pw"})
        self.assertTrue(self.ring.is_revoked(TARGET, v1))
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.load(TARGET, version=v1, password="pw")

    def test_sealed_records_get_fresh_salts_bound_to_target(self) -> None:
        v1 = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        old_salt = self._records()[0]["salt"]
        self.ring.rename_key(KEY, TARGET, {v1: PASSWORD})
        record = self._records(TARGET)[0]
        self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
        self.assertNotEqual(record["salt"], old_salt)
        self.assertEqual(
            self.ring.load(TARGET, version=v1, password=PASSWORD), b"secret")
        # The renamed record now binds TARGET: copying it under another key
        # fails authentication, exactly like every other v2 record.
        import copy
        document = self._document()
        document["keys"][OTHER] = {
            "versions": [copy.deepcopy(record)], "active": v1}
        self._put_document(document)
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load(OTHER, password=PASSWORD)

    def test_v1_record_is_resealed_as_target_bound_v2(self) -> None:
        v1 = self.ring.seal(KEY, "legacy-secret", PASSWORD, iterations=1_000)
        self._replace_with_v1_record(KEY, v1, b"legacy-secret", PASSWORD)
        self.ring.rename_key(KEY, TARGET, {v1: PASSWORD})
        record = self._records(TARGET)[0]
        self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(
            self.ring.load(TARGET, version=v1, password=PASSWORD),
            b"legacy-secret")

    def test_seal_after_rename_numbers_from_history_max_plus_one(self) -> None:
        self.ring.seal(KEY, "一", "pw", iterations=1_000)
        self.ring.seal(KEY, "二", "pw", iterations=1_000)
        self.ring.rename_key(KEY, TARGET, {1: "pw", 2: "pw"})
        new_version = self.ring.seal(TARGET, "三", "pw", iterations=1_000)
        self.assertEqual(new_version, 3)
        self.assertEqual(self.ring.versions(TARGET), [1, 2, 3])
        self.assertEqual(self.ring.active(TARGET), 3)

    def test_other_keys_and_extension_fields_are_untouched(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        self.ring.seal(OTHER, "o")
        document = self._document()
        document["x-top"] = {"keep": [1, 2]}
        document["keys"][KEY]["x-entry"] = "note"
        document["keys"][OTHER]["x-other"] = 42
        self._put_document(document)
        self.ring.rename_key(KEY, TARGET, {1: "pw"})
        document = self._document()
        self.assertEqual(document["x-top"], {"keep": [1, 2]})
        self.assertEqual(document["keys"][TARGET]["x-entry"], "note")
        self.assertEqual(document["keys"][OTHER]["x-other"], 42)
        self.assertEqual(self.ring.load(OTHER), b"o")

    def test_plain_extra_fields_carry_over_verbatim(self) -> None:
        self.ring.seal(KEY, "s")
        document = self._document()
        document["keys"][KEY]["versions"][0]["x-record"] = {"a": 1}
        self._put_document(document)
        self.ring.rename_key(KEY, TARGET)
        self.assertEqual(
            self._records(TARGET)[0]["x-record"], {"a": 1})

    def test_sealed_extra_fields_carry_over(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        document = self._document()
        document["keys"][KEY]["versions"][0]["x-record"] = [1, {"b": 2}]
        self._put_document(document)
        self.ring.rename_key(KEY, TARGET, {1: "pw"})
        record = self._records(TARGET)[0]
        self.assertEqual(record["x-record"], [1, {"b": 2}])
        # The standard fields were still replaced by fresh v2 values.
        self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(
            self.ring.load(TARGET, password="pw"), b"s")

    def test_empty_password_and_empty_material_supported(self) -> None:
        v1 = self.ring.seal(KEY, "", "", iterations=1_000)
        self.assertIsNone(self.ring.rename_key(KEY, TARGET, {v1: ""}))
        self.assertEqual(self.ring.load(TARGET, password=""), b"")
        with self.assertRaises(core.MissingPasswordError):
            self.ring.load(TARGET)

    def test_unicode_names_and_material(self) -> None:
        source, target = "中文键", "目标 键 😀/a|b\\"
        v1 = self.ring.seal(source, "材料🔐", "口令", iterations=1_000)
        self.ring.rename_key(source, target, {v1: "口令"})
        self.assertEqual(
            self.ring.load(target, password="口令"), "材料🔐".encode("utf-8"))

    def test_expected_active_matches(self) -> None:
        self.ring.seal(KEY, "一", "pw", iterations=1_000)
        second = self.ring.seal(KEY, "二", "pw", iterations=1_000)
        self.assertIsNone(
            self.ring.rename_key(KEY, TARGET, {1: "pw", 2: "pw"},
                                 expected_active=second))


class RenameInputValidationTests(RenameTestBase):
    def test_bad_names_raise_before_storage(self) -> None:
        missing = core.KeyRing(self.root / "never-initialised")
        for source, target in (("", TARGET), (KEY, ""), (123, TARGET),
                               (KEY, 456), (None, TARGET), (KEY, None)):
            with self.subTest(source=source, target=target):
                with self.assertRaises(ValueError):
                    missing.rename_key(source, target)

    def test_equal_names_raise(self) -> None:
        with self.assertRaises(ValueError):
            self.ring.rename_key(KEY, KEY)
        with self.assertRaises(ValueError):
            self.ring.rename_key("", "")

    def test_bad_passwords_map_raises(self) -> None:
        for passwords in ([], "x", 1, {1: 2}, {1: None}, {True: "x"},
                          {0: "x"}, {-1: "x"}, {1.0: "x"}, {"1": "x"}):
            with self.subTest(passwords=passwords):
                with self.assertRaises(ValueError):
                    self.ring.rename_key(KEY, TARGET, passwords)

    def test_bad_expected_active_raises(self) -> None:
        for expected in (0, -1, True, 1.0, "1"):
            with self.subTest(expected=expected):
                with self.assertRaises(ValueError):
                    self.ring.rename_key(KEY, TARGET, expected_active=expected)

    def test_validation_happens_before_storage_access(self) -> None:
        missing = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            missing.rename_key(KEY, TARGET, {True: "pw"})
        with self.assertRaises(ValueError):
            missing.rename_key(KEY, KEY)

    def test_caller_mapping_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "一", "pw", iterations=1_000)
        self.ring.seal(KEY, "二")
        passwords = {1: "pw", 2: "ignored-on-plain"}
        self.ring.rename_key(KEY, TARGET, passwords)
        self.assertEqual(passwords, {1: "pw", 2: "ignored-on-plain"})

    def test_password_for_plain_version_is_ignored(self) -> None:
        self.ring.seal(KEY, "plain")
        # An arbitrary string for the plain version must not be required to
        # match anything; omitting the map must work just as well.
        self.assertIsNone(self.ring.rename_key(KEY, TARGET, {1: "anything"}))
        self.assertEqual(self.ring.load(TARGET), b"plain")


class RenameCheckOrderTests(RenameTestBase):
    def test_whole_store_is_validated_before_everything(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        document = self._document()
        # Damage an unrelated key so the snapshot itself is corrupt; this must
        # surface before source/target/mapping checks even run.
        document["keys"][OTHER] = {"versions": [], "active": 99}
        self._put_document(document)
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.rename_key(KEY, TARGET, {1: "pw"})

    def test_missing_source_is_key_error(self) -> None:
        with self.assertRaises(KeyError):
            self.ring.rename_key("missing", TARGET)
        # Source lookup even outranks an existing target.
        self.ring.seal(TARGET, "t")
        with self.assertRaises(KeyError):
            self.ring.rename_key("missing", TARGET)

    def test_active_conflict_outranks_existing_target(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        self.ring.seal(TARGET, "t")
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rename_key(KEY, TARGET, {1: "pw"}, expected_active=5)

    def test_existing_target_is_value_error(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        self.ring.seal(TARGET, "t")
        # Target existence outranks an unknown mapped version.
        with self.assertRaisesRegex(ValueError, "目标键已存在"):
            self.ring.rename_key(KEY, TARGET, {99: "pw"})

    def test_unknown_mapped_version_is_key_error(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        with self.assertRaises(KeyError):
            self.ring.rename_key(KEY, TARGET, {1: "pw", 2: "pw"})

    def test_failure_leaves_keyring_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "一", "pw", iterations=1_000)
        self.ring.seal(KEY, "二", "pw2", iterations=1_000)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.BadPasswordError):
            self.ring.rename_key(KEY, TARGET, {1: "wrong", 2: "pw2"})
        self.assertEqual(before, self.ring.path.read_bytes())
        with self.assertRaises(core.MissingPasswordError):
            self.ring.rename_key(KEY, TARGET, {1: "pw"})
        self.assertEqual(before, self.ring.path.read_bytes())


class RenameAuthenticationTests(RenameTestBase):
    def test_missing_password_on_sealed_history(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.rename_key(KEY, TARGET)

    def test_walk_is_ascending_first_failure_wins(self) -> None:
        self.ring.seal(KEY, "一", "pw-1", iterations=1_000)
        self.ring.seal(KEY, "二", "pw-2", iterations=1_000)
        # Version 1 is missing first, so version 2's wrong password never
        # decides the verdict.
        with self.assertRaises(core.MissingPasswordError):
            self.ring.rename_key(KEY, TARGET, {2: "wrong"})
        # Version 1 wrong outranks a correct version 2.
        with self.assertRaises(core.BadPasswordError):
            self.ring.rename_key(KEY, TARGET, {1: "wrong", 2: "pw-2"})

    def test_bad_password(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.rename_key(KEY, TARGET, {1: "nope"})

    def test_correct_password_but_tampered_tag_is_corrupt(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        document = self._document()
        record = document["keys"][KEY]["versions"][0]
        tag = bytearray(base64.b64decode(record["tag"]))
        tag[0] ^= 0x01
        record["tag"] = base64.b64encode(bytes(tag)).decode("ascii")
        self._put_document(document)
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.rename_key(KEY, TARGET, {1: "pw"})

    def test_legacy_derived_record_blocks_rename(self) -> None:
        version = self.ring.seal(KEY, "s", "pw", iterations=1_000)
        document = self._document()
        document["keys"][KEY]["versions"][0] = {
            "version": version, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": False}
        self._put_document(document)
        with self.assertRaisesRegex(
                core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.rename_key(KEY, TARGET, {version: "pw"})
        self.assertIn(KEY, self._document()["keys"])

    def test_legacy_position_respected_in_ascending_walk(self) -> None:
        # Version 1 is a sealed record missing its password; version 2 is the
        # unrecoverable legacy one. The ascending walk hits the missing
        # passphrase first.
        self.ring.seal(KEY, "一", "pw", iterations=1_000)
        document = self._document()
        document["keys"][KEY]["versions"].append(
            {"version": 2, "scheme": core.LEGACY_DERIVE_SCHEME,
             "revoked": False})
        document["keys"][KEY]["active"] = 2
        self._put_document(document)
        with self.assertRaises(core.MissingPasswordError):
            self.ring.rename_key(KEY, TARGET, {2: "pw"})

    def test_revoked_sealed_record_authenticates(self) -> None:
        version = self.ring.seal(KEY, "s", "pw", iterations=1_000)
        self.ring.revoke(KEY, version)
        # A missing or wrong passphrase on the revoked record still aborts.
        with self.assertRaises(core.MissingPasswordError):
            self.ring.rename_key(KEY, TARGET)
        with self.assertRaises(core.BadPasswordError):
            self.ring.rename_key(KEY, TARGET, {version: "wrong"})
        # The correct passphrase renames it; revocation is carried over.
        self.assertIsNone(self.ring.rename_key(KEY, TARGET, {version: "pw"}))
        self.assertTrue(self.ring.is_revoked(TARGET, version))


class RenameStorageAndConcurrencyTests(RenameTestBase):
    def test_missing_store_raises_filenotfound(self) -> None:
        missing = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(FileNotFoundError):
            missing.rename_key(KEY, TARGET, {})

    def test_write_lock_timeout(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        ready = self.root / "holder.ready"
        holder = subprocess.Popen(
            [sys.executable, str(LOCK_HOLDER), str(self.root), "2", str(ready)],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)})
        original_timeout = core.LOCK_TIMEOUT_SECONDS
        core.LOCK_TIMEOUT_SECONDS = 0.3
        try:
            self._wait_for(ready, "lock holder")
            with self.assertRaisesRegex(TimeoutError, "获取密钥环写锁超时"):
                self.ring.rename_key(KEY, TARGET, {1: "pw"})
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)
        # The timed-out rename changed nothing.
        self.assertIn(KEY, self._document()["keys"])
        self.assertNotIn(TARGET, self._document()["keys"])

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file permissions")
    def test_storage_error_leaves_no_partial_rename(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        os.chmod(self.ring.path, stat.S_IRUSR)
        try:
            with self.assertRaises(OSError):
                self.ring.rename_key(KEY, TARGET, {1: "pw"})
        finally:
            os.chmod(self.ring.path, stat.S_IRUSR | stat.S_IWUSR)
        document = self._document()
        self.assertIn(KEY, document["keys"])
        self.assertNotIn(TARGET, document["keys"])
        leftovers = list(self.root.glob(core._TMP_GLOB))
        self.assertEqual(leftovers, [])

    def test_thread_callers_serialise_and_see_pre_or_post_state(self) -> None:
        version = self.ring.seal(KEY, "secret", PASSWORD, iterations=100_000)
        entered, release = threading.Event(), threading.Event()
        real_derive = core._derive

        def slow_derive(password, salt, iterations, length=32):
            # Held while the rename owns the exclusive snapshot (the first
            # _derive runs during authentication).
            entered.set()
            release.wait(timeout=5)
            return real_derive(password, salt, iterations, length)

        core._derive = slow_derive
        result: dict[str, object] = {}
        try:
            def rename() -> None:
                try:
                    self.ring.rename_key(KEY, TARGET, {version: PASSWORD})
                except Exception as error:  # noqa: BLE001 - surfaced via result
                    result["error"] = error

            thread = threading.Thread(target=rename)
            thread.start()
            self.assertTrue(entered.wait(timeout=5), "rename never entered its snapshot")
            # Another writer cannot squeeze into the open snapshot.
            original_timeout = core.LOCK_TIMEOUT_SECONDS
            core.LOCK_TIMEOUT_SECONDS = 0.3
            try:
                with self.assertRaises(TimeoutError):
                    self.ring.rename_key(OTHER, "else")
            finally:
                core.LOCK_TIMEOUT_SECONDS = original_timeout
            release.set()
            thread.join(timeout=15)
        finally:
            core._derive = real_derive
        self.assertEqual(result, {})
        # Only the post-rename state is visible: source gone, target present.
        self.assertEqual(self.ring.versions(TARGET), [version])
        with self.assertRaises(KeyError):
            self.ring.versions(KEY)

    def test_concurrent_renames_of_one_key_leave_a_consistent_store(self) -> None:
        self.ring.seal(KEY, "s", "pw", iterations=1_000)
        outcomes: list[object] = []

        def rename(target: str) -> None:
            try:
                self.ring.rename_key(KEY, target, {1: "pw"})
                outcomes.append(("ok", target))
            except Exception as error:  # noqa: BLE001 - surfaced via outcomes
                outcomes.append(("error", type(error).__name__))

        threads = [threading.Thread(target=rename, args=(f"t{i}",))
                   for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        successes = [target for status, target in outcomes if status == "ok"]
        self.assertEqual(len(successes), 1, outcomes)
        document = self._document()
        # Exactly one destination exists and holds the whole history; the
        # source and the losing targets are all absent, never both states.
        self.assertEqual(sorted(document["keys"]), successes)
        self.assertNotIn(KEY, document["keys"])
        entry = document["keys"][successes[0]]
        self.assertEqual([item["version"] for item in entry["versions"]], [1])

    def test_cross_process_rename_is_atomic_around_the_lock(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        ready = self.root / "holder.ready"
        holder = subprocess.Popen(
            [sys.executable, str(LOCK_HOLDER), str(self.root), "2", str(ready)],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)})
        try:
            # Only launch the rename once the holder genuinely owns the
            # exclusive lock, otherwise process startup could let the worker
            # commit first and the in-flight assertion would be meaningless.
            self._wait_for(ready, "lock holder")
            worker = subprocess.Popen(
                [sys.executable, "-c",
                 "import sys; from seal_derive.core import KeyRing;"
                 "KeyRing(sys.argv[1]).rename_key(%r, %r, {1: %r})"
                 % (KEY, TARGET, PASSWORD),
                 str(self.root)],
                cwd=PROJECT_ROOT,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                # The worker is queued behind the holder and has committed
                # nothing: the file still shows only the pre-rename state.
                time.sleep(0.5)
                document = self._document()
                self.assertIn(KEY, document["keys"])
                self.assertNotIn(TARGET, document["keys"])
                _, stderr = worker.communicate(timeout=15)
                self.assertEqual(stderr, "", stderr)
            finally:
                worker.wait(timeout=10)
                if worker.stdout is not None:
                    worker.stdout.close()
                if worker.stderr is not None:
                    worker.stderr.close()
        finally:
            holder.wait(timeout=10)
        self.assertNotIn(KEY, self._document()["keys"])
        self.assertEqual(
            self.ring.load(TARGET, password=PASSWORD), b"secret")


class RenameCompatibilityTests(RenameTestBase):
    def test_report_schema_and_cli_are_unchanged(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root),
             "report"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(
            set(payload),
            {"domain", "version", "sourceCategories", "tags", "components",
             "readiness"})
        self.assertEqual(payload["components"], ["keyring", "derive"])
        self.assertEqual(
            payload["readiness"],
            {"seal": True, "rotate": True, "revoke": True,
             "constantTime": False})
        # rename is Python-only: no new subcommand was introduced.
        rejected = subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root),
             "rename-key", KEY, TARGET],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(rejected.returncode, 2)


if __name__ == "__main__":
    unittest.main()
