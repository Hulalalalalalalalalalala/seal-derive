"""Tests for ``KeyRing.load_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts, each requiring ``key_id`` and allowing only
  ``version``/``password`` with ``load``'s defaults and types; bad structure,
  non-dict items, missing/unknown fields and illegal values are ``ValueError``
  raised for the whole batch before storage is touched, and the caller's
  objects are never mutated;
* every item is resolved against one committed snapshot (active by default;
  plain/v1/v2 keep ``load`` semantics); duplicates of one key, including
  different historical versions, are preserved in request order and the
  returned bytes equal single ``load`` bytes;
* the whole store is validated first -- even an unreferenced corrupt record
  raises ``CorruptRecordError`` -- then items open in request order with
  load's exact verdicts (KeyError/Revoked/Unrecoverable/Missing/Bad/Corrupt),
  the first failure aborts, no partial materials come back and keyring.json
  keeps its exact prior bytes on both success and failure;
* a concurrent rotation batch, set_active or revoke can only be observed
  whole, before or after the batch; a later revoke never negates a finished
  read;
* no CLI surface and no report change.

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
OTHER = "别的键"
PASSWORD = "correct horse"


class LoadBatchTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _replace_with_v1(self, key_id: str, version: int, plaintext: bytes,
                         password: str = PASSWORD, iterations: int = 1_000) -> None:
        document = self._document()
        record = next(item for item in document["keys"][key_id]["versions"]
                      if item["version"] == version)
        salt = base64.b64decode(record["salt"])
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


class HappyPathTests(LoadBatchTestBase):
    def test_mixed_sources_load_together_in_request_order(self) -> None:
        plain_v = self.ring.seal(KEY, "材料-α")
        sealed_v = self.ring.seal(OTHER, "材料-β", PASSWORD, iterations=1_000)
        self._replace_with_v1(OTHER, sealed_v, "材料-β".encode("utf-8"))
        third_v = self.ring.seal("k3", "three", PASSWORD, iterations=1_000)
        materials = self.ring.load_batch([
            {"key_id": "k3", "password": PASSWORD},
            {"key_id": KEY},
            {"key_id": OTHER, "password": PASSWORD},
        ])
        self.assertEqual(materials, [
            self.ring.load("k3", password=PASSWORD),
            self.ring.load(KEY),
            self.ring.load(OTHER, password=PASSWORD),
        ])
        self.assertEqual(materials, [
            b"three", "材料-α".encode("utf-8"), "材料-β".encode("utf-8")])
        self.assertEqual(plain_v, 1)
        self.assertEqual(sealed_v, 1)
        self.assertEqual(third_v, 1)

    def test_same_key_repeated_with_different_versions_keeps_duplicates(self) -> None:
        first = self.ring.seal(KEY, "一", PASSWORD, iterations=200)
        second = self.ring.seal(KEY, "二", PASSWORD, iterations=200)
        third = self.ring.seal(KEY, "三")
        materials = self.ring.load_batch([
            {"key_id": KEY, "version": third},
            {"key_id": KEY},                       # default == active == third
            {"key_id": KEY, "version": first, "password": PASSWORD},
            {"key_id": KEY, "version": second, "password": PASSWORD},
            {"key_id": KEY, "version": third},
        ])
        self.assertEqual(materials, [
            "三".encode("utf-8"), "三".encode("utf-8"),
            "一".encode("utf-8"), "二".encode("utf-8"), "三".encode("utf-8")])
        self.assertEqual([first, second, third], [1, 2, 3])

    def test_explicit_none_matches_defaults_and_plain_ignores_password(self) -> None:
        source = self.ring.seal(KEY, "材料")
        materials = self.ring.load_batch([
            {"key_id": KEY, "version": None, "password": None},
            # A legal but irrelevant passphrase on a plain record is ignored.
            {"key_id": KEY, "password": "definitely-not-the-password"},
        ])
        self.assertEqual(materials, ["材料".encode("utf-8"), "材料".encode("utf-8")])
        self.assertEqual(source, 1)

    def test_empty_password_empty_material_and_unicode(self) -> None:
        empty_v = self.ring.seal("e", "", "", iterations=200)
        uni_v = self.ring.seal("u", "emoji-😀", PASSWORD, iterations=200)
        materials = self.ring.load_batch([
            {"key_id": "e", "password": ""},
            {"key_id": "u", "password": PASSWORD},
        ])
        self.assertEqual(materials, [b"", "emoji-😀".encode("utf-8")])
        self.assertEqual((empty_v, uni_v), (1, 1))

    def test_full_key_names_are_not_normalised(self) -> None:
        self.ring.seal("k", "lower", PASSWORD, iterations=200)
        self.ring.seal("K", "upper", PASSWORD, iterations=200)
        self.ring.seal("键", "中文", PASSWORD, iterations=200)
        materials = self.ring.load_batch([
            {"key_id": "k", "password": PASSWORD},
            {"key_id": "K", "password": PASSWORD},
            {"key_id": "键", "password": PASSWORD},
        ])
        self.assertEqual(materials, [b"lower", b"upper", "中文".encode("utf-8")])

    def test_v1_and_v2_records_open_without_upgrade(self) -> None:
        v1 = self.ring.seal("a", "old", PASSWORD, iterations=1_000)
        self._replace_with_v1("a", v1, b"old")
        v2 = self.ring.seal("b", "new", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        materials = self.ring.load_batch([
            {"key_id": "a", "password": PASSWORD},
            {"key_id": "b", "password": PASSWORD},
        ])
        self.assertEqual(materials, [b"old", b"new"])
        # Read-only: the file is byte-for-byte the same and v1 stays v1.
        self.assertEqual(self.ring.path.read_bytes(), before)
        document = self._document()
        self.assertEqual(document["keys"]["a"]["versions"][0]["scheme"],
                         core.SEALED_SCHEME)
        self.assertEqual(document["keys"]["b"]["versions"][0]["scheme"],
                         core.SEALED_V2_SCHEME)
        self.assertEqual(v2, 1)

    def test_successful_batch_never_rewrites_keyring(self) -> None:
        self.ring.seal(KEY, "plain")
        self.ring.seal(OTHER, "sealed", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        materials = self.ring.load_batch([
            {"key_id": KEY},
            {"key_id": OTHER, "password": PASSWORD},
            {"key_id": KEY},
        ])
        self.assertEqual(materials, [b"plain", "sealed".encode(), b"plain"])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_caller_input_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        requests = [{"key_id": KEY, "password": PASSWORD, "version": 1}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.load_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)
        self.assertEqual(requests, [{"key_id": KEY, "password": PASSWORD, "version": 1}])

    def test_single_item_batch_matches_load(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "version": source,
                                  "password": PASSWORD}]),
            [self.ring.load(KEY, version=source, password=PASSWORD)])


class InputValidationTests(LoadBatchTestBase):
    def _batch(self, requests):
        return self.ring.load_batch(requests)

    def test_outer_value_must_be_non_empty_list(self) -> None:
        for bad in (None, [], "x", {"key_id": KEY}, ({"key_id": KEY},), 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch(bad)

    def test_each_item_must_be_dict(self) -> None:
        for bad in (None, "x", 7, ["x"], (KEY,)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch([bad])

    def test_required_fields(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{}])
        with self.assertRaises(ValueError):
            self._batch([{"version": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"password": "p"}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": True}])

    def test_unknown_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "bogus": 1}])
        # An unknown field is rejected even when key_id is missing.
        with self.assertRaises(ValueError):
            self._batch([{"bogus": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "password": "p", "new_password": "x"}])

    def test_field_value_rules_match_load(self) -> None:
        cases = (
            {"key_id": ""},
            {"key_id": 1},
            {"key_id": None},
            {"key_id": b"k"},
            {"key_id": KEY, "version": 0},
            {"key_id": KEY, "version": -1},
            {"key_id": KEY, "version": "1"},
            {"key_id": KEY, "version": True},
            {"key_id": KEY, "version": 1.5},
            {"key_id": KEY, "password": 1},
            {"key_id": KEY, "password": True},
            {"key_id": KEY, "password": b"x"},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    self._batch([request])

    def test_duplicate_key_ids_are_allowed(self) -> None:
        first = self.ring.seal("a", "one", PASSWORD, iterations=200)
        second = self.ring.seal("a", "two", PASSWORD, iterations=200)
        materials = self._batch([
            {"key_id": "a", "version": first, "password": PASSWORD},
            {"key_id": "a", "version": second, "password": PASSWORD},
            {"key_id": "a", "version": first, "password": PASSWORD},
        ])
        self.assertEqual(materials, [b"one", b"two", b"one"])

    def test_first_invalid_item_is_reported(self) -> None:
        # Item 0 is structurally fine; item 1 is not a dict.
        with self.assertRaises(ValueError):
            self._batch([{"key_id": "a"}, "not-a-dict"])
        # Item 0's bad value precedes item 1's bad value.
        with self.assertRaisesRegex(ValueError, "version"):
            self._batch([{"key_id": "a", "version": True},
                         {"key_id": "a", "password": 1}])

    def test_validation_precedes_storage_and_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        bad_batches = (
            [],
            [{"version": 1}],
            [{"key_id": "missing", "bogus": None}],
            [{"key_id": KEY, "version": True}],
            [{"key_id": KEY, "password": 1}],
            "not-a-list",
            [{"key_id": KEY}, "not-a-dict"],
        )
        for requests in bad_batches:
            with self.subTest(requests=requests):
                with self.assertRaises(ValueError):
                    self._batch(requests)
                self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_input_on_missing_ring_is_value_error_not_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.load_batch([])
        with self.assertRaises(ValueError):
            ring.load_batch([{"key_id": 1}])
        with self.assertRaises(ValueError):
            ring.load_batch([{"key_id": KEY, "password": 0}])


class ErrorOrderTests(LoadBatchTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.sealed = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.other = self.ring.seal(OTHER, "别的", PASSWORD, iterations=1_000)

    def test_unknown_key_is_keyerror_and_changes_nothing(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.load_batch([{"key_id": "missing"}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_version_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.load_batch([{"key_id": KEY, "version": 99,
                                   "password": PASSWORD}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_first_failing_item_in_request_order_is_reported(self) -> None:
        before = self.ring.path.read_bytes()
        # Item 0 fails its passphrase; item 1 names an unknown key. Item 0's
        # verdict must win.
        with self.assertRaises(core.BadPasswordError):
            self.ring.load_batch([
                {"key_id": KEY, "password": "wrong"},
                {"key_id": "no-such-key"},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Reversed order: the unknown key is now encountered first.
        with self.assertRaises(KeyError):
            self.ring.load_batch([
                {"key_id": "no-such-key"},
                {"key_id": KEY, "password": "wrong"},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_later_item_failure_returns_nothing_even_for_opened_items(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.BadPasswordError):
            self.ring.load_batch([
                {"key_id": OTHER, "password": PASSWORD},
                {"key_id": KEY, "password": "wrong"},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Nothing about the failure persists: both keys and versions intact.
        self.assertEqual(self.ring.versions(KEY), [self.sealed])
        self.assertEqual(self.ring.versions(OTHER), [self.other])
        self.assertFalse(self.ring.is_revoked(KEY, self.sealed))
        self.assertFalse(self.ring.is_revoked(OTHER, self.other))

    def test_revoked_version(self) -> None:
        self.ring.revoke(KEY, self.sealed)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_revoked_check_precedes_password_check(self) -> None:
        self.ring.revoke(KEY, self.sealed)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load_batch([{"key_id": KEY}])
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load_batch([{"key_id": KEY, "password": "wrong"}])

    def test_revoked_item_after_good_item_aborts_whole_batch(self) -> None:
        self.ring.revoke(KEY, self.sealed)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load_batch([
                {"key_id": OTHER, "password": PASSWORD},
                {"key_id": KEY, "password": PASSWORD},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_legacy_derived_record_is_unrecoverable(self) -> None:
        document = self._document()
        document["keys"][KEY]["versions"][0] = {
            "version": self.sealed, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": False}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.load_batch([{"key_id": KEY}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_wrong_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.load_batch([{"key_id": KEY, "password": "wrong"}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_tampered_record_with_correct_password_is_corrupt(self) -> None:
        document = self._document()
        material = bytearray(base64.b64decode(
            document["keys"][KEY]["versions"][0]["material"]))
        material[0] ^= 0x01
        document["keys"][KEY]["versions"][0]["material"] = \
            base64.b64encode(bytes(material)).decode("ascii")
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_unreferenced_record_still_rejects_whole_batch(self) -> None:
        # The request only names OTHER; KEY's record is nevertheless part of
        # the store and its damage must be reported before any item opens.
        document = self._document()
        document["keys"][KEY]["versions"][0].pop("revoked")
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load_batch([{"key_id": OTHER, "password": PASSWORD}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_unrequested_version_of_requested_key_rejects_too(self) -> None:
        # Item asks for the active sealed OTHER; damage a *different* key
        # entirely, reinforcing that whole-document validation comes first.
        self.ring.seal("bystander", "x")
        document = self._document()
        document["keys"]["bystander"]["active"] = 99
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load_batch([{"key_id": OTHER, "password": PASSWORD}])

    def test_corrupt_keyring_file_is_corrupt_and_unchanged(self) -> None:
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load_batch([{"key_id": KEY}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_v1_record_authenticates_inside_batch(self) -> None:
        self._replace_with_v1(KEY, self.sealed, b"secret")
        materials = self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(materials, [b"secret"])
        # The v1 record itself is neither upgraded nor rewritten.
        self.assertEqual(self._document()["keys"][KEY]["versions"][0]["scheme"],
                         core.SEALED_SCHEME)

    def test_missing_ring_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaisesRegex(FileNotFoundError, "no key ring"):
            ring.load_batch([{"key_id": KEY}])

    def test_lock_timeout(self) -> None:
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
                self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)


class SnapshotTests(LoadBatchTestBase):
    """Writers cannot commit while a batch has the shared-lock snapshot."""

    def _blocking_derive(self, entered: threading.Event, release: threading.Event):
        real_derive = core._derive

        def slow_derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
            # Runs inside the batch snapshot, before the revocation verdict.
            entered.set()
            self.assertTrue(release.wait(timeout=5), "test harness deadlocked")
            return real_derive(password, salt, iterations, length)

        return slow_derive

    def test_revoke_cannot_commit_during_batch(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=2_000)
        self.ring.seal(OTHER, "other", PASSWORD, iterations=2_000)
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        result: dict[str, object] = {}
        original = core._derive
        core._derive = self._blocking_derive(entered, release)
        try:
            def loader() -> None:
                try:
                    result["materials"] = self.ring.load_batch([
                        {"key_id": KEY, "password": PASSWORD},
                        {"key_id": OTHER, "password": PASSWORD},
                    ])
                except Exception as error:  # noqa: BLE001 - surfaced via result
                    result["error"] = error

            load_thread = threading.Thread(target=loader)
            load_thread.start()
            self.assertTrue(entered.wait(timeout=5), "batch never entered its snapshot")

            revoke_thread = threading.Thread(
                target=lambda: (self.ring.revoke(KEY, 1), done.set()))
            revoke_thread.start()
            time.sleep(0.4)
            self.assertFalse(done.is_set(), "revoke committed while batch was still open")

            release.set()
            load_thread.join(timeout=5)
            revoke_thread.join(timeout=5)
        finally:
            core._derive = original
        # The finished read is not retroactively denied by the later commit...
        self.assertEqual(result["materials"], [b"secret", b"other"])
        self.assertTrue(done.is_set())
        # ...but every later batch resolves against the post-revoke state.
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load_batch([
                {"key_id": KEY, "password": PASSWORD},
                {"key_id": OTHER, "password": PASSWORD},
            ])
        # Requesting only the untouched key still works after the revoke.
        self.assertEqual(
            self.ring.load_batch([{"key_id": OTHER, "password": PASSWORD}]),
            [b"other"])

    def test_set_active_cannot_commit_during_default_batch(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=2_000)
        self.ring.seal(KEY, "two", PASSWORD, iterations=2_000)
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        result: dict[str, object] = {}
        original = core._derive
        core._derive = self._blocking_derive(entered, release)
        try:
            load_thread = threading.Thread(target=lambda: result.setdefault(
                "materials", self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])))
            load_thread.start()
            self.assertTrue(entered.wait(timeout=5))

            switch_thread = threading.Thread(
                target=lambda: (self.ring.set_active(KEY, 1), done.set()))
            switch_thread.start()
            time.sleep(0.4)
            self.assertFalse(done.is_set(), "set-active committed during a default batch")
            release.set()
            load_thread.join(timeout=5)
            switch_thread.join(timeout=5)
        finally:
            core._derive = original
        # Default resolved in the pre-switch snapshot: active was version 2.
        self.assertEqual(result["materials"], [b"two"])
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}]), [b"one"])

    def test_batches_observe_whole_states_under_a_rotation_storm(self) -> None:
        # During a storm of multi-key rotation batches every load_batch takes
        # one internally consistent snapshot: the pinned plain v1 sources stay
        # readable throughout, and a default request repeated inside one batch
        # resolves the same active both times (never a half-committed state).
        keys = ["a", "b", "c", "d"]
        for key_id in keys:
            self.ring.seal(key_id, "secret")
        stop = threading.Event()
        errors: list[BaseException] = []

        def reader() -> None:
            try:
                while not stop.is_set():
                    # Validate one shared-lock snapshot at a time: that is the
                    # guarantee under test -- a committed document is always
                    # internally whole. Comparing two public calls against
                    # each other would mix snapshots taken either side of a
                    # rotation commit, which is a legitimate observation.
                    with core._locked(self.ring, exclusive=False):
                        document = self.ring._read()
                    for key_id in keys:
                        entry = document["keys"][key_id]
                        numbers = [item["version"] for item in entry["versions"]]
                        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))
                        self.assertIn(entry["active"], numbers)
                    # The pinned plain source survives every rotation; v1 is
                    # never revoked or rewritten. load_batch must keep opening
                    # all four inside one snapshot.
                    pinned = self.ring.load_batch(
                        [{"key_id": key_id, "version": 1} for key_id in keys])
                    self.assertEqual(pinned, [b"secret"] * len(keys))
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        def writer(i: int) -> None:
            try:
                for _ in range(3):
                    self.ring.rotate_password_batch([
                        {"key_id": key_id, "new_password": f"pw-{i}",
                         "version": 1, "iterations": 200}
                        for key_id in keys])
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        writers = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for thread in writers:
            thread.start()
        for thread in writers:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())
        stop.set()
        reader_thread.join(timeout=10)
        self.assertFalse(reader_thread.is_alive())
        self.assertEqual(errors, [])

    def test_batch_sees_either_pre_or_post_rotation_state(self) -> None:
        # A rotation either committed before the batch snapshot (the new
        # version opens under the new passphrase and is active) or has not
        # (the old passphrase opens active). Blocking writers at the snapshot
        # boundary makes the "before" case deterministic; the "after" case is
        # the ordinary post-commit read.
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(before, [b"secret"])
        new_version = self.ring.rotate_password_batch(
            [{"key_id": KEY, "new_password": "n", "password": PASSWORD,
              "iterations": 200}])
        after = self.ring.load_batch([{"key_id": KEY, "password": "n"}])
        self.assertEqual(after, [b"secret"])
        # The old version is still readable by its pinned number.
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "version": 1,
                                   "password": PASSWORD}]),
            [b"secret"])
        self.assertEqual(self.ring.active(KEY), new_version[0])


if __name__ == "__main__":
    unittest.main()
