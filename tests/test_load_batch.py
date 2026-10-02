"""Tests for ``KeyRing.load_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts, each requiring ``key_id`` and allowing only
  ``version``/``password`` with ``load``'s defaults and types; bad structure,
  non-dict items, missing/unknown fields and illegal values are ``ValueError``
  raised for the whole batch before storage is touched, and the caller's
  objects are never mutated;
* the same key may repeat, including different historical versions; success
  returns ``list[bytes]`` in request order with duplicates preserved, the
  bytes identical to ``load``, including empty/Unicode material and plain
  records that ignore a supplied passphrase;
* every item is resolved against one committed snapshot (shared lock):
  version resolution (default ``active``), revocation and decryption never
  mix states, so a concurrent batch rotation / set-active / revoke is visible
  only wholly before or wholly after, and a completed read is not denied by a
  revoke that commits later;
* the whole document is validated first -- structural damage in an
  unrequested record is still ``CorruptRecordError``; items are then opened in
  request order and the first failure aborts with load's exact verdicts
  (KeyError/Revoked/Unrecoverable/Missing/Bad/Corrupt), returning no partial
  material and leaving keyring.json byte-for-byte unchanged;
* storage errors keep their types (FileNotFoundError/TimeoutError/OSError);
* v1/v2 records are read without an upgrade write, v2 keeps its full key-name
  binding and key names are not normalised;
* no CLI surface and no report change.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import base64
import copy
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

    def _record(self, key_id: str, version: int) -> dict:
        for item in self._document()["keys"][key_id]["versions"]:
            if item["version"] == version:
                return item
        raise KeyError((key_id, version))

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
            {"key_id": OTHER, "password": PASSWORD, "version": sealed_v},
            # An explicit historical version on a key already requested, plus a
            # fully duplicated request: both must be preserved positionally.
            {"key_id": "k3", "version": third_v, "password": PASSWORD},
            {"key_id": KEY},
        ])
        self.assertEqual(materials, [
            b"three",
            "材料-α".encode("utf-8"),
            "材料-β".encode("utf-8"),
            b"three",
            "材料-α".encode("utf-8"),
        ])
        # Every byte is exactly what single load would have returned.
        self.assertEqual(materials[0], self.ring.load("k3", password=PASSWORD))
        self.assertEqual(materials[1], self.ring.load(KEY, version=plain_v))
        self.assertEqual(materials[2], self.ring.load(OTHER, version=sealed_v, password=PASSWORD))

    def test_default_version_resolves_active_per_snapshot(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.assertEqual(self.ring.active(KEY), second)
        [material] = self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(material, b"two")
        self.ring.set_active(KEY, first)
        [material] = self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(material, b"one")

    def test_same_key_repeated_at_different_versions(self) -> None:
        versions = [self.ring.seal(KEY, text, PASSWORD, iterations=200)
                    for text in ("一", "二", "三")]
        materials = self.ring.load_batch([
            {"key_id": KEY, "version": version, "password": PASSWORD}
            for version in reversed(versions)])
        self.assertEqual(materials, ["三".encode("utf-8"), "二".encode("utf-8"),
                                     "一".encode("utf-8")])

    def test_explicit_none_fields_are_the_defaults(self) -> None:
        self.ring.seal(KEY, "plain")
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "version": None, "password": None}]),
            [b"plain"])

    def test_plain_ignores_supplied_password(self) -> None:
        self.ring.seal(KEY, "secret")
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}]), [b"secret"])
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "password": ""}]), [b"secret"])

    def test_empty_password_empty_material_and_unicode_round_trip(self) -> None:
        plain_v = self.ring.seal("p", "")
        sealed_v = self.ring.seal("s", "", password="", iterations=200)
        unicode_v = self.ring.seal("u", "emoji-😀｜分隔", "口令", iterations=200)
        materials = self.ring.load_batch([
            {"key_id": "p"},
            {"key_id": "s", "password": ""},
            {"key_id": "u", "password": "口令"},
        ])
        self.assertEqual(materials, [b"", b"", "emoji-😀｜分隔".encode("utf-8")])
        self.assertEqual(materials[0], self.ring.load("p", version=plain_v))
        self.assertEqual(materials[1], self.ring.load("s", version=sealed_v, password=""))
        self.assertEqual(materials[2], self.ring.load("u", version=unicode_v, password="口令"))

    def test_full_key_names_are_not_normalised(self) -> None:
        self.ring.seal("k", "lower", PASSWORD, iterations=200)
        self.ring.seal("K", "upper", PASSWORD, iterations=200)
        self.ring.seal("键 ", "spaced", PASSWORD, iterations=200)
        materials = self.ring.load_batch([
            {"key_id": "k", "password": PASSWORD},
            {"key_id": "K", "password": PASSWORD},
            {"key_id": "键 ", "password": PASSWORD},
        ])
        self.assertEqual(materials, [b"lower", b"upper", b"spaced"])

    def test_v2_name_binding_is_enforced_inside_batch(self) -> None:
        number = self.ring.seal("a", "secret", "n", iterations=200)
        document = self._document()
        impostor = copy.deepcopy(self._record("a", number))
        document["keys"]["impostor"] = {"versions": [impostor], "active": impostor["version"]}
        self.ring.path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        # The first item opens; the copied v2 record under another name fails
        # authentication as corruption, aborting the whole batch.
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load_batch([
                {"key_id": "a", "password": "n"},
                {"key_id": "impostor", "password": "n"},
            ])

    def test_v1_read_is_not_upgraded(self) -> None:
        sealed_v = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self._replace_with_v1(KEY, sealed_v, b"secret")
        before = self.ring.path.read_bytes()
        [material] = self.ring.load_batch(
            [{"key_id": KEY, "version": sealed_v, "password": PASSWORD}])
        self.assertEqual(material, b"secret")
        self.assertEqual(self._record(KEY, sealed_v)["scheme"], core.SEALED_SCHEME)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_caller_input_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        requests = [{"key_id": KEY, "password": PASSWORD, "version": 1},
                    {"key_id": OTHER}]
        self.ring.seal(OTHER, "别的")
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.load_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)
        self.assertEqual(requests,
                         [{"key_id": KEY, "password": PASSWORD, "version": 1},
                          {"key_id": OTHER}])

    def test_single_item_batch_matches_load(self) -> None:
        number = self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "version": number, "password": PASSWORD}]),
            [self.ring.load(KEY, version=number, password=PASSWORD)])


class InputValidationTests(LoadBatchTestBase):
    def _batch(self, requests):
        return self.ring.load_batch(requests)

    def test_outer_value_must_be_non_empty_list(self) -> None:
        for bad in (None, [], "x", {"key_id": KEY}, ({"key_id": KEY},), 7, {}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch(bad)

    def test_each_item_must_be_dict(self) -> None:
        for bad in (None, "x", 7, ["x"], (KEY,), [["key_id"]]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch([bad])

    def test_required_fields(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{}])
        with self.assertRaises(ValueError):
            self._batch([{"version": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"password": "x"}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": True}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": ""}])

    def test_unknown_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "bogus": 1}])
        # rotate_password_batch fields are not part of this surface.
        for name in ("new_password", "iterations", "revoke_source"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self._batch([{"key_id": KEY, name: 1}])
        # An unknown field is rejected even when the required one is missing.
        with self.assertRaises(ValueError):
            self._batch([{"bogus": 1}])

    def test_field_value_rules_match_load(self) -> None:
        cases = (
            {"key_id": ""},
            {"key_id": b"k"},
            {"key_id": None},
            {"key_id": KEY, "version": 0},
            {"key_id": KEY, "version": -1},
            {"key_id": KEY, "version": "1"},
            {"key_id": KEY, "version": 1.5},
            {"key_id": KEY, "version": True},
            {"key_id": KEY, "version": False},
            {"key_id": KEY, "password": 1},
            {"key_id": KEY, "password": True},
            {"key_id": KEY, "password": b"x"},
            {"key_id": KEY, "password": 0},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    self._batch([request])

    def test_duplicate_key_ids_are_allowed(self) -> None:
        self.ring.seal("dup", "one")
        self.ring.seal("dup", "two")
        materials = self._batch([
            {"key_id": "dup", "version": 1},
            {"key_id": "dup", "version": 2},
            {"key_id": "dup"},
            {"key_id": "dup", "version": 1},
        ])
        self.assertEqual(materials, [b"one", b"two", b"two", b"one"])

    def test_first_invalid_item_is_reported(self) -> None:
        # Item 0 is structurally fine; item 1 is not a dict.
        with self.assertRaises(ValueError):
            self._batch([{"key_id": "a"}, "not-a-dict"])
        # Item 0's bad value precedes item 1's.
        with self.assertRaisesRegex(ValueError, "version"):
            self._batch([{"key_id": "a", "version": 0}, {"key_id": "a"}])
        with self.assertRaisesRegex(ValueError, "password"):
            self._batch([{"key_id": "a", "password": 0}, {"key_id": "a"}])

    def test_validation_precedes_storage_and_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        bad_batches = (
            [],
            [{"key_id": "missing", "password": 1}],
            [{"key_id": KEY, "version": 0}],
            [{"key_id": KEY, "version": True}],
            [{"key_id": KEY, "new_password": "x"}],
            [{"key_id": KEY}, {"not": "a request"}],
            "not-a-list",
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
            ring.load_batch([{"key_id": KEY, "password": 1}])
        with self.assertRaises(ValueError):
            ring.load_batch([{"key_id": KEY, "version": True}])


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
            self.ring.load_batch([{"key_id": KEY, "version": 99, "password": PASSWORD}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_first_failing_item_in_request_order_is_reported(self) -> None:
        before = self.ring.path.read_bytes()
        # Item 0 fails its passphrase; item 1 names an unknown key. Item 0's
        # verdict must win, and no material at all may come back.
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

    def test_later_item_failure_returns_no_partial_material(self) -> None:
        # Item 0 would open fine; item 1 is revoked. The exception must carry
        # nothing back even for item 0 (verifiable via the API contract: the
        # call raises rather than returning a shorter list).
        self.ring.revoke(KEY, self.sealed)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load_batch([
                {"key_id": OTHER, "password": PASSWORD},
                {"key_id": KEY, "password": PASSWORD},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.versions(KEY), [self.sealed])
        self.assertTrue(self.ring.is_revoked(KEY, self.sealed))
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

    def test_corrupt_keyring_is_corrupt_and_unchanged(self) -> None:
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_damage_in_unrequested_record_is_still_rejected(self) -> None:
        # A structurally broken record on another key that no item requests
        # must fail the whole batch, because the entire store is validated
        # first against one snapshot. Each corruption starts from the same
        # clean document so the validator actually reaches the damage under
        # test rather than an earlier sub-case's.
        self.ring.seal("plain-key", "open")
        clean = self._document()
        before_like = json.dumps(clean, sort_keys=True)
        corruptions = (
            lambda doc: doc["keys"][KEY]["versions"][0].__setitem__("revoked", "yes"),
            lambda doc: doc["keys"][KEY].__setitem__("active", 99),
            lambda doc: doc["keys"]["plain-key"]["versions"][0].__setitem__(
                "material", base64.b64encode(b"\xff\xfe").decode("ascii")),
        )
        for corrupt in corruptions:
            document = copy.deepcopy(clean)
            corrupt(document)
            self.ring.path.write_text(json.dumps(document), encoding="utf-8")
            written = self.ring.path.read_bytes()
            with self.subTest(document=document):
                with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
                    self.ring.load_batch([{"key_id": OTHER, "password": PASSWORD}])
                self.assertEqual(self.ring.path.read_bytes(), written)
        # Sanity: the untouched clean document opens normally.
        self.ring.path.write_text(before_like, encoding="utf-8")
        self.assertEqual(
            self.ring.load_batch([{"key_id": OTHER, "password": PASSWORD}]),
            ["别的".encode("utf-8")])

    def test_v1_record_authenticates_inside_batch(self) -> None:
        self._replace_with_v1(KEY, self.sealed, b"secret")
        [material] = self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])
        self.assertEqual(material, b"secret")
        self.assertEqual(self._record(KEY, self.sealed)["scheme"], core.SEALED_SCHEME)

    def test_missing_ring_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaisesRegex(FileNotFoundError, "no key ring"):
            ring.load_batch([{"key_id": KEY}])

    def test_write_lock_timeout(self) -> None:
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


class NoMutationTests(LoadBatchTestBase):
    def test_success_keeps_keyring_bytes_identical(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        self.ring.seal(KEY, "two")
        self.ring.seal(OTHER, "别的", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        for _ in range(3):
            materials = self.ring.load_batch([
                {"key_id": KEY, "version": 1, "password": PASSWORD},
                {"key_id": KEY},
                {"key_id": OTHER, "password": PASSWORD},
                {"key_id": KEY, "version": 1, "password": PASSWORD},
            ])
            self.assertEqual(
                materials, [b"one", b"two", "别的".encode("utf-8"), b"one"])
            self.assertEqual(self.ring.path.read_bytes(), before)
        # No new versions, no active/revoke movement, no atime-only surprises.
        self.assertEqual(self.ring.versions(KEY), [1, 2])
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertFalse(self.ring.is_revoked(KEY, 1))

    def test_revocation_markers_survive_unchanged(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.ring.revoke(KEY, first)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load_batch([
                {"key_id": KEY, "version": second, "password": PASSWORD},
                {"key_id": KEY, "version": first, "password": PASSWORD},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertTrue(self.ring.is_revoked(KEY, first))
        self.assertFalse(self.ring.is_revoked(KEY, second))


class ThreadSnapshotTests(LoadBatchTestBase):
    """revoke / set-active / batch rotation vs an in-flight load_batch."""

    def _blocking_derive(self, entered: threading.Event, release: threading.Event):
        real_derive = core._derive

        def slow_derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
            # Runs inside load_batch's shared-lock snapshot, after version
            # resolution and before the batch finishes.
            entered.set()
            self.assertTrue(release.wait(timeout=5), "test harness deadlocked")
            return real_derive(password, salt, iterations, length)

        return slow_derive

    def test_revoke_cannot_commit_during_batch(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=2_000)
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        result: dict[str, object] = {}
        original = core._derive
        core._derive = self._blocking_derive(entered, release)
        try:
            def loader() -> None:
                try:
                    result["materials"] = self.ring.load_batch([
                        {"key_id": KEY, "password": PASSWORD},
                        {"key_id": KEY, "version": 1, "password": PASSWORD},
                    ])
                except Exception as error:  # noqa: BLE001 - surfaced via result
                    result["error"] = error

            load_thread = threading.Thread(target=loader)
            load_thread.start()
            self.assertTrue(entered.wait(timeout=5), "load_batch never entered its snapshot")

            def revoker() -> None:
                self.ring.revoke(KEY, 1)
                done.set()

            revoke_thread = threading.Thread(target=revoker)
            revoke_thread.start()
            time.sleep(0.4)
            self.assertFalse(done.is_set(), "revoke committed while the batch was still open")

            release.set()
            load_thread.join(timeout=5)
            revoke_thread.join(timeout=5)
        finally:
            core._derive = original
        # Both items completed against the pre-revoke snapshot; the completed
        # read is not retroactively denied.
        self.assertEqual(result, {"materials": [b"secret", b"secret"]})
        self.assertTrue(done.is_set())
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])

    def test_set_active_cannot_commit_during_batch(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=2_000)
        self.ring.seal(KEY, "two", PASSWORD, iterations=2_000)
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        result: dict[str, object] = {}
        original = core._derive
        core._derive = self._blocking_derive(entered, release)
        try:
            load_thread = threading.Thread(target=lambda: result.setdefault(
                "materials",
                self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}])))
            load_thread.start()
            self.assertTrue(entered.wait(timeout=5))

            def switcher() -> None:
                self.ring.set_active(KEY, 1)
                done.set()

            switch_thread = threading.Thread(target=switcher)
            switch_thread.start()
            time.sleep(0.4)
            self.assertFalse(done.is_set(), "set-active committed during the batch")
            release.set()
            load_thread.join(timeout=5)
            switch_thread.join(timeout=5)
        finally:
            core._derive = original
        # The default (active=2) was resolved in the same snapshot that
        # produced the material; later batches see the committed repoint.
        self.assertEqual(result["materials"], [b"two"])
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "password": PASSWORD}]), [b"one"])

    def test_concurrent_batch_rotation_is_pre_or_post_only(self) -> None:
        # v1 is sealed under PASSWORD and is never rewritten: every rotation
        # re-seals it as a new active version under a fresh password. Each
        # reader batch therefore either observes the pre-rotation state
        # (both items open with PASSWORD) or a committed post state (the
        # default-active item fails its passphrase); it can never mix states
        # or hit KeyError/Corrupt/Revoked, and the explicit v1 item always
        # opens.
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        writer_count, rounds, reader_count = 4, 4, 6
        barrier = threading.Barrier(writer_count + reader_count)
        lock = threading.Lock()
        pre_seen = 0
        post_seen = 0
        errors: list[BaseException] = []
        passwords: dict[int, str] = {1: PASSWORD}

        def reader() -> None:
            nonlocal pre_seen, post_seen
            barrier.wait()
            for _ in range(30):
                try:
                    materials = self.ring.load_batch([
                        {"key_id": KEY, "version": 1, "password": PASSWORD},
                        {"key_id": KEY, "password": PASSWORD},
                    ])
                except core.BadPasswordError:
                    # Active has rotated to a version sealed under another
                    # password: a fully committed post state.
                    with lock:
                        post_seen += 1
                    continue
                except BaseException as error:  # noqa: BLE001
                    with lock:
                        errors.append(error)
                    continue
                with lock:
                    self.assertEqual(materials, [b"secret", b"secret"])
                    pre_seen += 1

        def writer(i: int) -> None:
            barrier.wait()
            for j in range(rounds):
                number = self.ring.rotate_password_batch([{
                    "key_id": KEY, "new_password": f"pw-{i}-{j}",
                    "password": PASSWORD, "version": 1, "iterations": 200}])[0]
                with lock:
                    passwords[number] = f"pw-{i}-{j}"

        threads = [threading.Thread(target=reader) for _ in range(reader_count)]
        threads += [threading.Thread(target=writer, args=(i,)) for i in range(writer_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertGreater(post_seen, 0, "readers never observed a committed rotation")
        # After the storm the history is gapless, the pinned v1 still opens,
        # and every rotated version opens under exactly one committed password.
        numbers = self.ring.versions(KEY)
        self.assertEqual(numbers, list(range(1, writer_count * rounds + 2)))
        self.assertEqual(
            self.ring.load_batch([{"key_id": KEY, "version": 1, "password": PASSWORD}]),
            [b"secret"])
        for number in numbers[1:]:
            self.assertEqual(
                self.ring.load(KEY, version=number, password=passwords[number]),
                b"secret")
        self.assertIn(self.ring.active(KEY), passwords)
        self.assertFalse(any(self.ring.is_revoked(KEY, number) for number in numbers))


class CompatibilityTests(LoadBatchTestBase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)

    def test_no_cli_surface_added(self) -> None:
        result = self._run("load-batch", KEY)
        self.assertNotEqual(result.returncode, 0)

    def test_report_shape_unchanged(self) -> None:
        result = self._run("report")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(set(payload),
                         {"domain", "version", "sourceCategories", "tags", "components", "readiness"})
        self.assertEqual(payload["components"], ["keyring", "derive"])
        self.assertEqual(payload["readiness"],
                         {"seal": True, "rotate": True, "revoke": True, "constantTime": False})
        self.assertEqual(result.stdout.strip(),
                         json.dumps(payload, ensure_ascii=False, sort_keys=True))

    def test_existing_cli_commands_still_work(self) -> None:
        self.assertEqual(self._run("seal", KEY, "secret", "--password", PASSWORD,
                                   "--iterations", "200").returncode, 0)
        loaded = self._run("load", KEY, "--password", PASSWORD)
        self.assertEqual(loaded.returncode, 0, loaded.stderr)
        self.assertEqual(loaded.stdout, "secret\n")


if __name__ == "__main__":
    unittest.main()
