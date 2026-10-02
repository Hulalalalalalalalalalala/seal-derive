"""Tests for ``KeyRing.rotate_password_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts sharing ``rotate_password``'s fields, defaults
  and types; bad structure, missing/unknown fields, duplicate key ids and
  illegal values are ``ValueError`` raised for the whole batch before storage
  is touched, and the caller's objects are never mutated;
* every item is resolved against one committed snapshot (active by default;
  plain/v1/v2 keep ``load`` semantics): the material bytes are re-sealed as a
  fresh v2 record with its own salt, the version is that key's own max+1,
  unrevoked and active, and only that item's source may be revoked;
* the first failing item is reported in request order with load's exact
  verdicts (KeyError/Revoked/Unrecoverable/Missing/Bad/Corrupt), leaving
  keyring.json byte-for-byte unchanged and returning no partial result;
* concurrent batches serialise to unique, gapless per-key histories and the
  single atomic commit is visible only whole, before or after;
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
NEW_PASSWORD = "battery staple"


class BatchTestBase(unittest.TestCase):
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


class HappyPathTests(BatchTestBase):
    def test_mixed_sources_rotate_together_in_request_order(self) -> None:
        plain_v = self.ring.seal(KEY, "材料-α")
        sealed_v = self.ring.seal(OTHER, "材料-β", PASSWORD, iterations=1_000)
        self._replace_with_v1(OTHER, sealed_v, "材料-β".encode("utf-8"))
        third_v = self.ring.seal("k3", "three", PASSWORD, iterations=1_000)
        new_versions = self.ring.rotate_password_batch([
            {"key_id": "k3", "new_password": "np3", "password": PASSWORD, "iterations": 2_000},
            {"key_id": KEY, "new_password": NEW_PASSWORD},
            {"key_id": OTHER, "new_password": "np2", "password": PASSWORD,
             "iterations": 3_000, "revoke_source": True},
        ])
        # Returned numbers follow request order, but each is computed against
        # that key's own history (all three keys currently hold one version).
        self.assertEqual(new_versions, [third_v + 1, plain_v + 1, sealed_v + 1])
        self.assertEqual(self.ring.load("k3", password="np3"), b"three")
        self.assertEqual(self.ring.load(KEY, password=NEW_PASSWORD), "材料-α".encode("utf-8"))
        self.assertEqual(self.ring.load(OTHER, password="np2"), "材料-β".encode("utf-8"))
        for key_id, number, iterations in (
                ("k3", new_versions[0], 2_000),
                (KEY, new_versions[1], 200_000),
                (OTHER, new_versions[2], 3_000)):
            record = self._record(key_id, number)
            self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
            self.assertFalse(record["revoked"])
            self.assertEqual(record["iterations"], iterations)
            self.assertEqual(self.ring.active(key_id), number)
        # Only the item asking for it loses its source.
        self.assertFalse(self.ring.is_revoked(KEY, plain_v))
        self.assertFalse(self.ring.is_revoked("k3", third_v))
        self.assertTrue(self.ring.is_revoked(OTHER, sealed_v))
        # Sources that survive are still independently readable.
        self.assertEqual(self.ring.load(KEY, version=plain_v), "材料-α".encode("utf-8"))
        self.assertEqual(
            self.ring.load("k3", version=third_v, password=PASSWORD), b"three")

    def test_version_is_per_key_history_max_plus_one_with_gaps(self) -> None:
        first = self.ring.seal(KEY, "一", PASSWORD, iterations=200)
        second = self.ring.seal(KEY, "二", PASSWORD, iterations=200)
        third = self.ring.seal(KEY, "三", PASSWORD, iterations=200)
        self.ring.set_active(KEY, first)
        other = self.ring.seal("o", "x", PASSWORD, iterations=200)
        new_versions = self.ring.rotate_password_batch([
            # Explicit non-active source on a key whose active points at v1.
            {"key_id": KEY, "new_password": "n", "password": PASSWORD,
             "version": second, "iterations": 200},
            {"key_id": "o", "new_password": "n", "password": PASSWORD, "iterations": 200},
        ])
        self.assertEqual(new_versions, [third + 1, other + 1])
        self.assertEqual(self.ring.versions(KEY), [first, second, third, third + 1])
        self.assertEqual(
            self.ring.load(KEY, version=third + 1, password="n"), "二".encode("utf-8"))
        self.assertEqual(self.ring.active(KEY), third + 1)

    def test_plain_source_ignores_password_and_empty_password_round_trips(self) -> None:
        source = self.ring.seal(KEY, "")
        new_versions = self.ring.rotate_password_batch(
            [{"key_id": KEY, "new_password": "", "password": PASSWORD}])
        self.assertEqual(new_versions, [source + 1])
        self.assertEqual(self.ring.load(KEY, version=source + 1, password=""), b"")
        self.assertFalse(self.ring.is_revoked(KEY, source))

    def test_unicode_material_and_full_key_name_distinction(self) -> None:
        self.ring.seal("k", "emoji-😀", PASSWORD, iterations=200)
        self.ring.seal("K", "upper", PASSWORD, iterations=200)
        new_versions = self.ring.rotate_password_batch([
            {"key_id": "k", "new_password": "n1", "password": PASSWORD, "iterations": 200},
            {"key_id": "K", "new_password": "n2", "password": PASSWORD, "iterations": 200},
        ])
        self.assertEqual(new_versions, [2, 2])
        self.assertEqual(self.ring.load("k", password="n1"), "emoji-😀".encode("utf-8"))
        self.assertEqual(self.ring.load("K", password="n2"), b"upper")

    def test_each_record_gets_distinct_fresh_salt_and_binds_name(self) -> None:
        self.ring.seal("a", "same", PASSWORD, iterations=200)
        self.ring.seal("b", "same", PASSWORD, iterations=200)
        new_versions = self.ring.rotate_password_batch([
            {"key_id": "a", "new_password": "n", "password": PASSWORD, "iterations": 200},
            {"key_id": "b", "new_password": "n", "password": PASSWORD, "iterations": 200},
        ])
        salt_a = self._record("a", new_versions[0])["salt"]
        salt_b = self._record("b", new_versions[1])["salt"]
        self.assertNotEqual(salt_a, salt_b)
        # A v2 record copied onto another key name cannot authenticate.
        import copy
        document = self._document()
        impostor = copy.deepcopy(self._record("a", new_versions[0]))
        document["keys"]["impostor"] = {"versions": [impostor], "active": impostor["version"]}
        self.ring.path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load("impostor", password="n")

    def test_sibling_versions_of_participating_keys_are_untouched(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        bystander = self.ring.seal("z", "旁", PASSWORD, iterations=200)
        self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": "n", "password": PASSWORD,
             "version": first, "iterations": 200},
        ])
        self.assertEqual(
            self.ring.load(KEY, version=second, password=PASSWORD), b"two")
        self.assertEqual(
            self.ring.load("z", version=bystander, password=PASSWORD), "旁".encode("utf-8"))
        self.assertFalse(self.ring.is_revoked(KEY, first))
        self.assertFalse(self.ring.is_revoked(KEY, second))

    def test_caller_input_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "secret")
        requests = [{"key_id": KEY, "new_password": NEW_PASSWORD}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.rotate_password_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)
        self.assertEqual(requests, [{"key_id": KEY, "new_password": NEW_PASSWORD}])

    def test_single_item_batch_matches_rotate_password_outcome(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        [number] = self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": NEW_PASSWORD, "password": PASSWORD,
             "iterations": 400, "revoke_source": True}])
        self.assertEqual(number, source + 1)
        self.assertTrue(self.ring.is_revoked(KEY, source))
        self.assertEqual(self.ring.load(KEY, password=NEW_PASSWORD), b"secret")
        self.assertEqual(self._record(KEY, number)["scheme"], core.SEALED_V2_SCHEME)


class InputValidationTests(BatchTestBase):
    def _batch(self, requests):
        return self.ring.rotate_password_batch(requests)

    def test_outer_value_must_be_non_empty_list(self) -> None:
        for bad in (None, [], "x", {"key_id": KEY}, ({"key_id": KEY, "new_password": "x"},), 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch(bad)

    def test_each_item_must_be_dict(self) -> None:
        for bad in (None, "x", 7, ["x"], (KEY, "x")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch([bad])

    def test_required_fields(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{}])
        with self.assertRaises(ValueError):
            self._batch([{"new_password": "x"}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": True, "new_password": "x"}])

    def test_unknown_fields_rejected(self) -> None:
        base = {"key_id": KEY, "new_password": "x"}
        with self.assertRaises(ValueError):
            self._batch([{**base, "bogus": 1}])
        # An unknown field is rejected even when a required one is missing.
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "bogus": 1}])
        with self.assertRaises(ValueError):
            self._batch([{**base, "password": "p", "revoke_source": False, "x": 0}])

    def test_field_value_rules_match_rotate_password(self) -> None:
        base = {"key_id": KEY, "new_password": "x"}
        cases = (
            {"key_id": "", "new_password": "x"},
            {**base, "new_password": None},
            {**base, "new_password": 1},
            {**base, "new_password": True},
            {**base, "password": 1},
            {**base, "password": True},
            {**base, "password": b"x"},
            {**base, "version": 0},
            {**base, "version": -1},
            {**base, "version": "1"},
            {**base, "version": True},
            {**base, "iterations": 0},
            {**base, "iterations": 1.5},
            {**base, "iterations": True},
            {**base, "iterations": "200"},
            {**base, "revoke_source": 0},
            {**base, "revoke_source": 1},
            {**base, "revoke_source": "true"},
            {**base, "revoke_source": None},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    self._batch([request])

    def test_duplicate_key_ids_are_value_errors(self) -> None:
        base = {"new_password": "x"}
        with self.assertRaises(ValueError):
            self._batch([{"key_id": "a", **base}, {"key_id": "a", **base}])
        # The comparison uses exact full strings: case-folded look-alikes are
        # different keys and must pass input validation.
        self.ring.seal("a", "x")
        self.ring.seal("A", "y")
        numbers = self._batch([{"key_id": "a", "new_password": "n"},
                               {"key_id": "A", "new_password": "n"}])
        self.assertEqual(numbers, [2, 2])

    def test_first_invalid_item_is_reported(self) -> None:
        self.ring.seal("a", "x")
        # Item 0 is structurally fine; item 1 is not a dict.
        with self.assertRaises(ValueError):
            self._batch([{"key_id": "a", "new_password": "n"}, "not-a-dict"])
        # Item 0's bad value precedes item 1's duplicate.
        with self.assertRaisesRegex(ValueError, "iterations"):
            self._batch([{"key_id": "a", "new_password": "n", "iterations": 0},
                         {"key_id": "a", "new_password": "m"}])

    def test_validation_precedes_storage_and_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        bad_batches = (
            [],
            [{"key_id": "missing", "new_password": 1}],
            [{"key_id": KEY, "new_password": "n", "iterations": 0}],
            [{"key_id": KEY, "new_password": "n", "revoke_source": 1}],
            [{"key_id": KEY, "new_password": "n", "version": True}],
            [{"key_id": KEY, "new_password": "n"}, {"key_id": KEY, "new_password": "m"}],
            [{"key_id": KEY, "new_password": "n", "nope": None}],
        )
        for requests in bad_batches:
            with self.subTest(requests=requests):
                with self.assertRaises(ValueError):
                    self._batch(requests)
                self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_input_on_missing_ring_is_value_error_not_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.rotate_password_batch([])
        with self.assertRaises(ValueError):
            ring.rotate_password_batch([{"key_id": KEY, "new_password": 1}])


class ErrorOrderTests(BatchTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.sealed = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.other = self.ring.seal(OTHER, "别的", PASSWORD, iterations=1_000)

    def test_unknown_key_is_keyerror_and_changes_nothing(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rotate_password_batch([{"key_id": "missing", "new_password": "x"}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_version_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "x", "password": PASSWORD,
                 "version": 99, "iterations": 1_000}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_first_failing_item_in_request_order_is_reported(self) -> None:
        before = self.ring.path.read_bytes()
        # Item 0 fails its passphrase; item 1 names an unknown key. Item 0's
        # verdict must win, and neither item may be applied.
        with self.assertRaises(core.BadPasswordError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "x", "password": "wrong",
                 "iterations": 1_000},
                {"key_id": "no-such-key", "new_password": "x"},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Reversed order: the unknown key is now encountered first.
        with self.assertRaises(KeyError):
            self.ring.rotate_password_batch([
                {"key_id": "no-such-key", "new_password": "x"},
                {"key_id": KEY, "new_password": "x", "password": "wrong",
                 "iterations": 1_000},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_later_item_failure_aborts_earlier_successful_item(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.BadPasswordError):
            self.ring.rotate_password_batch([
                {"key_id": OTHER, "new_password": "ok", "password": PASSWORD,
                 "iterations": 1_000, "revoke_source": True},
                {"key_id": KEY, "new_password": "x", "password": "wrong",
                 "iterations": 1_000},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # No partial append, no partial revocation, no partial active repoint.
        self.assertEqual(self.ring.versions(OTHER), [self.other])
        self.assertEqual(self.ring.active(OTHER), self.other)
        self.assertFalse(self.ring.is_revoked(OTHER, self.other))
        self.assertEqual(self.ring.versions(KEY), [self.sealed])

    def test_revoked_source(self) -> None:
        self.ring.revoke(KEY, self.sealed)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.rotate_password_batch(
                [{"key_id": KEY, "new_password": "x", "password": PASSWORD,
                  "iterations": 1_000}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_revoked_check_precedes_password_check(self) -> None:
        self.ring.revoke(KEY, self.sealed)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.rotate_password_batch(
                [{"key_id": KEY, "new_password": "x", "iterations": 1_000}])
        with self.assertRaises(core.RevokedVersionError):
            self.ring.rotate_password_batch(
                [{"key_id": KEY, "new_password": "x", "password": "wrong",
                  "iterations": 1_000}])

    def test_legacy_derived_source_is_unrecoverable(self) -> None:
        document = self._document()
        document["keys"][KEY]["versions"][0] = {
            "version": self.sealed, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": False}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.rotate_password_batch(
                [{"key_id": KEY, "new_password": "x", "password": PASSWORD,
                  "iterations": 1_000}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_old_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.rotate_password_batch(
                [{"key_id": KEY, "new_password": "x", "iterations": 1_000}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_wrong_old_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.rotate_password_batch(
                [{"key_id": KEY, "new_password": "x", "password": "wrong",
                  "iterations": 1_000}])
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
            self.ring.rotate_password_batch(
                [{"key_id": KEY, "new_password": "x", "password": PASSWORD,
                  "iterations": 1_000}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_keyring_is_corrupt_and_unchanged(self) -> None:
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.rotate_password_batch([{"key_id": KEY, "new_password": "x"}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_v1_source_authenticates_inside_batch(self) -> None:
        self._replace_with_v1(KEY, self.sealed, b"secret")
        [number] = self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": "n", "password": PASSWORD,
             "iterations": 1_000}])
        self.assertEqual(self._record(KEY, number)["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(self.ring.load(KEY, version=number, password="n"), b"secret")
        # The v1 source itself is neither upgraded nor rewritten.
        self.assertEqual(self._record(KEY, self.sealed)["scheme"], core.SEALED_SCHEME)

    def test_missing_ring_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaisesRegex(FileNotFoundError, "no key ring"):
            ring.rotate_password_batch([{"key_id": KEY, "new_password": "x"}])

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
                self.ring.rotate_password_batch(
                    [{"key_id": KEY, "new_password": "x", "password": PASSWORD,
                      "iterations": 1_000}])
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)


class ConcurrencyTests(BatchTestBase):
    def test_parallel_batches_serialise_to_gapless_unique_versions(self) -> None:
        # Every batch pins the plain v1 source of every key: that source stays
        # open and unrevoked throughout, so every worker can authenticate no
        # matter how active moved. Batches touch the same four keys.
        keys = ["k0", "k1", "k2", "k3"]
        for key_id in keys:
            self.ring.seal(key_id, "secret")
        count = 6
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        results: dict[str, dict[int, int]] = {key_id: {} for key_id in keys}
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                requests = [
                    {"key_id": key_id, "new_password": f"pw-{i}-{key_id}",
                     "version": 1, "iterations": 200}
                    for key_id in keys]
                numbers = self.ring.rotate_password_batch(requests)
                with lock:
                    for key_id, number in zip(keys, numbers):
                        results[key_id][number] = i
            except BaseException as error:  # noqa: BLE001 - surfaced to assertions
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        for key_id in keys:
            # Gapless 2..count+1, each number produced by exactly one batch.
            self.assertEqual(sorted(results[key_id]), list(range(2, 2 + count)))
            self.assertEqual(self.ring.versions(key_id), list(range(1, 2 + count)))
            for number, winner in results[key_id].items():
                self.assertFalse(self.ring.is_revoked(key_id, number))
                self.assertEqual(
                    self.ring.load(key_id, version=number,
                                   password=f"pw-{winner}-{key_id}"),
                    b"secret")
            # Active points at a committed version from one of the batches.
            self.assertIn(self.ring.active(key_id), results[key_id])

    def test_concurrent_batches_and_seals_lose_no_history(self) -> None:
        # Batch writers rotate a/b while independent sealers append plain
        # versions to a third key. The committed history must stay a complete
        # 1..max sequence for every key, and every produced version must open.
        self.ring.seal("a", "secret")
        self.ring.seal("b", "secret")
        self.ring.seal("c", "start")
        batch_count = 4
        seal_workers = 4
        seal_per_worker = 5
        barrier = threading.Barrier(batch_count + seal_workers)
        lock = threading.Lock()
        passwords: dict[tuple[str, int], str] = {("c", 1): "start"}
        errors: list[BaseException] = []

        def batch_worker(i: int) -> None:
            barrier.wait()
            try:
                numbers = self.ring.rotate_password_batch([
                    {"key_id": "a", "new_password": f"a-{i}", "version": 1,
                     "iterations": 200},
                    {"key_id": "b", "new_password": f"b-{i}", "version": 1,
                     "iterations": 200, "revoke_source": False},
                ])
                with lock:
                    passwords[("a", numbers[0])] = f"a-{i}"
                    passwords[("b", numbers[1])] = f"b-{i}"
            except BaseException as error:  # noqa: BLE001
                with lock:
                    errors.append(error)

        def seal_worker() -> None:
            barrier.wait()
            try:
                for j in range(seal_per_worker):
                    number = self.ring.seal("c", f"c{j}")
                    with lock:
                        passwords[("c", number)] = f"c{j % seal_per_worker}"
            except BaseException as error:  # noqa: BLE001
                with lock:
                    errors.append(error)

        workers = [threading.Thread(target=batch_worker, args=(i,))
                   for i in range(batch_count)]
        workers += [threading.Thread(target=seal_worker) for _ in range(seal_workers)]
        for thread in workers:
            thread.start()
        # No main-thread barrier wait: the eight worker parties release one
        # another themselves once every thread is ready.
        for thread in workers:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        expected_c = list(range(1, 2 + 4 * seal_per_worker))
        self.assertEqual(self.ring.versions("c"), expected_c)
        for key_id in ("a", "b"):
            numbers = self.ring.versions(key_id)
            self.assertEqual(numbers, list(range(1, 2 + batch_count)))
            for number in numbers[1:]:
                self.assertEqual(
                    self.ring.load(key_id, version=number,
                                   password=passwords[(key_id, number)]),
                    b"secret")
        for number in expected_c:
            self.assertEqual(
                self.ring.load("c", version=number),
                passwords[("c", number)].encode("utf-8"))

    def test_readers_never_observe_a_half_applied_batch(self) -> None:
        # During a storm of multi-key batches, every shared-lock snapshot must
        # be internally consistent: active points at an existing version, the
        # plain v1 sources stay readable, and per-key histories stay compact
        # 1..max sequences. A torn commit would violate at least one of these.
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
                    # batch commit, which is a legitimate observation.
                    with core._locked(self.ring, exclusive=False):
                        document = self.ring._read()
                    for key_id in keys:
                        entry = document["keys"][key_id]
                        numbers = [item["version"] for item in entry["versions"]]
                        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))
                        self.assertIn(entry["active"], numbers)
                    # The pinned plain source survives every batch; v1 is never
                    # revoked or rewritten.
                        self.assertEqual(
                            self.ring.load(key_id, version=1), b"secret")
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        def writer(i: int) -> None:
            for _ in range(3):
                self.ring.rotate_password_batch([
                    {"key_id": key_id, "new_password": f"pw-{i}",
                     "version": 1, "iterations": 200}
                    for key_id in keys])

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


if __name__ == "__main__":
    unittest.main()
