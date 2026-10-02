"""Tests for ``KeyRing.set_active_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts, each requiring ``key_id``/``version`` and
  allowing only ``expected_active``; the target must be a non-bool positive
  integer (no "stay active" default), ``expected_active`` must be ``None`` or
  a non-bool positive integer, and a key_id may appear only once. Bad
  structure, non-dict items, missing/unknown fields, illegal values and
  duplicate key_ids are ``ValueError`` raised for the whole batch before
  storage is touched; the caller's objects are never mutated;
* every item is judged against one committed snapshot: the whole store is
  validated first (even unreferenced damage raises ``CorruptRecordError``),
  then items are checked in request order -- key existence (KeyError),
  expected_active vs the active *number* only (ActiveVersionConflictError,
  the expected version need not exist), target existence (KeyError), target
  not revoked (RevokedVersionError); the first failure wins and keyring.json
  keeps its exact prior bytes;
* an already-active target still runs every check; a batch that moves
  nothing never rewrites keyring.json; on success only active pointers
  change, together in one atomic replace -- no new versions, no material or
  revocation changes, other keys untouched;
* two batches expecting the same old active of a shared key and moving it
  elsewhere cannot both succeed; concurrent callers see only the pre-batch
  or post-batch state;
* missing store -> FileNotFoundError, five-second lock wait -> TimeoutError,
  other storage errors stay OSError;
* single-key ``set_active`` may still point at a revoked version, there is
  no CLI surface, and the report schema is unchanged.

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


class SetActiveBatchTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _history(self, key_id: str) -> list[int]:
        return [item["version"] for item in self._document()["keys"][key_id]["versions"]]

    def _revoked(self, key_id: str) -> dict[int, bool]:
        return {item["version"]: item["revoked"]
                for item in self._document()["keys"][key_id]["versions"]}

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

    def _make_legacy_derived(self, key_id: str, version: int) -> None:
        document = self._document()
        record = next(item for item in document["keys"][key_id]["versions"]
                      if item["version"] == version)
        document["keys"][key_id]["versions"][0 if version == 1 else -1] = {
            "version": version, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": bool(record.get("revoked"))}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")

    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)

    def _wait_for(self, marker: Path, label: str) -> None:
        deadline = time.monotonic() + 5
        while not marker.is_file() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.is_file(), f"{label} never happened"


class HappyPathTests(SetActiveBatchTestBase):
    def test_switches_several_keys_together_and_returns_none(self) -> None:
        for key_id in (KEY, OTHER, "k3"):
            self.ring.seal(key_id, "one", PASSWORD, iterations=200)
            self.ring.seal(key_id, "two", PASSWORD, iterations=200)
        result = self.ring.set_active_batch([
            {"key_id": KEY, "version": 1},
            {"key_id": OTHER, "version": 1, "expected_active": 2},
            {"key_id": "k3", "version": 2},
        ])
        self.assertIsNone(result)
        self.assertEqual(self.ring.active(KEY), 1)
        self.assertEqual(self.ring.active(OTHER), 1)
        self.assertEqual(self.ring.active("k3"), 2)
        # The repointed defaults open the materials the pointers name.
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"one")
        self.assertEqual(self.ring.load(OTHER, password=PASSWORD), "one".encode())
        self.assertEqual(self.ring.load("k3", password=PASSWORD), b"two")

    def test_single_item_matches_single_key_set_active(self) -> None:
        first = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.set_active(KEY, first)
        self.assertEqual(self.ring.active(KEY), 1)
        self.assertIsNone(self.ring.set_active_batch([{"key_id": KEY, "version": 2}]))
        self.assertEqual(self.ring.active(KEY), 2)

    def test_only_active_pointers_change_no_versions_or_material(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.ring.seal(OTHER, "a", PASSWORD, iterations=200)
        self.ring.seal(OTHER, "b", PASSWORD, iterations=200)
        before = self._document()
        self.ring.set_active_batch([{"key_id": KEY, "version": 1}])
        after = self._document()
        # Exactly one active pointer differs; every record byte stays put.
        self.assertEqual(after["keys"][KEY]["active"], 1)
        self.assertEqual(after["keys"][OTHER]["active"], 2)
        self.assertEqual(after["keys"][KEY]["versions"], before["keys"][KEY]["versions"])
        self.assertEqual(after["keys"][OTHER], before["keys"][OTHER])
        self.assertEqual(self._history(KEY), [1, 2])
        self.assertEqual(self._revoked(KEY), {1: False, 2: False})
        # Historical versions keep opening with their own passphrase state.
        self.assertEqual(self.ring.load(KEY, version=2, password=PASSWORD), b"two")

    def test_targets_legacy_and_v1_records_without_touching_them(self) -> None:
        v1_key = "sealed-v1"
        legacy_key = "legacy"
        v = self.ring.seal(v1_key, "secret", PASSWORD, iterations=1_000)
        self.ring.seal(v1_key, "newer", PASSWORD, iterations=1_000)
        self._replace_with_v1(v1_key, v, b"secret")
        lv = self.ring.seal(legacy_key, "gone", PASSWORD, iterations=1_000)
        self.ring.seal(legacy_key, "current", PASSWORD, iterations=1_000)
        self._make_legacy_derived(legacy_key, lv)
        before = self.ring.path.read_bytes()
        # A structurally valid v1 or legacy derived-only version is a legal
        # pointer target; legacy material still comes out by load's old rule.
        self.assertIsNone(self.ring.set_active_batch([
            {"key_id": v1_key, "version": 1},
            {"key_id": legacy_key, "version": 1},
        ]))
        self.assertEqual(self.ring.active(v1_key), 1)
        self.assertEqual(self.ring.load(v1_key, password=PASSWORD), b"secret")
        with self.assertRaises(core.UnrecoverableRecordError):
            self.ring.load(legacy_key, password=PASSWORD)
        self.assertEqual(self._document()["keys"][v1_key]["versions"][0]["scheme"],
                         core.SEALED_SCHEME)
        self.assertEqual(self._document()["keys"][legacy_key]["versions"][0]["scheme"],
                         core.LEGACY_DERIVE_SCHEME)
        # The switch rewrote nothing but the two pointers.
        self.assertNotEqual(self.ring.path.read_bytes(), before)

    def test_unicode_key_names_are_not_normalised(self) -> None:
        self.ring.seal("k", "lower", PASSWORD, iterations=200)
        self.ring.seal("k", "lower-2", PASSWORD, iterations=200)
        self.ring.seal("K", "upper", PASSWORD, iterations=200)
        self.ring.seal("K", "upper-2", PASSWORD, iterations=200)
        self.ring.seal("键-😀", "中文", PASSWORD, iterations=200)
        self.ring.seal("键-😀", "中文-二", PASSWORD, iterations=200)
        self.ring.set_active_batch([
            {"key_id": "k", "version": 1},
            {"key_id": "K", "version": 1},
            {"key_id": "键-😀", "version": 1},
        ])
        self.assertEqual(self.ring.load("k", password=PASSWORD), b"lower")
        self.assertEqual(self.ring.load("K", password=PASSWORD), b"upper")
        self.assertEqual(self.ring.load("键-😀", password=PASSWORD), "中文".encode())


class NoRewriteTests(SetActiveBatchTestBase):
    def test_batch_with_no_pointer_to_move_does_not_rewrite_file(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(OTHER, "x")
        self.ring.seal(OTHER, "y")
        # Settle mtimes, then point both keys at their already-active version.
        time.sleep(0.02)
        before_bytes = self.ring.path.read_bytes()
        before_mtime = self.ring.path.stat().st_mtime_ns
        result = self.ring.set_active_batch([
            {"key_id": KEY, "version": 2, "expected_active": 2},
            {"key_id": OTHER, "version": 2},
        ])
        self.assertIsNone(result)
        self.assertEqual(self.ring.path.read_bytes(), before_bytes)
        self.assertEqual(self.ring.path.stat().st_mtime_ns, before_mtime)

    def test_one_real_move_among_noops_still_commits(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(OTHER, "x")
        self.ring.seal(OTHER, "y")
        before = self.ring.path.read_bytes()
        self.assertIsNone(self.ring.set_active_batch([
            {"key_id": KEY, "version": 2},   # already active
            {"key_id": OTHER, "version": 1},  # moves
        ]))
        self.assertNotEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertEqual(self.ring.active(OTHER), 1)

    def test_unknown_key_failure_does_not_rewrite(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([{"key_id": "missing", "version": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 2)


class InputValidationTests(SetActiveBatchTestBase):
    def _batch(self, requests):
        return self.ring.set_active_batch(requests)

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
            self._batch([{"key_id": KEY}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "version": None}])

    def test_unknown_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "version": 1, "bogus": 2}])
        # An unknown field is rejected even when a required one is missing.
        with self.assertRaises(ValueError):
            self._batch([{"bogus": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "version": 1, "password": "p"}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "version": 1, "new_password": "p"}])

    def test_field_value_rules(self) -> None:
        cases = (
            {"key_id": "", "version": 1},
            {"key_id": 1, "version": 1},
            {"key_id": None, "version": 1},
            {"key_id": b"k", "version": 1},
            {"key_id": KEY, "version": 0},
            {"key_id": KEY, "version": -1},
            {"key_id": KEY, "version": "1"},
            {"key_id": KEY, "version": True},
            {"key_id": KEY, "version": False},
            {"key_id": KEY, "version": 1.5},
            {"key_id": KEY, "version": b"1"},
            {"key_id": KEY, "version": 1, "expected_active": 0},
            {"key_id": KEY, "version": 1, "expected_active": -2},
            {"key_id": KEY, "version": 1, "expected_active": "1"},
            {"key_id": KEY, "version": 1, "expected_active": True},
            {"key_id": KEY, "version": 1, "expected_active": 1.5},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    self._batch([request])

    def test_expected_active_none_is_allowed(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.assertIsNone(
            self.ring.set_active_batch([{"key_id": KEY, "version": 1,
                                         "expected_active": None}]))
        self.assertEqual(self.ring.active(KEY), 1)

    def test_duplicate_key_id_rejected(self) -> None:
        self.ring.seal(KEY, "x")
        self.ring.seal(KEY, "y")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._batch([
                {"key_id": KEY, "version": 1},
                {"key_id": KEY, "version": 2},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 2)

    def test_validation_precedes_storage_and_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        before = self.ring.path.read_bytes()
        bad_batches = (
            [],
            [{"key_id": KEY}],
            [{"version": 1}],
            [{"key_id": KEY, "version": 1}, "not-a-dict"],
            [{"key_id": KEY, "version": 1, "bogus": None}],
            [{"key_id": KEY, "version": True}],
            [{"key_id": KEY, "version": 1, "expected_active": False}],
            "not-a-list",
            [{"key_id": KEY, "version": 1}, {"key_id": KEY, "version": 2}],
        )
        for requests in bad_batches:
            with self.subTest(requests=requests):
                with self.assertRaises(ValueError):
                    self._batch(requests)
                self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_input_on_missing_ring_is_value_error(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.set_active_batch([])
        with self.assertRaises(ValueError):
            ring.set_active_batch([{"key_id": 1, "version": 1}])
        with self.assertRaises(ValueError):
            ring.set_active_batch([{"key_id": KEY}])
        with self.assertRaises(ValueError):
            ring.set_active_batch([{"key_id": KEY, "version": 1,
                                    "expected_active": True}])

    def test_caller_input_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        requests = [{"key_id": KEY, "version": 1, "expected_active": 2}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.set_active_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)
        self.assertEqual(requests, [{"key_id": KEY, "version": 1,
                                      "expected_active": 2}])


class CheckOrderTests(SetActiveBatchTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        self.ring.seal(KEY, "two", PASSWORD, iterations=1_000)
        self.ring.seal(KEY, "three", PASSWORD, iterations=1_000)
        self.ring.seal(OTHER, "a", PASSWORD, iterations=1_000)
        self.ring.seal(OTHER, "b", PASSWORD, iterations=1_000)

    def test_unknown_key_is_keyerror_even_with_precondition(self) -> None:
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([
                {"key_id": "missing", "version": 1, "expected_active": 1}])

    def test_conflict_message_uses_existing_rule(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.set_active_batch([
                {"key_id": KEY, "version": 1, "expected_active": 9}])
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn("9", message)  # expected
        self.assertIn("3", message)  # actual
        self.assertIsInstance(caught.exception, core.SealError)

    def test_conflict_even_when_expected_version_never_existed(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch([
                {"key_id": KEY, "version": 1, "expected_active": 99}])

    def test_conflict_even_when_target_is_already_active(self) -> None:
        # Active is 3 and the target is 3: every check still runs, so the
        # wrong precondition is a conflict rather than a silent no-op.
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch([
                {"key_id": KEY, "version": 3, "expected_active": 2}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 3)

    def test_conflict_precedes_unknown_target(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch([
                {"key_id": KEY, "version": 99, "expected_active": 7}])

    def test_conflict_precedes_revoked_target(self) -> None:
        self.ring.revoke(KEY, 1)
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch([
                {"key_id": KEY, "version": 1, "expected_active": 7}])

    def test_unknown_target_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([{"key_id": KEY, "version": 42}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 3)

    def test_revoked_target_is_revoked_error_with_wording(self) -> None:
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销") as caught:
            self.ring.set_active_batch([{"key_id": KEY, "version": 1}])
        message = str(caught.exception)
        self.assertIn(repr(KEY), message)
        self.assertIn("1", message)
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 3)

    def test_revoked_target_fails_even_when_it_is_currently_active(self) -> None:
        # Point at v1, revoke v1 out from under the pointer (as allowed), then
        # ask to "switch" to the already-active revoked version.
        self.ring.set_active(KEY, 1)
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.RevokedVersionError):
            self.ring.set_active_batch([{"key_id": KEY, "version": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 1)
        # A matching precondition does not rescue the revoked target either.
        with self.assertRaises(core.RevokedVersionError):
            self.ring.set_active_batch([
                {"key_id": KEY, "version": 1, "expected_active": 1}])

    def test_first_failing_item_in_request_order_wins(self) -> None:
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        # Item 0 conflicts; item 1 names an unknown key. Item 0 wins.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch([
                {"key_id": KEY, "version": 2, "expected_active": 9},
                {"key_id": "no-such-key", "version": 1},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Reversed order: the unknown key is encountered first.
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([
                {"key_id": "no-such-key", "version": 1},
                {"key_id": KEY, "version": 2, "expected_active": 9},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Item 0 fine, item 1 revoked: revocation wins and item 0 is not moved.
        with self.assertRaises(core.RevokedVersionError):
            self.ring.set_active_batch([
                {"key_id": OTHER, "version": 1},
                {"key_id": KEY, "version": 1},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(OTHER), 2)
        self.assertEqual(self.ring.active(KEY), 3)

    def test_failure_moves_no_pointer_even_for_earlier_good_items(self) -> None:
        before = self._document()
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([
                {"key_id": OTHER, "version": 1},
                {"key_id": KEY, "version": 42},
            ])
        self.assertEqual(self._document(), before)
        self.assertEqual(self.ring.active(OTHER), 2)
        self.assertEqual(self.ring.active(KEY), 3)
        self.assertEqual(self._revoked(KEY), {1: False, 2: False, 3: False})


class WholeStoreValidationTests(SetActiveBatchTestBase):
    def test_corrupt_unreferenced_record_rejects_whole_batch(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(OTHER, "x")
        document = self._document()
        # Damage a key the batch never names.
        document["keys"][KEY]["versions"][0].pop("revoked")
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.set_active_batch([{"key_id": OTHER, "version": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_unrequested_version_of_requested_key_rejects(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal("bystander", "x")
        document = self._document()
        document["keys"]["bystander"]["active"] = 99
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.set_active_batch([{"key_id": KEY, "version": 1}])

    def test_corrupt_keyring_file_is_corrupt_and_unchanged(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.set_active_batch([{"key_id": KEY, "version": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_ring_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaisesRegex(FileNotFoundError, "no key ring"):
            ring.set_active_batch([{"key_id": KEY, "version": 1}])

    def test_lock_timeout_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        ready = self.root / "holder.ready"
        holder = subprocess.Popen(
            [sys.executable, str(LOCK_HOLDER), str(self.root), "2", str(ready)],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)})
        original_timeout = core.LOCK_TIMEOUT_SECONDS
        core.LOCK_TIMEOUT_SECONDS = 0.3
        try:
            self._wait_for(ready, "lock holder")
            before = self.ring.path.read_bytes()
            with self.assertRaisesRegex(TimeoutError, "获取密钥环写锁超时"):
                self.ring.set_active_batch([{"key_id": KEY, "version": 1}])
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)
        self.assertEqual(self.ring.active(KEY), 2)


class ConcurrencyTests(SetActiveBatchTestBase):
    def test_two_batches_one_shared_precondition_at_most_one_wins(self) -> None:
        # Shared KEY starts at active 1; every batch expects exactly that and
        # moves it to 2. Each batch also moves a thread-private key, so a
        # losing batch fails wholesale, never half-applied.
        self.ring.seal(KEY, "shared-one")
        self.ring.seal(KEY, "shared-two")
        # Two real versions, but the batch starts from active 1 and moves to 2.
        self.ring.set_active(KEY, 1)
        count = 6
        private = [f"p{i}" for i in range(count)]
        for name in private:
            self.ring.seal(name, "p-one")
            self.ring.seal(name, "p-two")
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        successes: list[int] = []
        conflicts: list[BaseException] = []
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                result = self.ring.set_active_batch([
                    {"key_id": KEY, "version": 2, "expected_active": 1},
                    {"key_id": private[i], "version": 1},
                ])
                with lock:
                    successes.append(i)
                    self.assertIsNone(result)
            except core.ActiveVersionConflictError as error:
                with lock:
                    conflicts.append(error)
            except BaseException as error:  # noqa: BLE001 - surfaced below
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(conflicts), count - 1)
        winner = successes[0]
        self.assertEqual(self.ring.active(KEY), 2)
        # The winner's private key moved; every loser's key never did.
        for i, name in enumerate(private):
            self.assertEqual(self.ring.active(name), 1 if i == winner else 2)
        # No history grew and no revocation appeared.
        self.assertEqual(self._history(KEY), [1, 2])
        self.assertEqual(self._revoked(KEY), {1: False, 2: False})

    def test_pointer_states_are_only_seen_whole_under_a_storm(self) -> None:
        keys = ["a", "b", "c", "d"]
        for key_id in keys:
            self.ring.seal(key_id, "v1")
            self.ring.seal(key_id, "v2")
        stop = threading.Event()
        errors: list[BaseException] = []

        def reader() -> None:
            try:
                while not stop.is_set():
                    # One shared-lock snapshot: a committed document is always
                    # internally whole -- every active pointer names a real
                    # version. Comparing two public calls would mix snapshots.
                    with core._locked(self.ring, exclusive=False):
                        document = self.ring._read()
                    for key_id in keys:
                        entry = document["keys"][key_id]
                        numbers = [item["version"] for item in entry["versions"]]
                        self.assertEqual(numbers, [1, 2])
                        self.assertIn(entry["active"], numbers)
                    # Pinned historical versions are never revoked or added to.
                    self.assertEqual(
                        self.ring.load_batch(
                            [{"key_id": key_id, "version": 1} for key_id in keys]),
                        [b"v1"] * len(keys))
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        def writer(i: int) -> None:
            try:
                for round_index in range(8):
                    target = 1 if (round_index + i) % 2 else 2
                    self.ring.set_active_batch(
                        [{"key_id": key_id, "version": target} for key_id in keys])
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
        for key_id in keys:
            self.assertEqual(self._history(key_id), [1, 2])


class CompatibilityTests(SetActiveBatchTestBase):
    def test_single_key_set_active_still_points_at_revoked_version(self) -> None:
        v1 = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.revoke(KEY, v1)
        # The single-key API keeps its old permissive behaviour.
        self.assertIsNone(self.ring.set_active(KEY, v1))
        self.assertEqual(self.ring.active(KEY), 1)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY)

    def test_cli_set_active_still_accepts_revoked_version(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        result = self._run_cli("revoke", KEY, "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self._run_cli("set-active", KEY, "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok\n")
        self.assertEqual(self._run_cli("active", KEY).stdout, "1\n")

    def test_no_batch_cli_subcommand(self) -> None:
        result = self._run_cli("set-active-batch", KEY, "1")
        self.assertNotEqual(result.returncode, 0)

    def test_report_shape_unchanged(self) -> None:
        result = self._run_cli("report")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(set(payload),
                         {"domain", "version", "sourceCategories", "tags",
                          "components", "readiness"})
        self.assertEqual(payload["components"], ["keyring", "derive"])
        self.assertEqual(payload["readiness"],
                         {"seal": True, "rotate": True, "revoke": True,
                          "constantTime": False})


if __name__ == "__main__":
    unittest.main()
