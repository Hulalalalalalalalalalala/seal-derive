"""Tests for ``KeyRing.revoke_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts, each requiring ``key_id``/``versions`` and
  allowing only ``replacement_active``/``expected_active``; ``versions`` is a
  non-empty list of distinct non-bool positive integers, both optional
  values are ``None``/omitted or a non-bool positive integer, and a key_id
  may appear only once. Bad structure, non-dict items, missing/unknown
  fields, illegal values, duplicate request versions or duplicate key_ids
  are ``ValueError`` raised for the whole batch before storage is touched;
  the caller's objects are never mutated;
* every item is judged against one committed snapshot: the whole store is
  validated first (even unreferenced damage raises ``CorruptRecordError``),
  then items are checked in request order -- key existence (KeyError),
  expected_active vs the active *number* only (ActiveVersionConflictError,
  the expected version need not exist), each requested version's existence
  in list order (KeyError; revoking an already-revoked version succeeds),
  and finally the replacement's existence (KeyError) and non-revocation
  (RevokedVersionError when it is already revoked or named in this item's
  versions); the first failure wins and keyring.json keeps its exact prior
  bytes;
* without a replacement the pointer is kept even when the active version is
  revoked; with one the pointer always moves to it; already-revoked targets
  are idempotent and a batch already fully at its target state still runs
  every check but never rewrites keyring.json; on success only revocation
  marks and active pointers change, together in one atomic replace -- no
  versions added/removed/decrypted, material and derived parameters intact,
  other keys untouched, all four record formats revocable;
* two batches expecting the same old active of a shared key cannot both
  switch it; concurrent callers see only the pre-batch or post-batch state;
* missing store -> FileNotFoundError, five-second lock wait -> TimeoutError,
  other storage errors stay OSError;
* single-key ``revoke`` is unchanged, there is no CLI surface, and the
  report schema is unchanged.

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


class RevokeBatchTestBase(unittest.TestCase):
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

    def _record(self, key_id: str, version: int) -> dict:
        return next(item for item in self._document()["keys"][key_id]["versions"]
                    if item["version"] == version)

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


class HappyPathTests(RevokeBatchTestBase):
    def test_revokes_several_keys_and_switches_pointers_returns_none(self) -> None:
        for key_id in (KEY, OTHER, "k3"):
            self.ring.seal(key_id, "one", PASSWORD, iterations=200)
            self.ring.seal(key_id, "two", PASSWORD, iterations=200)
            self.ring.seal(key_id, "three", PASSWORD, iterations=200)
        result = self.ring.revoke_batch([
            {"key_id": KEY, "versions": [2, 3], "replacement_active": 1},
            {"key_id": OTHER, "versions": [3], "replacement_active": 2,
             "expected_active": 3},
            {"key_id": "k3", "versions": [1, 2], "replacement_active": 3},
        ])
        self.assertIsNone(result)
        self.assertEqual(self.ring.active(KEY), 1)
        self.assertEqual(self.ring.active(OTHER), 2)
        self.assertEqual(self.ring.active("k3"), 3)
        self.assertEqual(self._revoked(KEY), {1: False, 2: True, 3: True})
        self.assertEqual(self._revoked(OTHER), {1: False, 2: False, 3: True})
        self.assertEqual(self._revoked("k3"), {1: True, 2: True, 3: False})
        # The new defaults open the materials the surviving pointers name.
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"one")
        self.assertEqual(self.ring.load(OTHER, password=PASSWORD), b"two")
        self.assertEqual(self.ring.load("k3", password=PASSWORD), b"three")

    def test_single_item_matches_single_key_revoke_without_replacement(self) -> None:
        first = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.assertIsNone(self.ring.revoke_batch([{"key_id": KEY, "versions": [first]}]))
        self.assertTrue(self.ring.is_revoked(KEY, first))
        # Single-key revoke keeps the same pointer semantics.
        self.assertEqual(self.ring.active(KEY), 2)
        self.ring.revoke(KEY, 2)
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertTrue(self.ring.is_revoked(KEY, 2))

    def test_only_revocation_marks_and_pointer_change(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.ring.seal(OTHER, "a", PASSWORD, iterations=200)
        self.ring.seal(OTHER, "b", PASSWORD, iterations=200)
        before = self._document()
        self.ring.revoke_batch([
            {"key_id": KEY, "versions": [2], "replacement_active": 1}])
        after = self._document()
        self.assertEqual(after["keys"][KEY]["active"], 1)
        self.assertEqual(after["keys"][OTHER], before["keys"][OTHER])
        self.assertEqual([item["version"] for item in after["keys"][KEY]["versions"]],
                         [1, 2])
        for number in (1, 2):
            old = next(item for item in before["keys"][KEY]["versions"]
                       if item["version"] == number)
            new = next(item for item in after["keys"][KEY]["versions"]
                       if item["version"] == number)
            self.assertEqual(new["revoked"], number == 2)
            for field, value in old.items():
                if field == "revoked":
                    continue
                self.assertEqual(new[field], value)
        # Survivors still open; revoked history does not.
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"one")
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY, version=2, password=PASSWORD)

    def test_all_four_record_formats_are_revocable_without_rewriting_material(self) -> None:
        v1_key, legacy_key, plain_key, v2_key = "sealed-v1", "legacy", "plain", "v2"
        v = self.ring.seal(v1_key, "secret", PASSWORD, iterations=1_000)
        self.ring.seal(v1_key, "newer", PASSWORD, iterations=1_000)
        self._replace_with_v1(v1_key, v, b"secret")
        lv = self.ring.seal(legacy_key, "gone", PASSWORD, iterations=1_000)
        self.ring.seal(legacy_key, "current", PASSWORD, iterations=1_000)
        self._make_legacy_derived(legacy_key, lv)
        self.ring.seal(plain_key, "raw")
        self.ring.seal(plain_key, "raw2")
        self.ring.seal(v2_key, "sealed", PASSWORD, iterations=200)
        self.ring.seal(v2_key, "sealed2", PASSWORD, iterations=200)
        schemes = {
            v1_key: (core.SEALED_SCHEME, 1),
            legacy_key: (core.LEGACY_DERIVE_SCHEME, 1),
            plain_key: (core.PLAIN_SCHEME, 1),
            v2_key: (core.SEALED_V2_SCHEME, 1),
        }
        result = self.ring.revoke_batch(
            [{"key_id": key_id, "versions": [1], "replacement_active": 2}
             for key_id in schemes])
        self.assertIsNone(result)
        for key_id, (scheme, _) in schemes.items():
            self.assertEqual(self._record(key_id, 1)["scheme"], scheme)
            self.assertTrue(self._record(key_id, 1)["revoked"])
            self.assertEqual(self.ring.active(key_id), 2)
        # v2 material and its key_id binding are untouched.
        self.assertEqual(self.ring.load(v2_key, password=PASSWORD), b"sealed2")
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(v1_key, version=1, password=PASSWORD)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(legacy_key, version=1, password=PASSWORD)

    def test_unicode_key_names_are_not_normalised(self) -> None:
        for key_id in ("k", "K", "键-😀"):
            self.ring.seal(key_id, "one", PASSWORD, iterations=200)
            self.ring.seal(key_id, "two", PASSWORD, iterations=200)
        self.ring.revoke_batch([
            {"key_id": "k", "versions": [2], "replacement_active": 1},
            {"key_id": "K", "versions": [1], "replacement_active": 2},
            {"key_id": "键-😀", "versions": [2]},
        ])
        self.assertEqual(self.ring.load("k", password=PASSWORD), b"one")
        self.assertEqual(self.ring.load("K", version=2, password=PASSWORD), b"two")
        self.assertEqual(self.ring.active("键-😀"), 2)
        self.assertTrue(self.ring.is_revoked("键-😀", 2))


class PointerSemanticsTests(RevokeBatchTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(KEY, "three")

    def test_without_replacement_revoking_active_keeps_pointer_at_it(self) -> None:
        # Active is 3; revoke it with no replacement: the pointer deliberately
        # stays on the now-revoked version, exactly like single-key revoke.
        self.assertIsNone(self.ring.revoke_batch([{"key_id": KEY, "versions": [3]}]))
        self.assertEqual(self.ring.active(KEY), 3)
        self.assertTrue(self.ring.is_revoked(KEY, 3))
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY)

    def test_replacement_always_switches_even_when_active_is_not_revoked(self) -> None:
        self.assertIsNone(self.ring.revoke_batch(
            [{"key_id": KEY, "versions": [1], "replacement_active": 2}]))
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertTrue(self.ring.is_revoked(KEY, 1))
        self.assertFalse(self.ring.is_revoked(KEY, 2))

    def test_replacement_switches_when_active_is_also_revoked(self) -> None:
        self.assertIsNone(self.ring.revoke_batch(
            [{"key_id": KEY, "versions": [2, 3], "replacement_active": 1}]))
        self.assertEqual(self.ring.active(KEY), 1)
        self.assertEqual(self._revoked(KEY), {1: False, 2: True, 3: True})

    def test_replacement_equal_to_active_keeps_pointer_but_revokes_targets(self) -> None:
        before = self.ring.path.read_bytes()
        result = self.ring.revoke_batch(
            [{"key_id": KEY, "versions": [1, 2], "replacement_active": 3,
              "expected_active": 3}])
        self.assertIsNone(result)
        self.assertNotEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 3)
        self.assertEqual(self._revoked(KEY), {1: True, 2: True, 3: False})

    def test_revoking_already_revoked_versions_succeeds(self) -> None:
        self.ring.revoke(KEY, 1)
        self.ring.revoke(KEY, 2)
        self.assertIsNone(self.ring.revoke_batch(
            [{"key_id": KEY, "versions": [1, 2], "replacement_active": 3}]))
        self.assertEqual(self._revoked(KEY), {1: True, 2: True, 3: False})
        self.assertEqual(self.ring.active(KEY), 3)


class NoRewriteTests(RevokeBatchTestBase):
    def test_batch_already_at_target_state_does_not_rewrite_file(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(KEY, "three")
        self.ring.seal(OTHER, "x")
        self.ring.seal(OTHER, "y")
        self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1, 2], "replacement_active": 3},
            {"key_id": OTHER, "versions": [1], "replacement_active": 2},
        ])
        time.sleep(0.02)
        before_bytes = self.ring.path.read_bytes()
        before_mtime = self.ring.path.stat().st_mtime_ns
        # Same target state: every named version already revoked, every
        # replacement already the active pointer. Checks still all run.
        result = self.ring.revoke_batch([
            {"key_id": KEY, "versions": [2, 1], "replacement_active": 3,
             "expected_active": 3},
            {"key_id": OTHER, "versions": [1], "replacement_active": 2},
        ])
        self.assertIsNone(result)
        self.assertEqual(self.ring.path.read_bytes(), before_bytes)
        self.assertEqual(self.ring.path.stat().st_mtime_ns, before_mtime)

    def test_one_real_change_among_noops_still_commits(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(KEY, "three")
        self.ring.seal(OTHER, "x")
        self.ring.seal(OTHER, "y")
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        self.assertIsNone(self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1], "replacement_active": 3},  # all no-op
            {"key_id": OTHER, "versions": [1], "replacement_active": 2},  # changes
        ]))
        self.assertNotEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 3)
        self.assertEqual(self.ring.active(OTHER), 2)
        self.assertTrue(self.ring.is_revoked(OTHER, 1))

    def test_unknown_key_failure_does_not_rewrite(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.revoke_batch([{"key_id": "missing", "versions": [1]}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 2)


class InputValidationTests(RevokeBatchTestBase):
    def _batch(self, requests):
        return self.ring.revoke_batch(requests)

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
            self._batch([{"versions": [1]}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY}])

    def test_unknown_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "versions": [1], "bogus": 2}])
        with self.assertRaises(ValueError):
            self._batch([{"bogus": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "versions": [1], "password": "p"}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "versions": [1], "version": 1}])

    def test_key_id_rules(self) -> None:
        for bad in ("", 1, None, b"k"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch([{"key_id": bad, "versions": [1]}])

    def test_versions_rules(self) -> None:
        for bad in (None, [], [[]], "", {}, (1,), [True], [False], [0], [-1],
                    ["1"], [1.5], [b"1"], [1, None], [1, 1], [2, 1, 2]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch([{"key_id": KEY, "versions": bad}])

    def test_optional_value_rules(self) -> None:
        cases = (
            {"key_id": KEY, "versions": [1], "replacement_active": 0},
            {"key_id": KEY, "versions": [1], "replacement_active": -2},
            {"key_id": KEY, "versions": [1], "replacement_active": "1"},
            {"key_id": KEY, "versions": [1], "replacement_active": True},
            {"key_id": KEY, "versions": [1], "replacement_active": 1.5},
            {"key_id": KEY, "versions": [1], "expected_active": 0},
            {"key_id": KEY, "versions": [1], "expected_active": False},
            {"key_id": KEY, "versions": [1], "expected_active": "2"},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    self._batch([request])

    def test_none_optionals_are_allowed(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.assertIsNone(self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1], "replacement_active": None,
             "expected_active": None}]))
        self.assertTrue(self.ring.is_revoked(KEY, 1))
        self.assertEqual(self.ring.active(KEY), 2)

    def test_optional_value_error_names_the_offending_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "replacement_active"):
            self._batch([{"key_id": KEY, "versions": [1],
                          "replacement_active": True}])
        with self.assertRaisesRegex(ValueError, "expected_active"):
            self._batch([{"key_id": KEY, "versions": [1],
                          "expected_active": True}])

    def test_duplicate_key_id_rejected(self) -> None:
        self.ring.seal(KEY, "x")
        self.ring.seal(KEY, "y")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._batch([
                {"key_id": KEY, "versions": [1]},
                {"key_id": KEY, "versions": [2]},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertFalse(self.ring.is_revoked(KEY, 1))

    def test_validation_precedes_storage_and_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        before = self.ring.path.read_bytes()
        bad_batches = (
            [],
            [{"key_id": KEY}],
            [{"versions": [1]}],
            [{"key_id": KEY, "versions": [1]}, "not-a-dict"],
            [{"key_id": KEY, "versions": [1], "bogus": None}],
            [{"key_id": KEY, "versions": [True]}],
            [{"key_id": KEY, "versions": [1, 1]}],
            [{"key_id": KEY, "versions": [1], "replacement_active": False}],
            "not-a-list",
            [{"key_id": KEY, "versions": [1]}, {"key_id": KEY, "versions": [2]}],
        )
        for requests in bad_batches:
            with self.subTest(requests=requests):
                with self.assertRaises(ValueError):
                    self._batch(requests)
                self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_input_on_missing_ring_is_value_error(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.revoke_batch([])
        with self.assertRaises(ValueError):
            ring.revoke_batch([{"key_id": 1, "versions": [1]}])
        with self.assertRaises(ValueError):
            ring.revoke_batch([{"key_id": KEY}])
        with self.assertRaises(ValueError):
            ring.revoke_batch([{"key_id": KEY, "versions": [1, True]}])

    def test_caller_input_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        requests = [{"key_id": KEY, "versions": [2],
                     "replacement_active": 1, "expected_active": 2}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.revoke_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)
        self.assertEqual(requests, [{"key_id": KEY, "versions": [2],
                                     "replacement_active": 1,
                                     "expected_active": 2}])


class CheckOrderTests(RevokeBatchTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        self.ring.seal(KEY, "two", PASSWORD, iterations=1_000)
        self.ring.seal(KEY, "three", PASSWORD, iterations=1_000)
        self.ring.seal(OTHER, "a", PASSWORD, iterations=1_000)
        self.ring.seal(OTHER, "b", PASSWORD, iterations=1_000)

    def test_unknown_key_is_keyerror_even_with_precondition(self) -> None:
        with self.assertRaises(KeyError):
            self.ring.revoke_batch([
                {"key_id": "missing", "versions": [1],
                 "replacement_active": 1, "expected_active": 1}])

    def test_conflict_message_uses_existing_rule(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [1], "expected_active": 9}])
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn("9", message)
        self.assertIn("3", message)
        self.assertIsInstance(caught.exception, core.SealError)

    def test_conflict_even_when_expected_version_never_existed(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [1], "expected_active": 99}])

    def test_conflict_precedes_unknown_target_and_replacement(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [42], "replacement_active": 7,
                 "expected_active": 7}])
        self.ring.revoke(KEY, 1)
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [2], "replacement_active": 1,
                 "expected_active": 7}])

    def test_requested_versions_are_checked_in_list_order(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(KeyError, "42"):
            self.ring.revoke_batch([{"key_id": KEY, "versions": [1, 42]}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        with self.assertRaisesRegex(KeyError, "42"):
            self.ring.revoke_batch([{"key_id": KEY, "versions": [42, 1]}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Versions need not be sorted: [2, 1] both exist and both are revoked.
        self.assertIsNone(
            self.ring.revoke_batch([{"key_id": KEY, "versions": [2, 1]}]))
        self.assertEqual(self._revoked(KEY), {1: True, 2: True, 3: False})

    def test_unknown_target_version_precedes_replacement_check(self) -> None:
        # The replacement is revoked (would be RevokedVersionError), but the
        # unknown requested version is checked first.
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [42], "replacement_active": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_replacement_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [1], "replacement_active": 99}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertFalse(self.ring.is_revoked(KEY, 1))

    def test_revoked_replacement_is_revoked_error_with_wording(self) -> None:
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销") as caught:
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [2], "replacement_active": 1}])
        message = str(caught.exception)
        self.assertIn(repr(KEY), message)
        self.assertIn("1", message)
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertFalse(self.ring.is_revoked(KEY, 2))
        self.assertEqual(self.ring.active(KEY), 3)

    def test_replacement_in_own_revoke_list_is_revoked_error_even_if_active(self) -> None:
        # The replacement names a currently-unrevoked version (even the active
        # one), but it is also in this item's versions list: it cannot both be
        # revoked and become the pointer.
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.RevokedVersionError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [3, 2], "replacement_active": 3}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(KEY), {1: False, 2: False, 3: False})
        self.assertEqual(self.ring.active(KEY), 3)
        # Same verdict when the self-revoking replacement is already revoked.
        self.ring.revoke(KEY, 1)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [1, 2], "replacement_active": 1}])

    def test_already_revoked_target_is_not_an_error(self) -> None:
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        self.assertIsNone(self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1], "replacement_active": 2}]))
        self.assertNotEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 2)

    def test_first_failing_item_in_request_order_wins(self) -> None:
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        # Item 0 conflicts; item 1 names an unknown key. Item 0 wins.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [2], "expected_active": 9},
                {"key_id": "no-such-key", "versions": [1]},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Reversed order: the unknown key is encountered first.
        with self.assertRaises(KeyError):
            self.ring.revoke_batch([
                {"key_id": "no-such-key", "versions": [1]},
                {"key_id": KEY, "versions": [2], "expected_active": 9},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Item 0 fine, item 1 has a revoked replacement: that wins and item 0
        # is not revoked either.
        with self.assertRaises(core.RevokedVersionError):
            self.ring.revoke_batch([
                {"key_id": OTHER, "versions": [1]},
                {"key_id": KEY, "versions": [2], "replacement_active": 1},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(OTHER), {1: False, 2: False})
        self.assertEqual(self.ring.active(OTHER), 2)
        self.assertEqual(self.ring.active(KEY), 3)

    def test_failure_revokes_nothing_even_for_earlier_good_items(self) -> None:
        before = self._document()
        with self.assertRaises(KeyError):
            self.ring.revoke_batch([
                {"key_id": OTHER, "versions": [1]},
                {"key_id": KEY, "versions": [42]},
            ])
        self.assertEqual(self._document(), before)
        self.assertEqual(self._revoked(OTHER), {1: False, 2: False})
        self.assertEqual(self._revoked(KEY), {1: False, 2: False, 3: False})


class WholeStoreValidationTests(RevokeBatchTestBase):
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
            self.ring.revoke_batch([{"key_id": OTHER, "versions": [1]}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_unrequested_version_of_requested_key_rejects(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal("bystander", "x")
        document = self._document()
        document["keys"]["bystander"]["active"] = 99
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.revoke_batch([{"key_id": KEY, "versions": [1]}])

    def test_corrupt_keyring_file_is_corrupt_and_unchanged(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.revoke_batch([{"key_id": KEY, "versions": [1]}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_ring_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaisesRegex(FileNotFoundError, "no key ring"):
            ring.revoke_batch([{"key_id": KEY, "versions": [1]}])

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
                self.ring.revoke_batch([{"key_id": KEY, "versions": [1]}])
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)
        self.assertFalse(self.ring.is_revoked(KEY, 1))


class ConcurrencyTests(RevokeBatchTestBase):
    def test_two_batches_one_shared_precondition_at_most_one_wins(self) -> None:
        # Shared KEY starts at active 1; every batch expects exactly that,
        # revokes version 1 and moves the pointer to 2. Each batch also revokes
        # a thread-private key's version 1, so a losing batch fails wholesale
        # and never leaves a private key half-revoked.
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
                result = self.ring.revoke_batch([
                    {"key_id": KEY, "versions": [1], "replacement_active": 2,
                     "expected_active": 1},
                    {"key_id": private[i], "versions": [1],
                     "replacement_active": 2},
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
        self.assertTrue(self.ring.is_revoked(KEY, 1))
        for i, name in enumerate(private):
            # The private pointer target (2) is already active for every key,
            # so win or lose the pointer reads 2; only the winner's private
            # version 1 was revoked.
            self.assertEqual(self.ring.active(name), 2)
            self.assertEqual(self.ring.is_revoked(name, 1), i == winner)

    def test_revoke_states_are_only_seen_whole_under_a_storm(self) -> None:
        keys = ["a", "b", "c", "d"]
        for key_id in keys:
            self.ring.seal(key_id, "v1")
            self.ring.seal(key_id, "v2")
        batch = [{"key_id": key_id, "versions": [1], "replacement_active": 2}
                 for key_id in keys]
        stop = threading.Event()
        errors: list[BaseException] = []

        def reader() -> None:
            try:
                while not stop.is_set():
                    # One shared-lock snapshot: a committed document is always
                    # internally whole -- every active pointer names a real
                    # version, and the document is never mid-batch. Both the
                    # all-unrevoked and the all-revoked pointer states are
                    # complete outcomes. The open checks use the very same
                    # in-memory snapshot (no second lock/read), so a writer
                    # cannot commit between the pointer and the material views.
                    with core._locked(self.ring, exclusive=False):
                        document = self.ring._read()
                        revoked_seen: set[str] = set()
                        for key_id in keys:
                            entry = document["keys"][key_id]
                            numbers = [item["version"] for item in entry["versions"]]
                            self.assertEqual(numbers, [1, 2])
                            self.assertIn(entry["active"], numbers)
                            marks = {item["version"]: item["revoked"]
                                     for item in entry["versions"]}
                            if marks[1]:
                                # Post-commit state: v1 revoked everywhere the
                                # batch touched, pointer at 2, and v2 still
                                # opens.
                                revoked_seen.add(key_id)
                                self.assertEqual(entry["active"], 2)
                                self.assertFalse(marks[2])
                        if not revoked_seen:
                            # Pre-commit state: v1 of every key still opens.
                            for key_id in keys:
                                record = self.ring._record_in(
                                    document["keys"][key_id], key_id, 1)
                                self.assertEqual(
                                    self.ring._material_from(record, key_id, None),
                                    b"v1")
                        elif len(revoked_seen) == len(keys):
                            for key_id in keys:
                                record = self.ring._record_in(
                                    document["keys"][key_id], key_id, 1)
                                with self.assertRaises(core.RevokedVersionError):
                                    self.ring._material_from(record, key_id, None)
                        else:
                            # A partial revocation set is precisely what the
                            # atomic commit must make unobservable.
                            self.fail("observed a partially revoked batch")
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        def writer() -> None:
            try:
                for _ in range(8):
                    # Idempotent after the first commit: later calls still run
                    # every check and return None, rewriting nothing.
                    self.ring.revoke_batch(batch)
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        writers = [threading.Thread(target=writer) for _ in range(4)]
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
            self.assertEqual(self._revoked(key_id), {1: True, 2: False})
            self.assertEqual(self.ring.active(key_id), 2)


class CompatibilityTests(RevokeBatchTestBase):
    def test_single_key_revoke_remains_unchanged(self) -> None:
        v1 = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.assertIsNone(self.ring.revoke(KEY, v1))
        self.assertTrue(self.ring.is_revoked(KEY, v1))
        # Revoking the active version with the single-key API leaves the
        # pointer where it was.
        self.ring.revoke(KEY, 2)
        self.assertEqual(self.ring.active(KEY), 2)

    def test_no_batch_cli_subcommand(self) -> None:
        result = self._run_cli("revoke-batch", KEY, "1")
        self.assertNotEqual(result.returncode, 0)

    def test_cli_single_revoke_still_works(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        result = self._run_cli("revoke", KEY, "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok\n")
        self.assertTrue(self.ring.is_revoked(KEY, 1))

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
