"""Tests for ``KeyRing.revoke_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts, each requiring ``key_id``/``versions`` and
  allowing only ``replacement_active``/``expected_active``; ``versions`` is a
  non-empty list of distinct non-bool positive integers resolved in list
  order; both optional fields are ``None``/omitted or a non-bool positive
  integer; a key_id may appear only once. Bad structure, non-dict items,
  missing/unknown fields, illegal values, a repeated key_id or a repeated
  version inside one item are ``ValueError`` raised for the whole batch
  before storage is touched; the caller's objects are never mutated;
* the whole store is validated first (even unreferenced damage raises
  ``CorruptRecordError``), then items are checked in request order against
  one committed snapshot -- key existence (KeyError), the expected_active
  precondition vs the active *number* only (ActiveVersionConflictError,
  the expected version need not exist), each requested version in list
  order (KeyError), and finally the replacement (KeyError when missing,
  RevokedVersionError when already revoked or listed for revocation);
  revoking an already revoked version succeeds; the first failure wins and
  keyring.json keeps its exact prior bytes;
* without a replacement the active pointer is kept even when the active
  version is revoked; with a replacement the pointer moves whether or not
  the old active was revoked; revocations and moves commit together in one
  atomic replace -- no new versions, no decryption, material and
  parameters untouched, other keys untouched; all four record formats can
  be revoked and even a legacy/v1 record may serve as replacement;
* a batch already entirely at its target state still runs every check but
  does not rewrite keyring.json;
* concurrent callers and load_batch see only the pre-batch or post-batch
  state; two batches expecting the same old active cannot both succeed;
* missing store -> FileNotFoundError, five-second lock wait ->
  TimeoutError, other storage errors stay OSError;
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
        document["keys"][key_id]["versions"][0 if version == 1 else -1] = {
            "version": version, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": False}
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
    def test_revokes_several_keys_together_and_returns_none(self) -> None:
        for key_id in (KEY, OTHER, "k3"):
            self.ring.seal(key_id, "one", PASSWORD, iterations=200)
            self.ring.seal(key_id, "two", PASSWORD, iterations=200)
        result = self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1]},
            {"key_id": OTHER, "versions": [1, 2]},
            {"key_id": "k3", "versions": [1], "replacement_active": 2},
        ])
        self.assertIsNone(result)
        self.assertEqual(self._revoked(KEY), {1: True, 2: False})
        self.assertEqual(self._revoked(OTHER), {1: True, 2: True})
        self.assertEqual(self._revoked("k3"), {1: True, 2: False})
        # Keys without a replacement keep their pointer; k3 moved to 2.
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertEqual(self.ring.active(OTHER), 2)
        self.assertEqual(self.ring.active("k3"), 2)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY, version=1, password=PASSWORD)
        self.assertEqual(self.ring.load("k3", password=PASSWORD), b"two")

    def test_revoking_active_without_replacement_keeps_pointer(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.set_active(KEY, 1)
        self.assertIsNone(
            self.ring.revoke_batch([{"key_id": KEY, "versions": [1]}]))
        # The pointer is deliberately left dangling at the revoked version.
        self.assertEqual(self.ring.active(KEY), 1)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY)

    def test_revoking_active_with_replacement_moves_pointer(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.set_active(KEY, 1)
        self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1], "replacement_active": 2}])
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertEqual(self._revoked(KEY), {1: True, 2: False})
        self.assertEqual(self.ring.load(KEY), b"two")

    def test_replacement_moves_even_when_active_is_not_revoked(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(KEY, "three")
        # Revoke the historical v1; the active v3 is untouched, yet the
        # explicit replacement still moves the pointer.
        self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1], "replacement_active": 2}])
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertEqual(self._revoked(KEY), {1: True, 2: False, 3: False})

    def test_already_revoked_targets_succeed_idempotently(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.revoke(KEY, 1)
        time.sleep(0.02)
        before = self.ring.path.read_bytes()
        before_mtime = self.ring.path.stat().st_mtime_ns
        result = self.ring.revoke_batch([{"key_id": KEY, "versions": [1]}])
        self.assertIsNone(result)
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.path.stat().st_mtime_ns, before_mtime)
        self.assertEqual(self._revoked(KEY), {1: True, 2: False})

    def test_all_four_record_formats_are_revocable(self) -> None:
        plain_key, v1_key, v2_key, legacy_key = "plain", "v1", "v2", "legacy"
        # plain is sealed with no passphrase; the others with a passphrase.
        self.ring.seal(plain_key, "secret")
        self.ring.seal(plain_key, "newer")
        for key_id in (v1_key, v2_key, legacy_key):
            self.ring.seal(key_id, "secret", PASSWORD, iterations=1_000)
            self.ring.seal(key_id, "newer", PASSWORD, iterations=1_000)
        self._replace_with_v1(v1_key, 1, b"secret")
        self._make_legacy_derived(legacy_key, 1)
        before = self._document()
        self.assertIsNone(self.ring.revoke_batch([
            {"key_id": plain_key, "versions": [1]},
            {"key_id": v1_key, "versions": [1]},
            {"key_id": v2_key, "versions": [1]},
            {"key_id": legacy_key, "versions": [1]},
        ]))
        for key_id, scheme in ((plain_key, core.PLAIN_SCHEME),
                               (v1_key, core.SEALED_SCHEME),
                               (v2_key, core.SEALED_V2_SCHEME),
                               (legacy_key, core.LEGACY_DERIVE_SCHEME)):
            self.assertEqual(self._record(key_id, 1)["scheme"], scheme)
            self.assertTrue(self._record(key_id, 1)["revoked"])
            self.assertFalse(self._record(key_id, 2)["revoked"])
            with self.assertRaises(core.RevokedVersionError):
                self.ring.load(key_id, version=1, password=PASSWORD)
        # Nothing besides the four revoked flags changed.
        after = self._document()
        for key_id in (plain_key, v1_key, v2_key, legacy_key):
            for after_item, before_item in zip(after["keys"][key_id]["versions"],
                                               before["keys"][key_id]["versions"]):
                self.assertEqual({k: v for k, v in after_item.items() if k != "revoked"},
                                 {k: v for k, v in before_item.items() if k != "revoked"})

    def test_replacement_may_point_at_v1_or_legacy_without_decrypting(self) -> None:
        v1_key, legacy_key = "v1", "legacy"
        self.ring.seal(v1_key, "secret", PASSWORD, iterations=1_000)
        self.ring.seal(v1_key, "newer", PASSWORD, iterations=1_000)
        self._replace_with_v1(v1_key, 1, b"secret")
        self.ring.seal(legacy_key, "gone", PASSWORD, iterations=1_000)
        self.ring.seal(legacy_key, "current", PASSWORD, iterations=1_000)
        self._make_legacy_derived(legacy_key, 1)
        self.ring.revoke_batch([
            {"key_id": v1_key, "versions": [2], "replacement_active": 1},
            {"key_id": legacy_key, "versions": [2], "replacement_active": 1},
        ])
        self.assertEqual(self.ring.active(v1_key), 1)
        self.assertEqual(self.ring.active(legacy_key), 1)
        # The v1 replacement opens normally; the legacy replacement keeps
        # failing by load's old rule -- revocation never decrypts anything.
        self.assertEqual(self.ring.load(v1_key, password=PASSWORD), b"secret")
        with self.assertRaises(core.UnrecoverableRecordError):
            self.ring.load(legacy_key, password=PASSWORD)

    def test_only_revocation_flags_and_named_pointers_change(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.ring.seal(OTHER, "a", PASSWORD, iterations=200)
        self.ring.seal(OTHER, "b", PASSWORD, iterations=200)
        # OTHER starts with its pointer at v1, so revoking v1 with v2 as the
        # replacement genuinely moves the pointer to 2.
        self.ring.set_active(OTHER, 1)
        before = self._document()
        self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1]},
            {"key_id": OTHER, "versions": [1], "replacement_active": 2},
        ])
        after = self._document()
        self.assertTrue(after["keys"][KEY]["versions"][0]["revoked"])
        self.assertFalse(after["keys"][KEY]["versions"][1]["revoked"])
        self.assertEqual(after["keys"][KEY]["active"], before["keys"][KEY]["active"])
        self.assertEqual(after["keys"][OTHER]["active"], 2)
        # Every non-revoked field of every record is byte-identical.
        for key_id in (KEY, OTHER):
            for after_item, before_item in zip(after["keys"][key_id]["versions"],
                                               before["keys"][key_id]["versions"]):
                self.assertEqual({k: v for k, v in after_item.items() if k != "revoked"},
                                 {k: v for k, v in before_item.items() if k != "revoked"})
        self.assertEqual(self._history(KEY), [1, 2])

    def test_unicode_key_names_are_not_normalised(self) -> None:
        self.ring.seal("k", "lower", PASSWORD, iterations=200)
        self.ring.seal("k", "lower-2", PASSWORD, iterations=200)
        self.ring.seal("K", "upper", PASSWORD, iterations=200)
        self.ring.seal("K", "upper-2", PASSWORD, iterations=200)
        self.ring.seal("键-😀", "中文", PASSWORD, iterations=200)
        self.ring.seal("键-😀", "中文-二", PASSWORD, iterations=200)
        self.ring.revoke_batch([
            {"key_id": "k", "versions": [1]},
            {"key_id": "K", "versions": [1], "replacement_active": 2},
            {"key_id": "键-😀", "versions": [1]},
        ])
        self.assertEqual(self._revoked("k"), {1: True, 2: False})
        self.assertEqual(self._revoked("K"), {1: True, 2: False})
        self.assertEqual(self.ring.active("K"), 2)
        self.assertEqual(self.ring.load("K", password=PASSWORD), b"upper-2")
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load("键-😀", version=1, password=PASSWORD)


class NoRewriteTests(RevokeBatchTestBase):
    def test_batch_already_at_target_does_not_rewrite_file(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(OTHER, "x")
        self.ring.seal(OTHER, "y")
        self.ring.revoke(KEY, 1)
        # OTHER keeps its pointer at 1; its v2 is already revoked and the
        # batch names no replacement, so nothing moves.
        self.ring.set_active(OTHER, 1)
        self.ring.revoke(OTHER, 2)
        time.sleep(0.02)
        before_bytes = self.ring.path.read_bytes()
        before_mtime = self.ring.path.stat().st_mtime_ns
        result = self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1], "expected_active": 2},
            {"key_id": OTHER, "versions": [2], "expected_active": 1},
        ])
        self.assertIsNone(result)
        self.assertEqual(self.ring.path.read_bytes(), before_bytes)
        self.assertEqual(self.ring.path.stat().st_mtime_ns, before_mtime)
        self.assertEqual(self.ring.active(OTHER), 1)

    def test_one_real_change_among_noops_still_commits(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.seal(OTHER, "x")
        self.ring.seal(OTHER, "y")
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        self.assertIsNone(self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1]},   # already revoked
            {"key_id": OTHER, "versions": [1]},  # newly revoked
        ]))
        self.assertNotEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(KEY), {1: True, 2: False})
        self.assertEqual(self._revoked(OTHER), {1: True, 2: False})

    def test_replacement_move_alone_rewrites_even_without_new_revocation(self) -> None:
        # v1 is already revoked; the batch revokes nothing new but the
        # replacement genuinely moves the pointer, so it must still commit.
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.revoke(KEY, 1)
        self.ring.set_active(KEY, 1)
        before = self.ring.path.read_bytes()
        self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1], "replacement_active": 2}])
        self.assertNotEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertEqual(self._revoked(KEY), {1: True, 2: False})

    def test_failure_does_not_rewrite(self) -> None:
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
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "versions": None}])

    def test_unknown_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "versions": [1], "bogus": 2}])
        with self.assertRaises(ValueError):
            self._batch([{"bogus": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "versions": [1], "version": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "versions": [1], "password": "p"}])

    def test_key_id_rules(self) -> None:
        for bad in ("", 1, None, b"k"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch([{"key_id": bad, "versions": [1]}])

    def test_versions_rules(self) -> None:
        good = {"key_id": KEY}
        for bad_versions in (
            None, [], (), [[]], "1", {"1": True}, 1,
            [0], [-1], ["1"], [b"1"], [1.5], [True], [False], [None],
            [1, 1], [2, 1, 2],
        ):
            with self.subTest(bad_versions=bad_versions):
                with self.assertRaises(ValueError):
                    self._batch([{**good, "versions": bad_versions}])

    def test_optional_fields_rules(self) -> None:
        for field in ("replacement_active", "expected_active"):
            for bad in (0, -2, "1", True, False, 1.5, b"1"):
                with self.subTest(field=field, bad=bad):
                    with self.assertRaises(ValueError):
                        self._batch([{"key_id": KEY, "versions": [1], field: bad}])

    def test_optional_none_is_allowed(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.assertIsNone(self.ring.revoke_batch([
            {"key_id": KEY, "versions": [1],
             "replacement_active": None, "expected_active": None}]))
        self.assertEqual(self.ring.active(KEY), 2)

    def test_duplicate_key_id_rejected(self) -> None:
        self.ring.seal(KEY, "x")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._batch([
                {"key_id": KEY, "versions": [1]},
                {"key_id": KEY, "versions": [2]},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_validation_precedes_storage_and_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "one")
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
        # A structurally valid batch on the same missing ring is the point
        # where storage is touched.
        with self.assertRaises(FileNotFoundError):
            ring.revoke_batch([{"key_id": KEY, "versions": [1]}])

    def test_caller_input_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        requests = [{"key_id": KEY, "versions": [1],
                     "replacement_active": 2, "expected_active": 2}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.revoke_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)
        self.assertEqual(requests, [{"key_id": KEY, "versions": [1],
                                     "replacement_active": 2,
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
        self.assertIn("9", message)  # expected
        self.assertIn("3", message)  # actual
        self.assertIsInstance(caught.exception, core.SealError)

    def test_conflict_even_when_expected_version_never_existed(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [1], "expected_active": 99}])

    def test_conflict_precedes_unknown_version_and_bad_replacement(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [99], "expected_active": 7}])
        self.ring.revoke(KEY, 1)
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [2],
                 "replacement_active": 1, "expected_active": 7}])

    def test_versions_resolved_in_list_order(self) -> None:
        before = self.ring.path.read_bytes()
        # 2 exists, 99 does not: the missing member is reported even though
        # a later member (1) exists and nothing has been revoked yet.
        with self.assertRaisesRegex(KeyError, "99"):
            self.ring.revoke_batch([{"key_id": KEY, "versions": [2, 99, 1]}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(KEY), {1: False, 2: False, 3: False})

    def test_replacement_checked_after_all_versions(self) -> None:
        # All listed versions exist (revoking them would be legal), but the
        # replacement does not: the replacement check comes last.
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(KeyError, "42"):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [1, 2], "replacement_active": 42}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(KEY), {1: False, 2: False, 3: False})

    def test_replacement_already_revoked_is_revoked_error(self) -> None:
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销") as caught:
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [2], "replacement_active": 1}])
        message = str(caught.exception)
        self.assertIn(repr(KEY), message)
        self.assertIn("1", message)
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(KEY), {1: True, 2: False, 3: False})
        self.assertEqual(self.ring.active(KEY), 3)

    def test_replacement_listed_for_revocation_is_revoked_error(self) -> None:
        # Even though v2 is currently unrevoked, pointing the pointer at the
        # version this item revokes is rejected.
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [1, 2], "replacement_active": 2}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(KEY), {1: False, 2: False, 3: False})
        self.assertEqual(self.ring.active(KEY), 3)

    def test_revoked_replacement_fails_even_when_active_points_at_it(self) -> None:
        self.ring.set_active(KEY, 1)
        self.ring.revoke(KEY, 1)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.revoke_batch([
                {"key_id": KEY, "versions": [2], "replacement_active": 1}])

    def test_unknown_version_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.revoke_batch([{"key_id": KEY, "versions": [42]}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_revoking_already_revoked_version_alone_succeeds(self) -> None:
        self.ring.revoke(KEY, 1)
        self.assertIsNone(self.ring.revoke_batch([{"key_id": KEY, "versions": [1]}]))
        # And mixed with a fresh revocation in the same list.
        self.assertIsNone(self.ring.revoke_batch([{"key_id": KEY, "versions": [1, 2]}]))
        self.assertEqual(self._revoked(KEY), {1: True, 2: True, 3: False})
        self.assertEqual(self.ring.active(KEY), 3)

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
        # Item 0 fine, item 1 has a revoked replacement: it wins and item 0
        # is not revoked.
        with self.assertRaises(core.RevokedVersionError):
            self.ring.revoke_batch([
                {"key_id": OTHER, "versions": [1]},
                {"key_id": KEY, "versions": [2], "replacement_active": 1},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._revoked(OTHER), {1: False, 2: False})
        self.assertEqual(self._revoked(KEY), {1: True, 2: False, 3: False})

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
        self.assertEqual(self.ring.active(KEY), 1)


class ConcurrencyTests(RevokeBatchTestBase):
    def test_two_batches_one_shared_precondition_at_most_one_wins(self) -> None:
        # Shared KEY starts at active 1; every batch expects exactly that,
        # revokes v1 and replaces it with v2. Each batch also revokes a
        # thread-private key's v1, so a losing batch fails wholesale and
        # never revokes the private version.
        self.ring.seal(KEY, "shared-one")
        self.ring.seal(KEY, "shared-two")
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
                    {"key_id": KEY, "versions": [1],
                     "replacement_active": 2, "expected_active": 1},
                    {"key_id": private[i], "versions": [1]},
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
            self.assertEqual(self.ring.is_revoked(name, 1), i == winner)
            # No replacement for private keys: the pointer stays at 2.
            self.assertEqual(self.ring.active(name), 2)

    def test_states_are_only_seen_whole_under_a_storm(self) -> None:
        keys = ["a", "b", "c", "d"]
        for key_id in keys:
            self.ring.seal(key_id, "v1")
            self.ring.seal(key_id, "v2")
            self.ring.seal(key_id, "v3")
        # v1 is revoked before the storm; writers only swing the live
        # pointer between v2 and v3, so every committed document keeps the
        # same shape: revoked v1, live v2/v3, pointer at 2 or 3.
        self.ring.revoke_batch([{"key_id": key_id, "versions": [1]}
                                for key_id in keys])
        stop = threading.Event()
        errors: list[BaseException] = []

        def reader() -> None:
            try:
                while not stop.is_set():
                    # One shared-lock snapshot: a committed document is always
                    # internally whole -- v1's revoked flag and the active
                    # pointer never appear from different generations.
                    with core._locked(self.ring, exclusive=False):
                        document = self.ring._read()
                    for key_id in keys:
                        entry = document["keys"][key_id]
                        numbers = [item["version"] for item in entry["versions"]]
                        self.assertEqual(numbers, [1, 2, 3])
                        self.assertIn(entry["active"], (2, 3))
                        self.assertTrue(entry["versions"][0]["revoked"])
                    # v3 is never revoked by any writer, so it always opens;
                    # the default load always names a live 2/3 pointer.
                    self.assertEqual(
                        self.ring.load_batch(
                            [{"key_id": key_id, "version": 3} for key_id in keys]),
                        [b"v3"] * len(keys))
                    self.ring.load_batch([{"key_id": key_id} for key_id in keys])
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        def writer(i: int) -> None:
            try:
                for round_index in range(8):
                    target = 2 if (round_index + i) % 2 else 3
                    self.ring.revoke_batch(
                        [{"key_id": key_id, "versions": [1],
                          "replacement_active": target}
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
        for key_id in keys:
            self.assertEqual(self._history(key_id), [1, 2, 3])
            self.assertEqual(self._revoked(key_id), {1: True, 2: False, 3: False})


class CompatibilityTests(RevokeBatchTestBase):
    def test_single_key_revoke_unchanged(self) -> None:
        v1 = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.assertIsNone(self.ring.revoke(KEY, v1))
        self.assertTrue(self.ring.is_revoked(KEY, v1))
        self.assertEqual(self.ring.active(KEY), 2)
        with self.assertRaises(core.RevokedVersionError):
            self.ring.load(KEY, version=1)

    def test_single_key_revoke_still_rewrites_for_already_revoked(self) -> None:
        # The single-key API keeps its old unconditional-rewrite behaviour;
        # only the batch skips the rewrite when already at the target.
        self.ring.seal(KEY, "one")
        self.ring.revoke(KEY, 1)
        before = self.ring.path.read_bytes()
        self.ring.revoke(KEY, 1)
        # Single revoke always goes through _write; content stays equivalent.
        self.assertEqual(json.loads(self.ring.path.read_text()),
                         json.loads(before))

    def test_no_batch_cli_subcommand(self) -> None:
        result = self._run_cli("revoke-batch", KEY, "1")
        self.assertNotEqual(result.returncode, 0)

    def test_existing_cli_revoke_still_works(self) -> None:
        self.ring.seal(KEY, "one")
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
