"""Tests for ``KeyRing.seal_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts, each requiring ``key_id``/``material`` and
  allowing only ``password``/``iterations``/``expected_active``. key_id must
  be a non-empty string unique within the batch; material must be a string;
  password omitted/None means plain (an explicit empty string is a real
  passphrase); iterations follows ``seal`` (non-bool positive integer,
  default 200_000); expected_active omitted/None means no check, the
  non-bool integer 0 requires the key to be absent, and a non-bool positive
  integer requires that exact current active. Bad structure, non-dict items,
  missing/unknown fields, illegal values and duplicate key_ids are
  ``ValueError`` raised before storage is touched; the caller's objects are
  never mutated;
* first seals of new keys and appended seals of existing keys commit
  together: new keys start at version 1, existing keys get history max plus
  one, every new version is unrevoked and active, plain vs
  ``pbkdf2-sha256-sealed-v2`` follows the per-item password, each sealed
  record gets a fresh salt and binds the exact key name and new version, and
  recovered material matches ``seal``/``load``; old history, revocation
  marks and unrequested keys are untouched;
* the whole store is validated first (even unreferenced damage raises
  CorruptRecordError), then preconditions run in request order against one
  committed snapshot; a missing key's actual active is 0; the first
  ActiveVersionConflictError (existing wording) wins and keyring.json keeps
  its exact prior bytes -- no partial seals, no partial results;
* concurrent callers observe only the pre-batch or post-batch state; two
  batches expecting the same key absent (0) or the same old active cannot
  both succeed;
* missing store -> FileNotFoundError, five-second lock wait -> TimeoutError,
  other storage errors stay OSError; empty material/password and Unicode
  names/material keep working, legacy records still read, and there is no
  CLI surface nor report change.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import base64
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
OTHER = "别的键-😀"
PASSWORD = "correct horse"


class SealBatchTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _entry(self, key_id: str) -> dict:
        return self._document()["keys"][key_id]

    def _history(self, key_id: str) -> list[int]:
        return [item["version"] for item in self._entry(key_id)["versions"]]

    def _revoked(self, key_id: str) -> dict[int, bool]:
        return {item["version"]: item["revoked"]
                for item in self._entry(key_id)["versions"]}

    def _scheme(self, key_id: str, version: int) -> str:
        return next(item["scheme"] for item in self._entry(key_id)["versions"]
                    if item["version"] == version)

    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)

    @staticmethod
    def _wait_for(marker: Path, label: str) -> None:
        deadline = time.monotonic() + 5
        while not marker.is_file() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.is_file(), f"{label} never happened"


class HappyPathTests(SealBatchTestBase):
    def test_new_keys_start_at_one_and_become_active(self) -> None:
        numbers = self.ring.seal_batch([
            {"key_id": KEY, "material": "one"},
            {"key_id": OTHER, "material": "二"},
        ])
        self.assertEqual(numbers, [1, 1])
        self.assertEqual(self.ring.active(KEY), 1)
        self.assertEqual(self.ring.active(OTHER), 1)
        self.assertEqual(self.ring.versions(KEY), [1])
        self.assertEqual(self.ring.load(KEY), b"one")
        self.assertEqual(self.ring.load(OTHER), "二".encode("utf-8"))

    def test_mixed_new_and_existing_keys_share_one_commit(self) -> None:
        first = self.ring.seal(KEY, "old", PASSWORD, iterations=1_000)
        self.assertEqual(first, 1)
        numbers = self.ring.seal_batch([
            {"key_id": "fresh", "material": "new"},
            {"key_id": KEY, "material": "appended", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": OTHER, "material": "", "password": "",
             "iterations": 1_000},
        ])
        self.assertEqual(numbers, [1, 2, 1])
        self.assertEqual(self._history(KEY), [1, 2])
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertEqual(self.ring.load("fresh"), b"new")
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"appended")
        # The old version is still the old material and still openable.
        self.assertEqual(
            self.ring.load(KEY, version=1, password=PASSWORD), b"old")
        # Empty string is a real passphrase, distinct from plain/no password.
        self.assertEqual(self._scheme(OTHER, 1), core.SEALED_V2_SCHEME)
        self.assertEqual(self.ring.load(OTHER, version=1, password=""), b"")
        with self.assertRaises(core.MissingPasswordError):
            self.ring.load(OTHER, version=1)

    def test_plain_omitted_and_none_password_are_plain(self) -> None:
        self.ring.seal_batch([
            {"key_id": "a", "material": "x"},
            {"key_id": "b", "material": "x", "password": None},
        ])
        self.assertEqual(self._scheme("a", 1), core.PLAIN_SCHEME)
        self.assertEqual(self._scheme("b", 1), core.PLAIN_SCHEME)

    def test_version_numbers_follow_each_keys_own_history(self) -> None:
        self.ring.seal(KEY, "v1")
        self.ring.seal(KEY, "v2")
        self.ring.seal(OTHER, "o1")
        numbers = self.ring.seal_batch([
            {"key_id": OTHER, "material": "o2"},
            {"key_id": KEY, "material": "v3"},
            {"key_id": "new", "material": "n1"},
        ])
        # Return order is request order even though histories differ.
        self.assertEqual(numbers, [2, 3, 1])
        self.assertEqual(self._history(KEY), [1, 2, 3])
        self.assertEqual(self._history(OTHER), [1, 2])

    def test_new_versions_are_unrevoked_and_keep_old_revocation_marks(self) -> None:
        v1 = self.ring.seal(KEY, "one")
        self.ring.revoke(KEY, v1)
        numbers = self.ring.seal_batch([{"key_id": KEY, "material": "two"}])
        self.assertEqual(numbers, [2])
        self.assertEqual(self._revoked(KEY), {1: True, 2: False})
        self.assertEqual(self.ring.active(KEY), 2)
        self.assertEqual(self.ring.load(KEY), b"two")

    def test_unrequested_keys_and_their_histories_are_untouched(self) -> None:
        self.ring.seal(KEY, "keep", PASSWORD, iterations=1_000)
        before = self._document()["keys"][KEY]
        self.ring.seal_batch([{"key_id": "other", "material": "x"}])
        self.assertEqual(self._document()["keys"][KEY], before)

    def test_each_sealed_record_gets_a_fresh_salt_and_bound_version(self) -> None:
        numbers = self.ring.seal_batch([
            {"key_id": "a", "material": "same", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": "b", "material": "same", "password": PASSWORD,
             "iterations": 1_000},
        ])
        self.assertEqual(numbers, [1, 1])
        salt_a = self._entry("a")["versions"][0]["salt"]
        salt_b = self._entry("b")["versions"][0]["salt"]
        self.assertNotEqual(salt_a, salt_b)
        for name in ("a", "b"):
            record = self._entry(name)["versions"][0]
            self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
            self.assertEqual(record["iterations"], 1_000)
            self.assertEqual(record["version"], 1)
            self.assertFalse(record["revoked"])

    def test_recovery_matches_single_key_seal_byte_for_byte(self) -> None:
        material = "材料-β\u0000\n"
        numbers = self.ring.seal_batch([
            {"key_id": "sealed", "material": material, "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": "plain", "material": material},
        ])
        self.assertEqual(numbers, [1, 1])
        expected = self.ring.seal("reference", material, PASSWORD,
                                  iterations=1_000)
        self.assertEqual(
            self.ring.load("sealed", password=PASSWORD),
            self.ring.load("reference", version=expected, password=PASSWORD))
        self.assertEqual(self.ring.load("plain"),
                         self.ring.load("reference", version=expected,
                                        password=PASSWORD))

    def test_empty_material_and_unicode_round_trip(self) -> None:
        numbers = self.ring.seal_batch([
            {"key_id": "empty-plain", "material": ""},
            {"key_id": "empty-sealed", "material": "", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": "🔑", "material": "中文😀\t\r", "password": "口令",
             "iterations": 1_000},
        ])
        self.assertEqual(numbers, [1, 1, 1])
        self.assertEqual(self.ring.load("empty-plain"), b"")
        self.assertEqual(
            self.ring.load("empty-sealed", password=PASSWORD), b"")
        self.assertEqual(self.ring.load("🔑", password="口令"),
                         "中文😀\t\r".encode("utf-8"))

    def test_appending_to_a_key_with_legacy_history_keeps_legacy_readable(self) -> None:
        v1 = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        document = self._document()
        document["keys"][KEY]["versions"][0] = {
            "version": v1, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": False}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        numbers = self.ring.seal_batch(
            [{"key_id": KEY, "material": "new", "password": PASSWORD,
              "iterations": 1_000}])
        self.assertEqual(numbers, [2])
        self.assertEqual(self._scheme(KEY, 1), core.LEGACY_DERIVE_SCHEME)
        self.assertEqual(self._scheme(KEY, 2), core.SEALED_V2_SCHEME)
        with self.assertRaises(core.UnrecoverableRecordError):
            self.ring.load(KEY, version=1, password=PASSWORD)
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"new")


class InputValidationTests(SealBatchTestBase):
    def _assert_value_error_before_storage(self, requests) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(ValueError):
            self.ring.seal_batch(requests)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_outer_value_must_be_a_non_empty_list(self) -> None:
        for bad in ([], None, {}, (), ("x",), "x", 1):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(bad)

    def test_every_item_must_be_a_dict(self) -> None:
        self._assert_value_error_before_storage(["x"])
        self._assert_value_error_before_storage([None])
        self._assert_value_error_before_storage([[]])

    def test_required_fields(self) -> None:
        self._assert_value_error_before_storage([{"material": "x"}])
        self._assert_value_error_before_storage([{"key_id": KEY}])
        self._assert_value_error_before_storage([{}])

    def test_unknown_fields_rejected(self) -> None:
        self._assert_value_error_before_storage(
            [{"key_id": KEY, "material": "x", "bogus": 1}])
        self._assert_value_error_before_storage(
            [{"key_id": KEY, "material": "x", "version": 1}])

    def test_key_id_must_be_non_empty_string(self) -> None:
        for bad in ("", b"k", 1, None, ["k"], {}):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": bad, "material": "x"}])

    def test_material_must_be_a_string_but_may_be_empty(self) -> None:
        for bad in (b"x", 1, None, ["x"], {}):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": bad}])
        # The empty string is accepted and stored as plain.
        self.assertEqual(
            self.ring.seal_batch([{"key_id": KEY, "material": ""}]), [1])

    def test_password_must_be_string_or_none_empty_string_is_valid(self) -> None:
        for bad in (1, b"", [], {}):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": "x", "password": bad}])
        self.assertEqual(
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "x", "password": "",
                  "iterations": 1_000}]), [1])

    def test_iterations_must_be_non_bool_positive_integer(self) -> None:
        for bad in (0, -1, True, False, 1.5, "2", b"1", None):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": "x", "iterations": bad}])

    def test_expected_active_accepts_zero_and_positive_not_other_values(self) -> None:
        for bad in (-1, True, False, 1.0, "0", b"0", []):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": "x",
                      "expected_active": bad}])
        # 0 and positives pass input validation (existence/value is checked
        # against the store afterwards).
        self.assertEqual(
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "x", "expected_active": 0}]),
            [1])
        # KEY now exists with active 1, so a matching positive precondition
        # passes input validation and appends version 2.
        self.assertEqual(
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "y", "expected_active": 1}]),
            [2])

    def test_duplicate_key_id_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.ring.seal_batch([
                {"key_id": KEY, "material": "a"},
                {"key_id": KEY, "material": "b"},
            ])

    def test_validation_precedes_storage_access(self) -> None:
        # Even against a never-initialised ring, bad input is a ValueError,
        # never a FileNotFoundError.
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.seal_batch([{"key_id": KEY}])
        with self.assertRaises(ValueError):
            ring.seal_batch([{"key_id": "", "material": "x"}])
        with self.assertRaises(ValueError):
            ring.seal_batch([])

    def test_caller_objects_are_not_mutated(self) -> None:
        requests = [
            {"key_id": KEY, "material": "s", "password": PASSWORD,
             "iterations": 1_000, "expected_active": 0},
            {"key_id": OTHER, "material": "p"},
        ]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.seal_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)


class PreconditionTests(SealBatchTestBase):
    def test_expected_zero_allows_missing_key_and_blocks_existing(self) -> None:
        self.assertEqual(
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "x", "expected_active": 0}]),
            [1])
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "y", "expected_active": 0}])
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn("0", message)  # expected
        self.assertIn("1", message)  # actual
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._history(KEY), [1])

    def test_positive_expectation_on_missing_key_conflicts_with_actual_zero(
            self) -> None:
        # A missing key is actual 0, not a KeyError.
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.seal_batch(
                [{"key_id": "ghost", "material": "x",
                  "expected_active": 3}])
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr("ghost"), message)
        self.assertIn("3", message)
        self.assertIn("0", message)
        self.assertNotIn("ghost", self._document()["keys"])

    def test_matching_positive_precondition_appends(self) -> None:
        self.ring.seal(KEY, "one")
        self.assertEqual(
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "two",
                  "expected_active": 1}]),
            [2])
        self.assertEqual(self.ring.active(KEY), 2)

    def test_mismatched_positive_precondition_conflicts(self) -> None:
        self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "three",
                  "expected_active": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self._history(KEY), [1, 2])

    def test_none_and_omitted_precondition_are_unconditional(self) -> None:
        self.ring.seal(KEY, "one")
        self.assertEqual(
            self.ring.seal_batch(
                [{"key_id": KEY, "material": "two",
                  "expected_active": None}]),
            [2])
        self.assertEqual(
            self.ring.seal_batch([{"key_id": KEY, "material": "three"}]),
            [3])

    def test_only_the_first_conflict_is_reported(self) -> None:
        self.ring.seal(KEY, "one")
        # Item 0 matches; item 1 (missing key, positive expectation) is the
        # first conflict; item 2 would also conflict but must not be reached.
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.seal_batch([
                {"key_id": KEY, "material": "x", "expected_active": 1},
                {"key_id": "missing-a", "material": "x",
                 "expected_active": 5},
                {"key_id": "missing-b", "material": "x",
                 "expected_active": 9},
            ])
        self.assertIn(repr("missing-a"), str(caught.exception))
        self.assertNotIn("missing-b", str(caught.exception))

    def test_earlier_request_order_wins(self) -> None:
        # Reversed: now the first request is the first conflict.
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.seal_batch([
                {"key_id": "missing-b", "material": "x",
                 "expected_active": 9},
                {"key_id": "missing-a", "material": "x",
                 "expected_active": 5},
            ])
        self.assertIn(repr("missing-b"), str(caught.exception))

    def test_conflict_aborts_whole_batch_without_partial_seals(self) -> None:
        self.ring.seal(KEY, "one")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.seal_batch([
                {"key_id": "would-be-new", "material": "x",
                 "expected_active": 0},
                {"key_id": KEY, "material": "two", "expected_active": 9},
            ])
        # Nothing was created or appended anywhere.
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertNotIn("would-be-new", self._document()["keys"])
        self.assertEqual(self._history(KEY), [1])
        self.assertEqual(self.ring.active(KEY), 1)

    def test_unicode_key_in_conflict_message(self) -> None:
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.seal_batch(
                [{"key_id": OTHER, "material": "x", "expected_active": 2}])
        self.assertIn("活动版本冲突", str(caught.exception))
        self.assertIn(OTHER, str(caught.exception))


class WholeStoreValidationTests(SealBatchTestBase):
    def test_corrupt_keyring_file_is_corrupt_and_unchanged(self) -> None:
        self.ring.seal(KEY, "secret")
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.seal_batch([{"key_id": "other", "material": "x"}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_damage_in_an_unrequested_key_still_rejects_batch(self) -> None:
        self.ring.seal(KEY, "secret")
        document = self._document()
        document["keys"][KEY]["active"] = 99  # points at no real version
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.seal_batch([{"key_id": "other", "material": "x"}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_ring_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaisesRegex(FileNotFoundError, "no key ring"):
            ring.seal_batch([{"key_id": KEY, "material": "x"}])

    def test_lock_timeout_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "secret")
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
            before = self.ring.path.read_bytes()
            with self.assertRaisesRegex(TimeoutError, "获取密钥环写锁超时"):
                self.ring.seal_batch([{"key_id": "other", "material": "x"}])
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)


class ConcurrencyTests(SealBatchTestBase):
    def test_two_batches_expecting_key_absent_at_most_one_succeeds(self) -> None:
        count = 6
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        successes: list[int] = []
        conflicts: list[BaseException] = []
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                numbers = self.ring.seal_batch(
                    [{"key_id": KEY, "material": f"m-{i}",
                      "password": PASSWORD, "iterations": 500,
                      "expected_active": 0}])
                with lock:
                    successes.append(numbers[0])
            except core.ActiveVersionConflictError as error:
                with lock:
                    conflicts.append(error)
            except BaseException as error:  # noqa: BLE001 - surfaced below
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(conflicts), count - 1)
        # The winner committed exactly one version; losers sealed nothing.
        self.assertEqual(self._history(KEY), [1])
        self.assertEqual(self.ring.active(KEY), 1)

    def test_two_batches_expecting_same_old_active_at_most_one_succeeds(
            self) -> None:
        self.ring.seal(KEY, "zero")
        count = 5
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        successes: list[int] = []
        conflicts: list[BaseException] = []
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                numbers = self.ring.seal_batch(
                    [{"key_id": KEY, "material": f"m-{i}",
                      "expected_active": 1}])
                with lock:
                    successes.append(numbers[0])
            except core.ActiveVersionConflictError as error:
                with lock:
                    conflicts.append(error)
            except BaseException as error:  # noqa: BLE001 - surfaced below
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(conflicts), count - 1)
        self.assertEqual(self._history(KEY), [1, 2])
        self.assertEqual(self.ring.active(KEY), 2)

    def test_concurrent_batches_on_disjoint_keys_both_commit(self) -> None:
        barrier = threading.Barrier(2)
        results: dict[str, list[int]] = {}
        errors: list[BaseException] = []

        def worker(name: str, key_id: str) -> None:
            barrier.wait()
            try:
                results[name] = self.ring.seal_batch(
                    [{"key_id": key_id, "material": name,
                      "expected_active": 0}])
            except BaseException as error:  # noqa: BLE001 - surfaced below
                errors.append(error)

        threads = [
            threading.Thread(target=worker, args=("a", "key-a")),
            threading.Thread(target=worker, args=("b", "key-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(results, {"a": [1], "b": [1]})
        self.assertEqual(self.ring.load("key-a"), b"a")
        self.assertEqual(self.ring.load("key-b"), b"b")


class CompatibilityTests(SealBatchTestBase):
    def test_no_cli_subcommand_was_added(self) -> None:
        result = self._run_cli("seal-batch", "x")
        self.assertNotEqual(result.returncode, 0)
        # Existing single-key seal still works through the CLI.
        result = self._run_cli("seal", KEY, "cli-secret")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1\n")

    def test_report_shape_unchanged(self) -> None:
        self.ring.seal_batch([{"key_id": KEY, "material": "x"}])
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

    def test_single_key_and_other_batches_keep_working(self) -> None:
        self.assertEqual(self.ring.seal(KEY, "one"), 1)
        numbers = self.ring.seal_batch(
            [{"key_id": KEY, "material": "two"},
             {"key_id": OTHER, "material": "o", "expected_active": 0}])
        self.assertEqual(numbers, [2, 1])
        # rotate_password_batch appends after the seal_batch history.
        rotated = self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": "np", "iterations": 1_000,
             "expected_active": 2}])
        self.assertEqual(rotated, [3])
        self.assertEqual(self.ring.active(KEY), 3)
        self.assertEqual(
            self.ring.load(KEY, password="np"), b"two")

    def test_sealed_v2_record_binds_exact_key_and_new_version(self) -> None:
        # Sealing two different keys with the same material/password must not
        # be cross-openable: the v2 tag binds each full key name, and it
        # binds the actual new version number (2 for an existing key).
        self.ring.seal(KEY, "first", PASSWORD, iterations=1_000)
        self.ring.seal_batch([
            {"key_id": KEY, "material": "secret", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": "twin", "material": "secret", "password": PASSWORD,
             "iterations": 1_000},
        ])
        document = self._document()
        record_k = next(item for item in document["keys"][KEY]["versions"]
                        if item["version"] == 2)
        # Moving KEY's v2 record under "twin" breaks key binding. The copy
        # keeps version number 2 and twin's history is 1,2, so the document
        # stays structurally valid; the bound tag is what must reject it.
        moved = json.loads(json.dumps(record_k))
        document["keys"]["twin"]["versions"].append(moved)
        self.ring.path.write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load("twin", version=2, password=PASSWORD)
        # The authentic twin v1 record still opens.
        self.assertEqual(
            self.ring.load("twin", version=1, password=PASSWORD), b"secret")


if __name__ == "__main__":
    unittest.main()
