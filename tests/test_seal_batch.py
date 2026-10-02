"""Tests for ``KeyRing.seal_batch``.

Acceptance surface:
* one atomic batch seals brand-new keys (version 1) and appends further
  versions to existing keys (history max + 1), returning the new numbers in
  request order; each new version is unrevoked and becomes that key's active,
  older history and unrequested keys stay byte-for-byte intact;
* plain items come from an omitted/``None`` password; every string password --
  even the empty one -- writes a fresh-salt ``pbkdf2-sha256-sealed-v2``
  record bound to the full key name and new version, recoverable with
  ``load``'s exact verdicts and identical bytes to ``seal``;
* ``ValueError`` for every structural/value problem, including duplicate
  ``key_id``, all raised before storage is touched without mutating caller
  objects; ``expected_active`` uniquely accepts non-bool non-negative ints,
  where 0 means "key must not exist";
* the whole store is validated first; preconditions then run in request order
  against one committed snapshot, a missing key counting as active 0, the first
  conflict raising ``ActiveVersionConflictError`` with the standard wording;
* any failure leaves ``keyring.json`` byte-identical and returns nothing;
* concurrency: two batches expecting the same key absent or at the same old
  active cannot both commit;
* missing store -> FileNotFoundError, corrupt store -> CorruptRecordError,
  lock wait over five seconds -> TimeoutError, other storage errors -> OSError;
* empty materials/passphrases, Unicode keys and materials, old formats keep
  working; this is Python API only -- no CLI surface changes.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
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

    def _entry(self, key_id: str = KEY) -> dict:
        return self._document()["keys"][key_id]

    def _raw(self) -> bytes:
        return self.ring.path.read_bytes()


class HappyPathTests(SealBatchTestBase):
    def test_new_keys_start_at_one_and_become_active(self) -> None:
        numbers = self.ring.seal_batch([
            {"key_id": KEY, "material": "one"},
            {"key_id": OTHER, "material": "材料"},
        ])
        self.assertEqual(numbers, [1, 1])
        self.assertEqual(self.ring.active(KEY), 1)
        self.assertEqual(self.ring.active(OTHER), 1)
        self.assertEqual(self.ring.versions(KEY), [1])
        self.assertEqual(self.ring.load(KEY), b"one")
        self.assertEqual(self.ring.load(OTHER), "材料".encode("utf-8"))

    def test_new_and_existing_keys_in_one_commit(self) -> None:
        first = self.ring.seal(KEY, "old", PASSWORD, iterations=1_000)
        self.ring.seal(KEY, "older", iterations=1_000)
        untouched = self.ring.seal("untouched", "keep")
        numbers = self.ring.seal_batch([
            {"key_id": KEY, "material": "new", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": "fresh", "material": "brand"},
            {"key_id": OTHER, "material": "材料", "password": ""},
        ])
        self.assertEqual(numbers, [3, 1, 1])
        self.assertEqual(self.ring.versions(KEY), [1, 2, 3])
        self.assertEqual(self.ring.active(KEY), 3)
        self.assertEqual(self.ring.versions("fresh"), [1])
        self.assertEqual(self.ring.active("fresh"), 1)
        self.assertEqual(self.ring.versions(OTHER), [1])
        # Old history stays readable and keeps its revocation state.
        self.assertEqual(self.ring.load(KEY, version=first, password=PASSWORD), b"old")
        self.assertEqual(self.ring.load(KEY, version=2), b"older")
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"new")
        self.assertEqual(self.ring.load("fresh"), b"brand")
        self.assertEqual(self.ring.load(OTHER, password=""), "材料".encode("utf-8"))
        # An unrequested key is untouched entirely.
        self.assertEqual(self.ring.versions("untouched"), [untouched])
        self.assertEqual(self.ring.active("untouched"), untouched)
        self.assertEqual(self.ring.load("untouched"), b"keep")

    def test_version_uses_history_max_even_when_active_points_elsewhere(self) -> None:
        self.ring.seal(KEY, "one", iterations=1_000)
        self.ring.seal(KEY, "two", iterations=1_000)
        self.ring.seal(KEY, "three", iterations=1_000)
        self.ring.set_active(KEY, 1)
        self.ring.revoke(KEY, 2)
        number = self.ring.seal_batch([{"key_id": KEY, "material": "four"}])[0]
        self.assertEqual(number, 4)
        self.assertEqual(self.ring.versions(KEY), [1, 2, 3, 4])
        self.assertEqual(self.ring.active(KEY), 4)
        self.assertTrue(self.ring.is_revoked(KEY, 2))
        self.assertFalse(self.ring.is_revoked(KEY, 4))
        self.assertEqual(self.ring.load(KEY), b"four")

    def test_plain_via_omitted_and_none_password(self) -> None:
        numbers = self.ring.seal_batch([
            {"key_id": "a", "material": "plain-one"},
            {"key_id": "b", "material": "plain-two", "password": None},
            {"key_id": "c", "material": "", "password": ""},
        ])
        self.assertEqual(numbers, [1, 1, 1])
        records = {name: self._entry(name)["versions"][0] for name in "abc"}
        self.assertEqual(records["a"]["scheme"], core.PLAIN_SCHEME)
        self.assertEqual(records["b"]["scheme"], core.PLAIN_SCHEME)
        self.assertEqual(records["c"]["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(self.ring.load("a"), b"plain-one")
        self.assertEqual(self.ring.load("b"), b"plain-two")
        self.assertEqual(self.ring.load("c", password=""), b"")
        with self.assertRaises(core.MissingPasswordError):
            self.ring.load("c")
        with self.assertRaises(core.BadPasswordError):
            self.ring.load("c", password="x")

    def test_each_item_gets_fresh_salt_and_bound_v2_record(self) -> None:
        numbers = self.ring.seal_batch([
            {"key_id": KEY, "material": "same", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": OTHER, "material": "same", "password": PASSWORD,
             "iterations": 1_000},
        ])
        self.assertEqual(numbers, [1, 1])
        first = self._entry(KEY)["versions"][0]
        second = self._entry(OTHER)["versions"][0]
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["material"], second["material"])
        self.assertEqual(first["iterations"], 1_000)
        self.assertEqual(second["iterations"], 1_000)
        # The v2 tag binds the full key name: the record only opens under it.
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"same")
        self.assertEqual(self.ring.load(OTHER, password=PASSWORD), b"same")
        copied = self._document()
        copied["keys"]["moved"] = copied["keys"].pop(KEY)
        self.ring.path.write_text(json.dumps(copied), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load("moved", password=PASSWORD)

    def test_new_record_uses_requested_iterations(self) -> None:
        self.ring.seal(KEY, "old", PASSWORD, iterations=1_000)
        self.ring.seal_batch([
            {"key_id": KEY, "material": "new", "password": PASSWORD,
             "iterations": 4_242}])
        record = self._entry(KEY)["versions"][-1]
        self.assertEqual(record["iterations"], 4_242)
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"new")

    def test_material_bytes_match_single_seal_semantics(self) -> None:
        reference = core.KeyRing(self.root / "reference")
        reference.init()
        reference.seal(KEY, "材料-α", PASSWORD, iterations=1_000)
        expected = reference.load(KEY, password=PASSWORD)
        self.ring.seal_batch([
            {"key_id": KEY, "material": "材料-α", "password": PASSWORD,
             "iterations": 1_000}])
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), expected)


class ExpectedActiveTests(SealBatchTestBase):
    def test_zero_matches_only_a_missing_key(self) -> None:
        numbers = self.ring.seal_batch([
            {"key_id": KEY, "material": "born", "expected_active": 0}])
        self.assertEqual(numbers, [1])
        before = self._raw()
        # The key now exists: a second 0-precondition batch must conflict.
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.seal_batch([
                {"key_id": KEY, "material": "again", "expected_active": 0}])
        self.assertEqual(self._raw(), before)
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn("预期活动版本为 0", message)
        self.assertIn("实际活动版本为 1", message)

    def test_positive_precondition_on_missing_key_conflicts_with_zero(self) -> None:
        before = self._raw()
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.seal_batch([
                {"key_id": KEY, "material": "x", "expected_active": 3}])
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn("3", message)
        self.assertIn("为 0", message)  # missing key actual is 0
        self.assertEqual(self._raw(), before)
        self.assertNotIn(KEY, self._document()["keys"])

    def test_matching_positive_precondition_appends(self) -> None:
        self.ring.seal(KEY, "one", iterations=1_000)
        numbers = self.ring.seal_batch([
            {"key_id": KEY, "material": "two", "expected_active": 1}])
        self.assertEqual(numbers, [2])
        self.assertEqual(self.ring.active(KEY), 2)

    def test_mismatch_reports_first_conflict_in_request_order(self) -> None:
        self.ring.seal(KEY, "one", iterations=1_000)
        before = self._raw()
        # Item 0 matches, item 1 conflicts on a missing key: item 1 is
        # reported, and item 0 never commits.
        with self.assertRaisesRegex(core.ActiveVersionConflictError, repr(OTHER)):
            self.ring.seal_batch([
                {"key_id": KEY, "material": "x", "expected_active": 1},
                {"key_id": OTHER, "material": "y", "expected_active": 5},
            ])
        self.assertEqual(self._raw(), before)
        self.assertEqual(self.ring.versions(KEY), [1])
        self.assertEqual(self.ring.active(KEY), 1)
        self.assertNotIn(OTHER, self._document()["keys"])
        # Reversed order: the missing key is item 0 and reported first.
        with self.assertRaisesRegex(core.ActiveVersionConflictError, repr(OTHER)):
            self.ring.seal_batch([
                {"key_id": OTHER, "material": "y", "expected_active": 5},
                {"key_id": KEY, "material": "x", "expected_active": 99},
            ])
        self.assertEqual(self._raw(), before)

    def test_none_and_omitted_skip_the_check(self) -> None:
        self.ring.seal(KEY, "one", iterations=1_000)
        self.assertEqual(
            self.ring.seal_batch([{"key_id": KEY, "material": "a"}]), [2])
        self.assertEqual(
            self.ring.seal_batch(
                [{"key_id": OTHER, "material": "b", "expected_active": None}]),
            [1])

    def test_conflict_aborts_before_any_new_key_is_created(self) -> None:
        self.ring.seal(KEY, "one", iterations=1_000)
        before = self._raw()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.seal_batch([
                {"key_id": "new-a", "material": "a", "expected_active": 0},
                {"key_id": KEY, "material": "b", "expected_active": 9},
                {"key_id": "new-b", "material": "c", "expected_active": 0},
            ])
        self.assertEqual(self._raw(), before)
        self.assertEqual(set(self._document()["keys"]), {KEY})


class ValidationTests(SealBatchTestBase):
    def _assert_value_error_before_storage(self, requests) -> None:
        before = self._raw()
        with self.assertRaises(ValueError):
            self.ring.seal_batch(requests)
        self.assertEqual(self._raw(), before)

    def test_outer_shape(self) -> None:
        for bad in ([], None, {}, (), "x", 42):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(bad)

    def test_items_must_be_dicts(self) -> None:
        for bad in ([()], [("x",)], [object()], [42], ["x"], [None]):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(bad)

    def test_required_and_allowed_fields(self) -> None:
        good = {"key_id": KEY, "material": "m"}
        self._assert_value_error_before_storage([{"material": "m"}])
        self._assert_value_error_before_storage([{"key_id": KEY}])
        self._assert_value_error_before_storage([{}])
        for field in ("password", "iterations", "expected_active"):
            self._assert_value_error_before_storage(
                [{**good, field: None, "bogus": 1}])
        self._assert_value_error_before_storage([{**good, "version": 1}])

    def test_key_id_rules(self) -> None:
        for bad in ("", None, b"k", 1, ["k"]):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": bad, "material": "m"}])

    def test_material_must_be_string_but_may_be_empty(self) -> None:
        for bad in (None, b"m", 1, ["m"], {}):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": bad}])
        # Empty string is fine.
        self.assertEqual(
            self.ring.seal_batch([{"key_id": KEY, "material": ""}]), [1])
        self.assertEqual(self.ring.load(KEY), b"")

    def test_password_rules(self) -> None:
        for bad in (1, b"p", [""]):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": "m", "password": bad}])
        # Empty password is a valid passphrase; None/omitted means plain.
        for value in ("",):
            numbers = self.ring.seal_batch(
                [{"key_id": f"k-{value!r}", "material": "m",
                  "password": value}])
            self.assertEqual(numbers, [1])

    def test_iterations_rules(self) -> None:
        for bad in (0, -1, True, False, 1.0, "2", b"1"):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": "m", "iterations": bad}])

    def test_expected_active_rules(self) -> None:
        # 0 is legal for seal_batch; negatives, bools and non-ints are not.
        for bad in (-1, True, False, "0", 1.5, b"0"):
            with self.subTest(bad=bad):
                self._assert_value_error_before_storage(
                    [{"key_id": KEY, "material": "m",
                      "expected_active": bad}])
        # Both legal forms work.
        self.assertEqual(self.ring.seal_batch(
            [{"key_id": "a", "material": "m", "expected_active": 0}]), [1])
        self.assertEqual(self.ring.seal_batch(
            [{"key_id": "b", "material": "m", "expected_active": None}]), [1])

    def test_duplicate_key_id_rejected(self) -> None:
        before = self._raw()
        with self.assertRaises(ValueError):
            self.ring.seal_batch([
            {"key_id": "é", "material": "a"},
            {"key_id": "é", "material": "b"},
            ])
        self.assertEqual(self._raw(), before)
        # Distinct Unicode spellings are distinct keys, even when they look alike:
        # U+00E9 ("é") versus "e" + U+0301 combining acute.
        numbers = self.ring.seal_batch([
            {"key_id": "\u00e9", "material": "a"},
            {"key_id": "\u0065\u0301", "material": "b"},
        ])
        self.assertEqual(numbers, [1, 1])

    def test_validation_runs_before_storage_access(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        # Illegal input raises ValueError even though the store is missing.
        with self.assertRaises(ValueError):
            ring.seal_batch([])
        with self.assertRaises(ValueError):
            ring.seal_batch([{"key_id": KEY, "material": "m",
                               "expected_active": -1}])
        # Well-formed input against the missing store reaches storage: FileNotFoundError.
        with self.assertRaises(FileNotFoundError):
            ring.seal_batch([{"key_id": KEY, "material": "m"}])

    def test_caller_objects_are_not_mutated(self) -> None:
        self.ring.seal(KEY, "old", iterations=1_000)
        requests = [
            {"key_id": KEY, "material": "new", "password": PASSWORD,
             "iterations": 1_000, "expected_active": 1},
            {"key_id": OTHER, "material": "材料"},
        ]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.seal_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)


class StorageGuardTests(SealBatchTestBase):
    def test_whole_store_is_validated_even_for_unrelated_keys(self) -> None:
        self.ring.seal("victim", "secret", PASSWORD, iterations=1_000)
        document = self._document()
        document["keys"]["victim"]["active"] = 9
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self._raw()
        # expected_active 0 would match for a brand-new key; store damage wins.
        with self.assertRaises(core.CorruptRecordError):
            self.ring.seal_batch([
                {"key_id": "brand-new", "material": "m",
                 "expected_active": 0}])
        self.assertEqual(self._raw(), before)

    def test_failure_leaves_file_unchanged_and_no_partial_seal(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        before = self._raw()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.seal_batch([
            {"key_id": "é", "material": "a"},
                {"key_id": KEY, "material": "b", "expected_active": 9},
            ])
        self.assertEqual(self._raw(), before)

    def test_write_lock_timeout(self) -> None:
        import os
        import time
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
            with self.assertRaisesRegex(TimeoutError, "获取密钥环写锁超时"):
                self.ring.seal_batch([{"key_id": KEY, "material": "m"}])
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)

    def test_legacy_formats_remain_readable_after_batch(self) -> None:
        # A derived-only legacy record survives a batch touching other keys and keeps
        # its load verdict.
        document = self._document()
        document["keys"]["legacy"] = {
            "active": 1,
            "versions": [{"version": 1, "scheme": core.LEGACY_DERIVE_SCHEME,
                          "revoked": False}]}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        self.ring.seal_batch([{"key_id": KEY, "material": "new"}])
        with self.assertRaises(core.UnrecoverableRecordError):
            self.ring.load("legacy", password=PASSWORD)
        self.assertEqual(self.ring.load(KEY), b"new")


class ConcurrencyTests(SealBatchTestBase):
    def test_two_batches_expecting_absent_key_at_most_one_commits(self) -> None:
        count = 8
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        successes = 0
        conflicts: list[BaseException] = []
        errors: list[BaseException] = []

        def worker() -> None:
            nonlocal successes
            barrier.wait()
            try:
                self.ring.seal_batch(
                    [{"key_id": KEY, "material": "born",
                      "expected_active": 0}])
                with lock:
                    successes += 1
            except core.ActiveVersionConflictError as error:
                with lock:
                    conflicts.append(error)
            except BaseException as error:  # noqa: BLE001 - surfaced below
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(successes, 1)
        self.assertEqual(len(conflicts), count - 1)
        self.assertEqual(self.ring.versions(KEY), [1])
        self.assertEqual(self.ring.active(KEY), 1)

    def test_two_batches_expecting_same_old_active_at_most_one(self) -> None:
        self.ring.seal(KEY, "seed", iterations=1_000)
        count = 6
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        winners: list[int] = []
        conflicts: list[BaseException] = []
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                numbers = self.ring.seal_batch([
                    {"key_id": KEY, "material": f"m-{i}",
                     "expected_active": 1}])
                with lock:
                    winners.append(numbers[0])
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
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(conflicts), count - 1)
        self.assertEqual(self.ring.versions(KEY), [1, 2])
        self.assertEqual(self.ring.active(KEY), 2)

    def test_observers_see_only_pre_or_post_batch_state(self) -> None:
        # A reader hammering versions()/active() while mixed new+old items
        # commit must see a consistent document every time.
        self.ring.seal(KEY, "seed", iterations=1_000)
        stop = threading.Event()
        bad: list[str] = []

        def reader() -> None:
            while not stop.is_set():
                try:
                    document = self._document()
                    for key_id, entry in document["keys"].items():
                        if entry["active"] not in {v["version"]
                                                    for v in entry["versions"]}:
                            bad.append(key_id)
                except json.JSONDecodeError as error:  # a torn read
                    bad.append(str(error))

        thread = threading.Thread(target=reader)
        thread.start()
        try:
            for round_index in range(20):
                self.ring.seal_batch([
                    {"key_id": KEY, "material": f"k-{round_index}"},
                    {"key_id": f"new-{round_index}", "material": "n",
                     "expected_active": 0},
                ])
        finally:
            stop.set()
            thread.join(timeout=10)
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
