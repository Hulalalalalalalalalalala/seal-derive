"""Tests for ``KeyRing.set_active_batch`` (Python API only).

Acceptance surface:
* a non-empty list of dicts, each requiring ``key_id`` and ``version`` and
  allowing only ``expected_active``; bad structure, non-dict items,
  missing/unknown fields, illegal values and duplicate key ids are
  ``ValueError`` raised for the whole batch before storage is touched, and
  the caller's objects are never mutated;
* every item is checked against one committed snapshot after the whole store
  validates (even an unreferenced corrupt record is ``CorruptRecordError``):
  in request order key lookup, the ``expected_active`` precondition (active
  number only), target existence and the target's revocation flag; the first
  failure (KeyError / ActiveVersionConflictError / KeyError /
  RevokedVersionError) aborts before any mutation and keyring.json keeps its
  exact prior bytes;
* on success all active pointers move together in one atomic commit: no new
  versions, no decrypted material, other keys/histories/revocation flags
  untouched; an already-active target still passes through every check, and
  a batch that moves nothing never rewrites keyring.json;
* readers observe only the state before or after the whole batch; of two
  batches expecting the same old active on a shared key at most one commits;
* single-key ``set_active`` still accepts a revoked target; no CLI surface
  and no report change.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

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


class HappyPathTests(SetActiveBatchTestBase):
    def test_switches_several_keys_together_and_returns_none(self) -> None:
        first = self.ring.seal(KEY, "一", PASSWORD, iterations=200)
        self.ring.seal(KEY, "二", PASSWORD, iterations=200)
        other_first = self.ring.seal(OTHER, "甲")
        self.ring.seal(OTHER, "乙")
        result = self.ring.set_active_batch([
            {"key_id": KEY, "version": first, "expected_active": 2},
            {"key_id": OTHER, "version": other_first, "expected_active": 2},
        ])
        self.assertIsNone(result)
        self.assertEqual(self.ring.active(KEY), first)
        self.assertEqual(self.ring.active(OTHER), other_first)
        # No versions were appended and the materials still open as before.
        self.assertEqual(self.ring.versions(KEY), [first, first + 1])
        self.assertEqual(self.ring.versions(OTHER), [other_first, other_first + 1])
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), "一".encode("utf-8"))
        self.assertEqual(self.ring.load(OTHER), "甲".encode("utf-8"))

    def test_other_keys_histories_and_revocation_flags_untouched(self) -> None:
        first = self.ring.seal(KEY, "one")
        second = self.ring.seal(KEY, "two")
        bystander = self.ring.seal("z", "旁")
        self.ring.revoke(KEY, first)
        before = self._document()
        self.ring.set_active_batch([{"key_id": KEY, "version": second}])
        after = self._document()
        self.assertEqual(before["keys"]["z"], after["keys"]["z"])
        self.assertEqual(before["keys"][KEY]["versions"],
                         after["keys"][KEY]["versions"])
        self.assertTrue(self.ring.is_revoked(KEY, first))
        self.assertEqual(self.ring.active("z"), bystander)

    def test_sealed_targets_switch_without_any_password(self) -> None:
        # The batch never decrypts material: sealed keys switch with no
        # passphrase supplied anywhere.
        first = self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        self.ring.seal(KEY, "newer", PASSWORD, iterations=200)
        self.assertIsNone(self.ring.set_active_batch([{"key_id": KEY, "version": first}]))
        self.assertEqual(self.ring.active(KEY), first)
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), b"secret")

    def test_already_active_target_still_runs_every_check(self) -> None:
        self.ring.seal(KEY, "one")
        second = self.ring.seal(KEY, "two")
        before = self.ring.path.read_bytes()
        # Target == active and the precondition matches: a complete no-op
        # batch must not rewrite keyring.json.
        self.assertIsNone(self.ring.set_active_batch(
            [{"key_id": KEY, "version": second, "expected_active": second}]))
        self.assertEqual(self.ring.path.read_bytes(), before)
        # The precondition is still enforced for an already-active target.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch(
                [{"key_id": KEY, "version": second, "expected_active": second + 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_already_active_revoked_target_is_still_rejected(self) -> None:
        # Single set_active may point at a version that is later revoked; the
        # batch must still run its revocation check on such a target even
        # though switching to it would move nothing.
        first = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.set_active(KEY, first)
        self.ring.revoke(KEY, first)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.set_active_batch([{"key_id": KEY, "version": first}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_partial_noop_batch_commits_the_moving_items(self) -> None:
        first = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        other_first = self.ring.seal(OTHER, "甲")
        self.ring.seal(OTHER, "乙")
        # OTHER is already at its target; only KEY actually moves.
        self.assertIsNone(self.ring.set_active_batch([
            {"key_id": OTHER, "version": other_first + 1},
            {"key_id": KEY, "version": first},
        ]))
        self.assertEqual(self.ring.active(KEY), first)
        self.assertEqual(self.ring.active(OTHER), other_first + 1)

    def test_caller_input_is_not_mutated(self) -> None:
        first = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        requests = [{"key_id": KEY, "version": first, "expected_active": 2}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.set_active_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)
        self.assertEqual(
            requests, [{"key_id": KEY, "version": first, "expected_active": 2}])

    def test_key_names_are_not_normalised(self) -> None:
        lower = self.ring.seal("k", "lower")
        self.ring.seal("k", "lower-2")
        upper = self.ring.seal("K", "upper")
        self.ring.seal("K", "upper-2")
        self.assertIsNone(self.ring.set_active_batch([
            {"key_id": "k", "version": lower},
            {"key_id": "K", "version": upper},
        ]))
        self.assertEqual(self.ring.active("k"), lower)
        self.assertEqual(self.ring.active("K"), upper)
        self.assertEqual(self.ring.load("k"), b"lower")
        self.assertEqual(self.ring.load("K"), b"upper")


class InputValidationTests(SetActiveBatchTestBase):
    def _batch(self, requests):
        return self.ring.set_active_batch(requests)

    def test_outer_value_must_be_non_empty_list(self) -> None:
        for bad in (None, [], "x", {"key_id": KEY}, ({"key_id": KEY, "version": 1},), 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch(bad)

    def test_each_item_must_be_dict(self) -> None:
        for bad in (None, "x", 7, ["x"], (KEY, 1)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._batch([bad])

    def test_required_fields(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY}])
        with self.assertRaises(ValueError):
            self._batch([{"version": 1}])
        with self.assertRaises(ValueError):
            self._batch([{"key_id": True, "version": 1}])

    def test_unknown_fields_rejected(self) -> None:
        base = {"key_id": KEY, "version": 1}
        with self.assertRaises(ValueError):
            self._batch([{**base, "bogus": 1}])
        # Fields from other APIs are not allowed here either.
        with self.assertRaises(ValueError):
            self._batch([{**base, "password": "p"}])
        with self.assertRaises(ValueError):
            self._batch([{**base, "new_password": "x"}])
        # An unknown field is rejected even when a required one is missing.
        with self.assertRaises(ValueError):
            self._batch([{"key_id": KEY, "bogus": 1}])

    def test_field_value_rules(self) -> None:
        base = {"key_id": KEY, "version": 1}
        cases = (
            {"key_id": "", "version": 1},
            {"key_id": 1, "version": 1},
            {**base, "version": None},
            {**base, "version": 0},
            {**base, "version": -1},
            {**base, "version": "1"},
            {**base, "version": True},
            {**base, "version": 1.5},
            {**base, "expected_active": 0},
            {**base, "expected_active": -2},
            {**base, "expected_active": True},
            {**base, "expected_active": "2"},
            {**base, "expected_active": 1.5},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    self._batch([request])

    def test_expected_active_none_and_omitted_are_accepted(self) -> None:
        first = self.ring.seal(KEY, "one")
        self.ring.seal(KEY, "two")
        self.ring.set_active_batch([{"key_id": KEY, "version": first}])
        self.ring.set_active_batch(
            [{"key_id": KEY, "version": first + 1, "expected_active": None}])
        self.assertEqual(self.ring.active(KEY), first + 1)

    def test_duplicate_key_ids_are_value_errors(self) -> None:
        with self.assertRaises(ValueError):
            self._batch([{"key_id": "a", "version": 1}, {"key_id": "a", "version": 2}])
        # The comparison uses exact full strings: case-folded look-alikes are
        # different keys and must pass input validation.
        self.ring.seal("a", "x")
        self.ring.seal("A", "y")
        self.assertIsNone(
            self._batch([{"key_id": "a", "version": 1}, {"key_id": "A", "version": 1}]))

    def test_first_invalid_item_is_reported(self) -> None:
        self.ring.seal("a", "x")
        # Item 0 is structurally fine; item 1 is not a dict.
        with self.assertRaises(ValueError):
            self._batch([{"key_id": "a", "version": 1}, "not-a-dict"])
        # Item 0's bad value precedes item 1's duplicate.
        with self.assertRaisesRegex(ValueError, "version"):
            self._batch([{"key_id": "a", "version": 0},
                         {"key_id": "a", "version": 1}])

    def test_validation_precedes_storage_and_leaves_bytes_unchanged(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        bad_batches = (
            [],
            [{"key_id": "missing", "version": "1"}],
            [{"key_id": KEY, "version": None}],
            [{"key_id": KEY, "version": True}],
            [{"key_id": KEY, "version": 1, "expected_active": 0}],
            [{"key_id": KEY, "version": 1}, {"key_id": KEY, "version": 2}],
            [{"key_id": KEY, "version": 1, "nope": None}],
        )
        for requests in bad_batches:
            with self.subTest(requests=requests):
                with self.assertRaises(ValueError):
                    self._batch(requests)
                self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_input_on_missing_ring_is_value_error_not_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.set_active_batch([])
        with self.assertRaises(ValueError):
            ring.set_active_batch([{"key_id": KEY, "version": 0}])


class ErrorOrderTests(SetActiveBatchTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.first = self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        self.second = self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.other = self.ring.seal(OTHER, "别的")

    def test_unknown_key_is_keyerror_and_changes_nothing(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([{"key_id": "missing", "version": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_target_version_is_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([{"key_id": KEY, "version": 99}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_conflict_message_names_key_expected_and_actual(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.set_active_batch(
                [{"key_id": KEY, "version": self.first, "expected_active": self.first}])
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn(str(self.first), message)   # expected
        self.assertIn(str(self.second), message)  # actual
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), self.second)

    def test_conflict_even_when_expected_version_never_existed(self) -> None:
        # 99 is not in the history at all: still a conflict, not a KeyError.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch(
                [{"key_id": KEY, "version": self.first, "expected_active": 99}])

    def test_revoked_target_is_rejected_but_single_set_active_still_allows_it(self) -> None:
        self.ring.revoke(KEY, self.first)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.set_active_batch([{"key_id": KEY, "version": self.first}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # The single-key API keeps its old semantics: revoked targets allowed.
        self.ring.set_active(KEY, self.first)
        self.assertEqual(self.ring.active(KEY), self.first)

    def test_per_item_order_key_then_precondition_then_target(self) -> None:
        # Unknown key outranks a precondition that would also mismatch.
        with self.assertRaises(KeyError):
            self.ring.set_active_batch(
                [{"key_id": "missing", "version": 1, "expected_active": 99}])
        # A precondition mismatch outranks this item's unknown target version.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch(
                [{"key_id": KEY, "version": 99, "expected_active": 99}])

    def test_first_failing_item_in_request_order_is_reported(self) -> None:
        before = self.ring.path.read_bytes()
        # Item 0 conflicts; item 1 names an unknown key. Item 0's verdict wins.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.set_active_batch([
                {"key_id": KEY, "version": self.first, "expected_active": self.first},
                {"key_id": "no-such-key", "version": 1},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Reversed order: the unknown key is now encountered first.
        with self.assertRaises(KeyError):
            self.ring.set_active_batch([
                {"key_id": "no-such-key", "version": 1},
                {"key_id": KEY, "version": self.first, "expected_active": self.first},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_later_item_failure_aborts_earlier_successful_item(self) -> None:
        self.ring.revoke(KEY, self.first)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.RevokedVersionError):
            self.ring.set_active_batch([
                {"key_id": OTHER, "version": self.other, "expected_active": self.other},
                {"key_id": KEY, "version": self.first},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # No partial repoint of the earlier, otherwise fine item.
        self.assertEqual(self.ring.active(OTHER), self.other)
        self.assertEqual(self.ring.active(KEY), self.second)

    def test_unrequested_corrupt_record_fails_the_batch(self) -> None:
        document = self._document()
        document["keys"]["bystander"] = {
            "versions": [{"version": 1, "scheme": "no-such-scheme",
                          "revoked": False}],
            "active": 1}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.set_active_batch([{"key_id": KEY, "version": self.first}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_corrupt_keyring_is_corrupt_and_unchanged(self) -> None:
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.set_active_batch([{"key_id": KEY, "version": self.first}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_missing_ring_is_filenotfound(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaisesRegex(FileNotFoundError, "no key ring"):
            ring.set_active_batch([{"key_id": KEY, "version": 1}])

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
                self.ring.set_active_batch([{"key_id": KEY, "version": self.first}])
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)


class ConcurrencyTests(SetActiveBatchTestBase):
    def test_two_batches_expecting_same_old_active_at_most_one_succeeds(self) -> None:
        first = self.ring.seal(KEY, "one")
        second = self.ring.seal(KEY, "two")
        third = self.ring.seal(KEY, "three")
        self.ring.set_active(KEY, first)
        barrier = threading.Barrier(2)
        outcomes: list[BaseException | None] = []

        def worker(target: int) -> None:
            barrier.wait()
            try:
                self.ring.set_active_batch(
                    [{"key_id": KEY, "version": target, "expected_active": first}])
                outcomes.append(None)
            except BaseException as error:  # noqa: BLE001 - surfaced to assertions
                outcomes.append(error)

        threads = [threading.Thread(target=worker, args=(target,))
                   for target in (second, third)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())
        successes = [outcome for outcome in outcomes if outcome is None]
        conflicts = [outcome for outcome in outcomes
                     if isinstance(outcome, core.ActiveVersionConflictError)]
        # Both expect the same old active and aim at different targets: the
        # first commit invalidates the other's precondition.
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertIn(self.ring.active(KEY), (second, third))

    def test_load_batch_observes_only_whole_switches(self) -> None:
        # Two keys flip between (v1, v1) and (v2, v2) as one batch; a reader
        # must only ever load one of the two consistent combinations.
        self.ring.seal("a", "a1")
        self.ring.seal("a", "a2")
        self.ring.seal("b", "b1")
        self.ring.seal("b", "b2")
        self.ring.set_active_batch(
            [{"key_id": "a", "version": 1}, {"key_id": "b", "version": 1}])
        consistent = {(b"a1", b"b1"), (b"a2", b"b2")}
        stop = threading.Event()
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                for _ in range(30):
                    self.ring.set_active_batch(
                        [{"key_id": "a", "version": 2}, {"key_id": "b", "version": 2}])
                    self.ring.set_active_batch(
                        [{"key_id": "a", "version": 1}, {"key_id": "b", "version": 1}])
            except BaseException as error:  # noqa: BLE001
                errors.append(error)
            finally:
                stop.set()

        def reader() -> None:
            try:
                while not stop.is_set():
                    pair = tuple(self.ring.load_batch(
                        [{"key_id": "a"}, {"key_id": "b"}]))
                    self.assertIn(pair, consistent)
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        writer_thread = threading.Thread(target=writer)
        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        writer_thread.start()
        writer_thread.join(timeout=60)
        self.assertFalse(writer_thread.is_alive())
        stop.set()
        reader_thread.join(timeout=10)
        self.assertFalse(reader_thread.is_alive())
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
