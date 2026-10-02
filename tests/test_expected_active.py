"""Tests for the ``expected_active`` precondition on password rotation.

Acceptance surface:
* ``rotate_password(..., expected_active=...)`` and per-item
  ``expected_active`` in ``rotate_password_batch`` compare only the key's
  current active version number; ``None``/omitted keeps the old behaviour,
  anything else must be a non-bool positive integer or ``ValueError`` is
  raised before storage is touched;
* a mismatch raises ``seal_derive.core.ActiveVersionConflictError`` (a
  ``SealError``) naming the key, the expected and the actual active version,
  whether or not the expected version exists; the check follows the key
  lookup and precedes that item's source/revocation/passphrase failures, but
  never an earlier batch item's failure;
* condition and rotation commit atomically: of two concurrent rotations
  expecting the same initial active version, exactly one succeeds;
* any precondition failure leaves keyring.json byte-for-byte unchanged and
  returns no partial result;
* the CLI accepts ``--expected-active``: success prints only the version,
  a conflict exits 1 with an empty stdout, illegal values exit 2.

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
KEY = "k"
OTHER = "别的键"
PASSWORD = "correct horse"
NEW_PASSWORD = "battery staple"


class ExpectedActiveTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30)


class SingleRotationPreconditionTests(ExpectedActiveTestBase):
    def test_matching_precondition_rotates(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000,
            expected_active=source)
        self.assertEqual(new_version, source + 1)
        self.assertEqual(self.ring.active(KEY), new_version)
        self.assertEqual(
            self.ring.load(KEY, password=NEW_PASSWORD), b"secret")

    def test_omitted_and_none_keep_unconditional_behaviour(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        self.ring.seal(KEY, "two", PASSWORD, iterations=1_000)
        # Active is 2; rotating the non-active v1 without a precondition works.
        rotated = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=first, iterations=1_000)
        self.assertEqual(rotated, 3)
        rotated = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=first,
            iterations=1_000, expected_active=None)
        self.assertEqual(rotated, 4)

    def test_precondition_compares_active_not_source_version(self) -> None:
        self.ring.seal(KEY, "one", PASSWORD, iterations=1_000)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=1_000)
        # Source is the non-active v1; the precondition is about active (v2).
        rotated = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=1, iterations=1_000,
            expected_active=second)
        self.assertEqual(self.ring.load(KEY, version=rotated, password=NEW_PASSWORD),
                         "one".encode("utf-8"))

    def test_mismatch_raises_conflict_and_changes_nothing(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000,
                expected_active=source + 5)
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn(str(source + 5), message)  # expected
        self.assertIn(str(source), message)      # actual
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.versions(KEY), [source])
        self.assertEqual(self.ring.active(KEY), source)

    def test_conflict_is_a_seal_error_importable_from_core(self) -> None:
        self.assertTrue(issubclass(core.ActiveVersionConflictError, core.SealError))
        from seal_derive.core import ActiveVersionConflictError
        self.assertIs(ActiveVersionConflictError, core.ActiveVersionConflictError)

    def test_conflict_even_when_expected_version_never_existed(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        # 99 is not in the history at all: still a conflict, not a KeyError.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000,
                expected_active=99)

    def test_unknown_key_is_keyerror_even_with_precondition(self) -> None:
        with self.assertRaises(KeyError):
            self.ring.rotate_password(
                "missing", NEW_PASSWORD, expected_active=1)

    def test_conflict_precedes_unknown_source_version(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, version=99,
                iterations=1_000, expected_active=7)

    def test_conflict_precedes_revoked_source(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.ring.revoke(KEY, source)
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=1_000,
                expected_active=source + 1)

    def test_conflict_precedes_password_failures(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password="wrong", iterations=1_000,
                expected_active=7)
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, iterations=1_000, expected_active=7)

    def test_invalid_expected_active_is_value_error_before_storage(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        for bad in (0, -1, True, False, "2", 1.5, b"1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(
                        KEY, NEW_PASSWORD, expected_active=bad)  # type: ignore[arg-type]
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_expected_active_on_missing_ring_is_value_error(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.rotate_password(KEY, NEW_PASSWORD, expected_active=0)

    def test_unicode_key_name_in_conflict_message(self) -> None:
        key = "键-😀"
        self.ring.seal(key, "材料", PASSWORD, iterations=1_000)
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.rotate_password(
                key, NEW_PASSWORD, password=PASSWORD, iterations=1_000,
                expected_active=2)
        self.assertIn("活动版本冲突", str(caught.exception))
        self.assertIn(key, str(caught.exception))


class BatchPreconditionTests(ExpectedActiveTestBase):
    def test_matching_preconditions_rotate_together(self) -> None:
        first = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        other = self.ring.seal(OTHER, "别的", PASSWORD, iterations=1_000)
        numbers = self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": NEW_PASSWORD, "password": PASSWORD,
             "iterations": 1_000, "expected_active": first},
            {"key_id": OTHER, "new_password": "n2", "password": PASSWORD,
             "iterations": 1_000, "expected_active": other},
        ])
        self.assertEqual(numbers, [first + 1, other + 1])
        self.assertEqual(self.ring.load(KEY, password=NEW_PASSWORD), b"secret")
        self.assertEqual(self.ring.load(OTHER, password="n2"), "别的".encode("utf-8"))

    def test_items_without_precondition_are_unconditional(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.ring.seal(OTHER, "别的", PASSWORD, iterations=1_000)
        numbers = self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": "n1", "password": PASSWORD,
             "iterations": 1_000, "expected_active": None},
            {"key_id": OTHER, "new_password": "n2", "password": PASSWORD,
             "iterations": 1_000},
        ])
        self.assertEqual(numbers, [2, 2])

    def test_mismatch_aborts_whole_batch_without_partial_results(self) -> None:
        first = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        other = self.ring.seal(OTHER, "别的", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "n1", "password": PASSWORD,
                 "iterations": 1_000, "expected_active": first,
                 "revoke_source": True},
                {"key_id": OTHER, "new_password": "n2", "password": PASSWORD,
                 "iterations": 1_000, "expected_active": other + 3},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.versions(KEY), [first])
        self.assertEqual(self.ring.active(KEY), first)
        self.assertFalse(self.ring.is_revoked(KEY, first))
        self.assertEqual(self.ring.versions(OTHER), [other])

    def test_conflict_message_names_key_expected_and_actual(self) -> None:
        self.ring.seal(KEY, "secret")
        with self.assertRaises(core.ActiveVersionConflictError) as caught:
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "n", "expected_active": 9}])
        message = str(caught.exception)
        self.assertIn("活动版本冲突", message)
        self.assertIn(repr(KEY), message)
        self.assertIn("9", message)
        self.assertIn("1", message)

    def test_conflict_precedes_items_own_source_failures(self) -> None:
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.ring.revoke(KEY, source)
        # Revoked source AND wrong password AND unknown explicit version all
        # lose to the precondition of the same item.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "n", "password": "wrong",
                 "iterations": 1_000, "expected_active": 5}])
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "n", "password": PASSWORD,
                 "version": 99, "iterations": 1_000, "expected_active": 5}])

    def test_earlier_items_failure_wins_over_later_conflict(self) -> None:
        first = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.ring.seal(OTHER, "别的", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        # Item 0 fails its passphrase; item 1 would conflict. Item 0 wins.
        with self.assertRaises(core.BadPasswordError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "n", "password": "wrong",
                 "iterations": 1_000, "expected_active": first},
                {"key_id": OTHER, "new_password": "n", "password": PASSWORD,
                 "iterations": 1_000, "expected_active": 99},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Reversed order: now the conflict is encountered first.
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password_batch([
                {"key_id": OTHER, "new_password": "n", "password": PASSWORD,
                 "iterations": 1_000, "expected_active": 99},
                {"key_id": KEY, "new_password": "n", "password": "wrong",
                 "iterations": 1_000, "expected_active": first},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_key_is_keyerror_before_precondition(self) -> None:
        with self.assertRaises(KeyError):
            self.ring.rotate_password_batch([
                {"key_id": "missing", "new_password": "n", "expected_active": 1}])

    def test_invalid_expected_active_values_are_value_errors(self) -> None:
        self.ring.seal(KEY, "secret")
        before = self.ring.path.read_bytes()
        for bad in (0, -3, True, False, "1", 2.5, b"1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password_batch([
                        {"key_id": KEY, "new_password": "n",
                         "expected_active": bad}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_expected_active_on_missing_ring_is_value_error(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "n", "expected_active": 0}])

    def test_caller_input_with_precondition_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "secret")
        requests = [{"key_id": KEY, "new_password": "n", "expected_active": 1}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.rotate_password_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)

    def test_duplicate_key_id_still_rejected_with_preconditions(self) -> None:
        self.ring.seal(KEY, "secret")
        with self.assertRaises(ValueError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "n", "expected_active": 1},
                {"key_id": KEY, "new_password": "m", "expected_active": 1},
            ])


class ConcurrencyPreconditionTests(ExpectedActiveTestBase):
    def test_only_one_of_two_competing_rotations_succeeds(self) -> None:
        # Both rotations expect the initial active version and both sources
        # are openable; with no other writes, exactly one may commit.
        source = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        count = 6
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        successes: dict[int, str] = {}
        conflicts: list[BaseException] = []
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                number = self.ring.rotate_password(
                    KEY, f"pw-{i}", password=PASSWORD, iterations=1_000,
                    expected_active=source)
                with lock:
                    successes[number] = f"pw-{i}"
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
        winner, winner_password = next(iter(successes.items()))
        self.assertEqual(self.ring.active(KEY), winner)
        self.assertEqual(self.ring.versions(KEY), [source, winner])
        self.assertEqual(
            self.ring.load(KEY, version=winner, password=winner_password),
            b"secret")


class CliPreconditionTests(ExpectedActiveTestBase):
    def test_success_with_matching_expected_active(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        result = self._run_cli(
            "rotate-password", KEY, "--new-password", NEW_PASSWORD,
            "--password", PASSWORD, "--iterations", "1000",
            "--expected-active", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2\n")
        self.assertEqual(result.stderr, "")

    def test_conflict_exits_one_with_empty_stdout(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        result = self._run_cli(
            "rotate-password", KEY, "--new-password", NEW_PASSWORD,
            "--password", PASSWORD, "--iterations", "1000",
            "--expected-active", "7")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("活动版本冲突", result.stderr)
        self.assertIn(KEY, result.stderr)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_illegal_expected_active_exits_two(self) -> None:
        self.ring.seal(KEY, "secret")
        for value in ("0", "-2"):
            with self.subTest(value=value):
                result = self._run_cli(
                    "rotate-password", KEY, "--new-password", "x",
                    "--expected-active", value)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
        # A non-integer value is rejected by argparse itself.
        result = self._run_cli(
            "rotate-password", KEY, "--new-password", "x",
            "--expected-active", "abc")
        self.assertEqual(result.returncode, 2)

    def test_omitted_expected_active_behaves_as_before(self) -> None:
        self.ring.seal(KEY, "secret")
        result = self._run_cli("rotate-password", KEY, "--new-password", "x")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2\n")


if __name__ == "__main__":
    unittest.main()
