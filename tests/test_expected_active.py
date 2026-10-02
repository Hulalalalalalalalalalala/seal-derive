"""Tests for the ``expected_active`` precondition on password rotation.

Acceptance surface (single ``rotate_password`` and ``rotate_password_batch``):
* omitted or ``None`` disables the precondition and keeps the old behaviour;
* any other value must be a non-bool positive int, validated before storage
  is touched (``ValueError``), also when the ring directory is missing;
* when pinned it compares only the entry's current active version number --
  not the source version and not the whole history; a mismatch raises
  ``ActiveVersionConflictError`` (importable from ``seal_derive.core``,
  subclass of ``SealError``, message names the key and both versions) even
  when the expected version does not exist;
* per item the order is key existence, then the precondition, then source
  resolution/authentication, so a conflict beats that item's unknown
  source, revocation and passphrase failures but never an earlier item's
  failure; an unknown key stays ``KeyError``;
* every failure leaves keyring.json bytes, history, active and revocation
  untouched; success still preserves the material bytes under a fresh v2
  record;
* two concurrent requests pinning the same initial active serialise:
  exactly one succeeds, the other conflicts;
* the CLI gains ``--expected-active``: success still prints only
  ``<version>\\n``; a conflict empties stdout, names the conflict on stderr
  and exits 1; illegal arguments exit 2.

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


class ErrorTypeTests(ExpectedActiveTestBase):
    def test_importable_and_is_a_seal_error(self) -> None:
        self.assertTrue(issubclass(core.ActiveVersionConflictError, core.SealError))
        self.assertTrue(issubclass(core.ActiveVersionConflictError, ValueError))

    def test_message_names_key_expected_and_actual(self) -> None:
        first = self.ring.seal(KEY, "one", PASSWORD, iterations=200)
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.assertEqual(self.ring.active(KEY), second)
        with self.assertRaisesRegex(core.ActiveVersionConflictError, "活动版本冲突") as ctx:
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=200,
                expected_active=first)
        message = str(ctx.exception)
        self.assertIn(KEY, message)
        self.assertIn(str(first), message)
        self.assertIn(str(second), message)


class SingleRotateHappyPathTests(ExpectedActiveTestBase):
    def test_matching_precondition_rotates(self) -> None:
        source = self.ring.seal(KEY, "材料", PASSWORD, iterations=200)
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, iterations=200,
            expected_active=source)
        self.assertEqual(new_version, source + 1)
        self.assertEqual(self.ring.active(KEY), new_version)
        self.assertEqual(
            self.ring.load(KEY, password=NEW_PASSWORD), "材料".encode("utf-8"))
        self.assertFalse(self.ring.is_revoked(KEY, source))

    def test_none_explicit_and_omitted_keep_old_behaviour(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        first = self.ring.rotate_password(
            KEY, "n1", password=PASSWORD, iterations=200, expected_active=None)
        # Active is now sealed under "n1"; chaining without a precondition
        # still works exactly as before.
        second = self.ring.rotate_password(
            KEY, "n2", password="n1", iterations=200)
        self.assertEqual((first, second), (2, 3))

    def test_compares_active_not_source_version(self) -> None:
        # Source is an older non-active version; the precondition only has to
        # match the current active pointer, not the source being opened.
        first = self.ring.seal(KEY, "一", PASSWORD, iterations=200)
        second = self.ring.seal(KEY, "二", PASSWORD, iterations=200)
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=first, iterations=200,
            expected_active=second)
        self.assertEqual(new_version, 3)
        self.assertEqual(
            self.ring.load(KEY, version=new_version, password=NEW_PASSWORD),
            "一".encode("utf-8"))
        self.assertEqual(self.ring.active(KEY), new_version)

    def test_unicode_key_name_in_conflict_message(self) -> None:
        self.ring.seal(OTHER, "材料", PASSWORD, iterations=200)
        with self.assertRaisesRegex(core.ActiveVersionConflictError, OTHER):
            self.ring.rotate_password(
                OTHER, NEW_PASSWORD, password=PASSWORD, iterations=200,
                expected_active=99)

    def test_empty_password_round_trip_with_precondition(self) -> None:
        source = self.ring.seal(KEY, "", PASSWORD, iterations=200)
        new_version = self.ring.rotate_password(
            KEY, "", password=PASSWORD, iterations=200, expected_active=source)
        self.assertEqual(
            self.ring.load(KEY, version=new_version, password=""), b"")


class SingleRotateValidationTests(ExpectedActiveTestBase):
    def test_bad_values_are_value_errors(self) -> None:
        for bad in (0, -1, True, False, "1", 1.5, b"1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(
                        KEY, NEW_PASSWORD, expected_active=bad)  # type: ignore[arg-type]

    def test_validation_happens_before_storage_is_touched(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        for bad in (0, -3, True, "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password(
                        KEY, NEW_PASSWORD, iterations=200, expected_active=bad)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_invalid_precondition_on_missing_ring_is_value_error(self) -> None:
        ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            ring.rotate_password(KEY, NEW_PASSWORD, expected_active=True)
        self.assertFalse((self.root / "never-initialised").exists())


class SingleRotateOrderAndAtomicityTests(ExpectedActiveTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.sealed = self.ring.seal(KEY, "secret", PASSWORD, iterations=200)

    def _assert_unchanged(self, before: bytes, active: int) -> None:
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), active)
        self.assertEqual(self.ring.versions(KEY), [self.sealed])
        self.assertFalse(self.ring.is_revoked(KEY, self.sealed))

    def test_unknown_key_stays_keyerror(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rotate_password(
                "missing", NEW_PASSWORD, expected_active=self.sealed)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_conflict_when_expected_version_does_not_exist(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=200,
                expected_active=999)
        self._assert_unchanged(before, self.sealed)

    def test_conflict_beats_unknown_source_version(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, version=77,
                iterations=200, expected_active=999)
        self._assert_unchanged(before, self.sealed)

    def test_conflict_beats_revoked_source(self) -> None:
        self.ring.revoke(KEY, self.sealed)  # active still points at revoked v1
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password=PASSWORD, iterations=200,
                expected_active=999)
        # Bytes (including the pre-existing revocation), active and history
        # are preserved; nothing got appended or un-revoked.
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), self.sealed)
        self.assertEqual(self.ring.versions(KEY), [self.sealed])
        self.assertTrue(self.ring.is_revoked(KEY, self.sealed))

    def test_conflict_beats_missing_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, iterations=200, expected_active=999)
        self._assert_unchanged(before, self.sealed)

    def test_conflict_beats_bad_password(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password(
                KEY, NEW_PASSWORD, password="wrong", iterations=200,
                expected_active=999)
        self._assert_unchanged(before, self.sealed)

    def test_conflict_after_active_moved_by_earlier_rotation(self) -> None:
        # A stale caller pinned the initial active; an intervening rotation
        # repoints active. The stale caller's source (plain v1) would still
        # open and its passphrase would be right -- the conflict must win.
        self.ring.set_active(KEY, self.sealed)
        winner = self.ring.rotate_password(
            KEY, "winner-pw", password=PASSWORD, iterations=200,
            expected_active=self.sealed)
        before = self.ring.path.read_bytes()
        with self.assertRaisesRegex(core.ActiveVersionConflictError, "活动版本冲突"):
            self.ring.rotate_password(
                KEY, "stale-pw", password=PASSWORD, iterations=200,
                expected_active=self.sealed)
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.active(KEY), winner)

    def test_precondition_does_not_care_about_history_otherwise(self) -> None:
        # Pin active to its current value after history grew: set_active back
        # to an older version makes active move without any seal; pinning the
        # real current active must still pass even though history is "newer".
        second = self.ring.seal(KEY, "two", PASSWORD, iterations=200)
        self.ring.set_active(KEY, self.sealed)
        new_version = self.ring.rotate_password(
            KEY, NEW_PASSWORD, password=PASSWORD, version=second, iterations=200,
            expected_active=self.sealed)
        self.assertEqual(self.ring.active(KEY), new_version)


class BatchPreconditionTests(ExpectedActiveTestBase):
    def test_matching_preconditions_rotate_whole_batch(self) -> None:
        k1v = self.ring.seal(KEY, "材料-α")
        k2v = self.ring.seal(OTHER, "材料-β", PASSWORD, iterations=200)
        numbers = self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": "n1", "expected_active": k1v},
            {"key_id": OTHER, "new_password": "n2", "password": PASSWORD,
             "iterations": 200, "expected_active": k2v},
        ])
        self.assertEqual(numbers, [k1v + 1, k2v + 1])
        self.assertEqual(self.ring.active(KEY), k1v + 1)
        self.assertEqual(self.ring.active(OTHER), k2v + 1)

    def test_none_and_omitted_keep_behaviour(self) -> None:
        self.ring.seal(KEY, "secret")
        numbers = self.ring.rotate_password_batch([
            {"key_id": KEY, "new_password": "n1", "expected_active": None},
        ])
        self.assertEqual(numbers, [2])
        # Omitted precondition: pin the still-open plain v1 source.
        [number] = self.ring.rotate_password_batch(
            [{"key_id": KEY, "new_password": "n2", "version": 1}])
        self.assertEqual(number, 3)

    def test_conflict_beats_that_items_source_failures(self) -> None:
        sealed = self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        cases = (
            {"key_id": KEY, "new_password": "x", "version": 77,
             "iterations": 200, "expected_active": 999},
            {"key_id": KEY, "new_password": "x", "iterations": 200,
             "expected_active": 999},
            {"key_id": KEY, "new_password": "x", "password": "wrong",
             "iterations": 200, "expected_active": 999},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(core.ActiveVersionConflictError):
                    self.ring.rotate_password_batch([request])
                self.assertEqual(self.ring.active(KEY), sealed)
                self.assertEqual(self.ring.versions(KEY), [sealed])

    def test_conflict_beats_revoked_source_in_batch(self) -> None:
        sealed = self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        self.ring.revoke(KEY, sealed)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "x", "password": PASSWORD,
                 "iterations": 200, "expected_active": 999}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_key_in_batch_is_not_a_conflict(self) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(KeyError):
            self.ring.rotate_password_batch([
                {"key_id": "missing", "new_password": "x",
                 "expected_active": 1}])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_earlier_item_failure_precedes_later_conflict(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        self.ring.seal(OTHER, "别的", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.BadPasswordError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "x", "password": "wrong",
                 "iterations": 200},
                {"key_id": OTHER, "new_password": "x", "password": PASSWORD,
                 "iterations": 200, "expected_active": 999},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_earlier_conflict_precedes_later_item_failure(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "x", "password": PASSWORD,
                 "iterations": 200, "expected_active": 999},
                {"key_id": "no-such-key", "new_password": "x"},
            ])
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_later_conflict_aborts_earlier_successful_item(self) -> None:
        other_v = self.ring.seal(OTHER, "别的", PASSWORD, iterations=200)
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.ActiveVersionConflictError):
            self.ring.rotate_password_batch([
                {"key_id": OTHER, "new_password": "ok", "password": PASSWORD,
                 "iterations": 200, "revoke_source": True,
                 "expected_active": other_v},
                {"key_id": KEY, "new_password": "x", "password": PASSWORD,
                 "iterations": 200, "expected_active": 999},
            ])
        # No partial append, revocation or active repoint.
        self.assertEqual(self.ring.path.read_bytes(), before)
        self.assertEqual(self.ring.versions(OTHER), [other_v])
        self.assertEqual(self.ring.active(OTHER), other_v)
        self.assertFalse(self.ring.is_revoked(OTHER, other_v))

    def test_batch_field_validation(self) -> None:
        self.ring.seal(KEY, "secret")
        base = {"key_id": KEY, "new_password": "x"}
        for bad in (0, -1, True, "1", 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.ring.rotate_password_batch(
                        [{**base, "expected_active": bad}])

    def test_duplicate_key_ids_still_rejected_with_precondition(self) -> None:
        with self.assertRaises(ValueError):
            self.ring.rotate_password_batch([
                {"key_id": KEY, "new_password": "a", "expected_active": 1},
                {"key_id": KEY, "new_password": "b", "expected_active": 1},
            ])

    def test_caller_input_is_not_mutated(self) -> None:
        self.ring.seal(KEY, "secret")
        requests = [{"key_id": KEY, "new_password": NEW_PASSWORD,
                     "expected_active": 1}]
        snapshot = json.dumps(requests, ensure_ascii=False)
        self.ring.rotate_password_batch(requests)
        self.assertEqual(json.dumps(requests, ensure_ascii=False), snapshot)


class ConcurrencyTests(ExpectedActiveTestBase):
    def test_two_pinned_requests_exactly_one_succeeds(self) -> None:
        # Five rounds: in every round two callers pin that round's initial
        # active and open the always-available plain v1 source. Exactly one
        # rotation commits per round, so active advances by one and the loser
        # sees ActiveVersionConflictError (the stale snapshot fails the
        # precondition before its source is even resolved).
        self.ring.seal(KEY, "secret")
        successes = 0
        conflicts = 0
        for round_number in range(5):
            pinned = self.ring.active(KEY)
            barrier = threading.Barrier(2)
            outcomes: list[object] = []
            lock = threading.Lock()

            def worker(suffix: str) -> None:
                barrier.wait()
                try:
                    number = self.ring.rotate_password(
                        KEY, f"pw-{round_number}-{suffix}", version=1,
                        iterations=200, expected_active=pinned)
                    with lock:
                        outcomes.append(("ok", number))
                except core.ActiveVersionConflictError as error:
                    with lock:
                        outcomes.append(("conflict", error))

            threads = [threading.Thread(target=worker, args=(s,))
                       for s in ("a", "b")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
                self.assertFalse(thread.is_alive())
            kinds = [kind for kind, _ in outcomes]
            self.assertEqual(sorted(kinds), ["conflict", "ok"])
            successes += kinds.count("ok")
            conflicts += kinds.count("conflict")
            # Exactly one new version committed, now active.
            self.assertEqual(self.ring.active(KEY), pinned + 1)
        self.assertEqual((successes, conflicts), (5, 5))
        self.assertEqual(self.ring.versions(KEY), [1, 2, 3, 4, 5, 6])
        # Every produced version is unrevoked; the plain v1 source survives.
        document = self._document()
        for item in document["keys"][KEY]["versions"]:
            self.assertFalse(item["revoked"])
        self.assertEqual(self.ring.load(KEY, version=1), b"secret")

    def test_two_pinned_sealed_requests_exactly_one_succeeds(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        barrier = threading.Barrier(2)
        outcomes: list[object] = []
        lock = threading.Lock()

        def worker(suffix: str) -> None:
            barrier.wait()
            try:
                number = self.ring.rotate_password(
                    KEY, f"new-{suffix}", password=PASSWORD, iterations=200,
                    expected_active=1)
                with lock:
                    outcomes.append(("ok", number))
            except core.ActiveVersionConflictError:
                with lock:
                    outcomes.append(("conflict", None))

        threads = [threading.Thread(target=worker, args=(s,)) for s in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(kind for kind, _ in outcomes),
                         ["conflict", "ok"])
        self.assertEqual(self.ring.versions(KEY), [1, 2])
        self.assertEqual(self.ring.active(KEY), 2)


class CliTests(ExpectedActiveTestBase):
    def test_success_with_expected_active(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        result = self._run_cli(
            "rotate-password", KEY, "--new-password", NEW_PASSWORD,
            "--password", PASSWORD, "--iterations", "200",
            "--expected-active", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2\n")
        self.assertEqual(result.stderr, "")

    def test_conflict_is_exit_one_with_empty_stdout(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        self._run_cli(
            "rotate-password", KEY, "--new-password", "first",
            "--password", PASSWORD, "--iterations", "200",
            "--expected-active", "1")
        result = self._run_cli(
            "rotate-password", KEY, "--new-password", "stale",
            "--password", PASSWORD, "--iterations", "200",
            "--expected-active", "1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("活动版本冲突", result.stderr)
        self.assertIn(KEY, result.stderr)
        self.assertIn("1", result.stderr)
        self.assertIn("2", result.stderr)

    def test_illegal_expected_active_is_exit_two(self) -> None:
        self.ring.seal(KEY, "secret")
        # Non-integer token: argparse usage error.
        result = self._run_cli(
            "rotate-password", KEY, "--new-password", "x",
            "--expected-active", "abc")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        # Integer token but semantically invalid (zero): core ValueError.
        result = self._run_cli(
            "rotate-password", KEY, "--new-password", "x",
            "--expected-active", "0")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_other_commands_and_report_unchanged(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=200)
        self.assertEqual(
            self._run_cli("active", KEY).stdout.strip(), "1")
        report = self._run_cli("report")
        self.assertEqual(report.returncode, 0, report.stderr)
        payload = json.loads(report.stdout)
        self.assertEqual(payload["domain"], "key-management")
        self.assertEqual(payload["components"], ["keyring", "derive"])
        self.assertEqual(
            payload["readiness"],
            {"seal": True, "rotate": True, "revoke": True,
             "constantTime": False})


if __name__ == "__main__":
    unittest.main()
