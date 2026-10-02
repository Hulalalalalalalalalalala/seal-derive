"""Tests for ``KeyRing.rotate_password_batch``.

Acceptance surface:
* the batch is a non-empty list of dictionaries; ``key_id``/``new_password``
  are required, only ``password``/``version``/``iterations``/``revoke_source``
  are allowed otherwise, defaults and types mirror ``rotate_password``, and a
  key name may appear at most once -- every violation is ``ValueError`` and
  whole-batch validation precedes any storage access; the caller's objects
  are never mutated;
* every source is taken from one committed snapshot (active by default;
  plain ignores the old password, v1/v2 authenticate with ``load`` semantics),
  the recovered bytes become a fresh v2 record (new salt, requested
  iterations, tag bound to the full key name and the new version), the new
  version is per-key max+1, unrevoked and active, and only that item's
  ``revoke_source`` revokes its source;
* failures are reported in request order (KeyError / Revoked /
  Unrecoverable / Missing / Bad / Corrupt), the whole store is validated
  first, and any failure leaves keyring.json byte-identical with no partial
  results;
* success returns the new version numbers in request order via one atomic
  commit, so concurrent callers only ever see pre- or post-batch state and a
  concurrent seal never loses history; lock waits past five seconds raise
  TimeoutError;
* no CLI/report surface is added or changed.

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

    def _record(self, key: str, version: int) -> dict:
        for item in self._document()["keys"][key]["versions"]:
            if item["version"] == version:
                return item
        raise KeyError((key, version))

    def _replace_with_v1(self, key: str, version: int, plaintext: bytes,
                         password: str = PASSWORD) -> None:
        document = self._document()
        record = next(item for item in document["keys"][key]["versions"]
                      if item["version"] == version)
        salt = base64.b64decode(record["salt"])
        iterations = record["iterations"]
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
    def test_mixed_plain_v1_v2_sources_commit_together(self) -> None:
        plain_v = self.ring.seal("plain-key", "材料-plain")
        v2_v = self.ring.seal("v2-key", "材料-v2", PASSWORD, iterations=1_000)
        legacy_v = self.ring.seal("v1-key", "材料-v1", PASSWORD, iterations=1_000)
        self._replace_with_v1("v1-key", legacy_v, "材料-v1".encode("utf-8"))

        results = self.ring.rotate_password_batch([
            {"key_id": "plain-key", "new_password": "np-1"},
            {"key_id": "v2-key", "new_password": "np-2",
             "password": PASSWORD, "iterations": 2_000},
            {"key_id": "v1-key", "new_password": "np-3",
             "password": PASSWORD, "iterations": 1_000},
        ])
        self.assertEqual(results, [plain_v + 1, v2_v + 1, legacy_v + 1])
        for key, new_version, old_source, new_pw, material in (
            ("plain-key", results[0], plain_v, "np-1", "材料-plain"),
            ("v2-key", results[1], v2_v, "np-2", "材料-v2"),
            ("v1-key", results[2], legacy_v, "np-3", "材料-v1"),
        ):
            record = self._record(key, new_version)
            self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
            self.assertFalse(record["revoked"])
            self.assertEqual(self.ring.active(key), new_version)
            self.assertEqual(self.ring.load(key, version=new_version, password=new_pw),
                             material.encode("utf-8"))
            self.assertFalse(self.ring.is_revoked(key, old_source))
        # The v1 source record is not upgraded or rewritten.
        self.assertEqual(self._record("v1-key", legacy_v)["scheme"], core.SEALED_SCHEME)
        # Fresh salts for the sealed sources; plain records carry no salt.
        for key, new_version, old_source in (
            ("v2-key", results[1], v2_v),
            ("v1-key", results[2], legacy_v),
        ):
            self.assertNotEqual(self._record(key, new_version)["salt"],
                                self._record(key, old_source)["salt"])

    def test_defaults_match_rotate_password(self) -> None:
        source = self.ring.seal(KEY := "k", "secret")
        results = self.ring.rotate_password_batch([{"key_id": KEY, "new_password": ""}])
        self.assertEqual(results, [source + 1])
        record = self._record(KEY, results[0])
        self.assertEqual(record["iterations"], 200_000)
        self.assertFalse(record["revoked"])
        # Plain source, default (active) version, empty new password all work.
        self.assertEqual(self.ring.load(KEY, version=results[0], password=""), b"secret")
        self.assertEqual(self.ring.active(KEY), results[0])

    def test_explicit_version_iterations_and_revoke_source(self) -> None:
        first = self.ring.seal("k", "一", PASSWORD, iterations=1_000)
        second = self.ring.seal("k", "二", PASSWORD, iterations=1_000)
        other = self.ring.seal("other", "别的", iterations=1_000)
        results = self.ring.rotate_password_batch([
            {"key_id": "k", "new_password": "nk", "password": PASSWORD,
             "version": first, "iterations": 4_000, "revoke_source": True},
            {"key_id": "other", "new_password": "no", "revoke_source": True},
        ])
        self.assertEqual(results, [3, other + 1])
        # The new copy carries the explicitly chosen (non-active) source.
        self.assertEqual(self.ring.load("k", version=results[0], password="nk"),
                         "一".encode("utf-8"))
        self.assertEqual(self._record("k", results[0])["iterations"], 4_000)
        self.assertTrue(self.ring.is_revoked("k", first))
        self.assertFalse(self.ring.is_revoked("k", second))
        self.assertFalse(self.ring.is_revoked("k", results[0]))
        # Only each item's own source is revoked; active still repoints.
        self.assertTrue(self.ring.is_revoked("other", other))
        self.assertEqual(self.ring.active("k"), results[0])
        self.assertEqual(self.ring.active("other"), results[1])
        # Unrelated versions remain readable.
        self.assertEqual(self.ring.load("k", version=second, password=PASSWORD),
                         "二".encode("utf-8"))

    def test_repeated_batches_keep_versions_gapless_per_key(self) -> None:
        self.ring.seal("a", "ma", PASSWORD, iterations=1_000)
        self.ring.seal("b", "mb", iterations=1_000)
        first = self.ring.rotate_password_batch([
            {"key_id": "a", "new_password": "a2", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": "b", "new_password": "b2"},
        ])
        second = self.ring.rotate_password_batch([
            {"key_id": "b", "new_password": "b3", "password": "b2",
             "iterations": 1_000},
            {"key_id": "a", "new_password": "a3", "password": "a2",
             "iterations": 1_000},
        ])
        self.assertEqual(first, [2, 2])
        self.assertEqual(second, [3, 3])
        self.assertEqual(self.ring.versions("a"), [1, 2, 3])
        self.assertEqual(self.ring.versions("b"), [1, 2, 3])
        self.assertEqual(self.ring.load("a", password="a3"), b"ma")
        self.assertEqual(self.ring.load("b", password="b3"), b"mb")

    def test_empty_and_unicode_materials_and_passwords(self) -> None:
        cases = {"empty": "", "emoji": "😀‍‍", "acute": "é" * 100}
        for name, material in cases.items():
            self.ring.seal(name, material, PASSWORD, iterations=1_000)
        requests = [{"key_id": name, "new_password": f"pw-{name}",
                     "password": PASSWORD, "iterations": 1_000}
                    for name in cases]
        results = self.ring.rotate_password_batch(requests)
        for (name, material), new_version in zip(cases.items(), results):
            self.assertEqual(
                self.ring.load(name, version=new_version, password=f"pw-{name}"),
                material.encode("utf-8"))
        # Empty new password on a plain empty material.
        self.ring.seal("void", "")
        number = self.ring.rotate_password_batch([{"key_id": "void", "new_password": ""}])[0]
        self.assertEqual(self.ring.load("void", version=number, password=""), b"")

    def test_full_string_key_names_stay_distinct(self) -> None:
        names = ("中文键", "键 😀/a|b\\", "  ", "caf" + chr(0xE9),
                 "caf" + chr(0x65) + chr(0x301))
        for index, name in enumerate(names):
            self.ring.seal(name, f"m{index}", PASSWORD, iterations=1_000)
        results = self.ring.rotate_password_batch([
            {"key_id": name, "new_password": f"n{index}", "password": PASSWORD,
             "iterations": 1_000}
            for index, name in enumerate(names)])
        self.assertEqual(results, [2] * len(names))
        for index, name in enumerate(names):
            self.assertEqual(
                self.ring.load(name, version=results[index], password=f"n{index}"),
                f"m{index}".encode("utf-8"))

    def test_input_objects_are_not_mutated(self) -> None:
        self.ring.seal("a", "ma", PASSWORD, iterations=1_000)
        self.ring.seal("b", "mb")
        requests = [
            {"key_id": "a", "new_password": "na", "password": PASSWORD,
             "iterations": 1_000, "revoke_source": False},
            {"key_id": "b", "new_password": "nb"},
        ]
        snapshot = copy.deepcopy(requests)
        results = self.ring.rotate_password_batch(requests)
        self.assertEqual(requests, snapshot)
        self.assertIsNot(results, requests)


class InputValidationTests(BatchTestBase):
    def _assert_value_error(self, requests) -> None:
        with self.assertRaises(ValueError):
            self.ring.rotate_password_batch(requests)

    def test_shape_must_be_non_empty_list_of_dicts(self) -> None:
        self._assert_value_error([])
        self._assert_value_error(None)
        self._assert_value_error({})
        self._assert_value_error("x")
        self._assert_value_error(({"key_id": "k", "new_password": "n"},))
        self._assert_value_error([{"key_id": "k", "new_password": "n"}, "x"])
        self._assert_value_error([["key_id", "k"]])

    def test_required_fields(self) -> None:
        self._assert_value_error([{"new_password": "n"}])
        self._assert_value_error([{"key_id": "k"}])
        self._assert_value_error([{}])

    def test_unknown_fields_rejected(self) -> None:
        self._assert_value_error([{"key_id": "k", "new_password": "n", "extra": 1}])
        self._assert_value_error([{"key_id": "k", "new_password": "n", "revoke": True}])

    def test_value_types_mirror_rotate_password(self) -> None:
        def request(**overrides) -> list[dict]:
            item = {"key_id": "k", "new_password": "n"}
            item.update(overrides)
            return [item]

        for bad in ("", None, 7):
            self._assert_value_error(request(key_id=bad))
        for bad in (None, 1, b"x", True):
            self._assert_value_error(request(new_password=bad))
        for bad in (1, True, b"x"):
            self._assert_value_error(request(password=bad))
        for bad in (0, -2, True, "1"):
            self._assert_value_error(request(version=bad))
        for bad in (0, -1, 1.5, True, "2000", None):
            self._assert_value_error(request(iterations=bad))
        for bad in (0, 1, "true", None):
            self._assert_value_error(request(revoke_source=bad))

    def test_duplicate_key_names_rejected(self) -> None:
        self._assert_value_error([
            {"key_id": "k", "new_password": "a"},
            {"key_id": "k", "new_password": "b"}])
        # Duplicate identity, not visual similarity: NFC/NFD are both allowed.
        nfc = "caf" + chr(0xE9)
        nfd = "caf" + chr(0x65) + chr(0x301)
        self.ring.seal(nfc, "x", PASSWORD, iterations=1_000)
        self.ring.seal(nfd, "y", PASSWORD, iterations=1_000)
        results = self.ring.rotate_password_batch([
            {"key_id": nfc, "new_password": "a", "password": PASSWORD,
             "iterations": 1_000},
            {"key_id": nfd, "new_password": "b", "password": PASSWORD,
             "iterations": 1_000}])
        self.assertEqual(results, [2, 2])

    def test_first_invalid_item_is_reported_even_when_storage_would_fail(self) -> None:
        # Whole-batch input validation precedes storage: an unknown key on disk
        # would be KeyError, but a type error later in the batch wins as
        # ValueError, and a missing ring never surfaces as FileNotFoundError.
        with self.assertRaises(ValueError):
            self.ring.rotate_password_batch([
                {"key_id": "missing", "new_password": "n"},
                {"key_id": "k", "new_password": 1}])
        missing_ring = core.KeyRing(self.root / "never-initialised")
        with self.assertRaises(ValueError):
            missing_ring.rotate_password_batch([{"key_id": "k", "new_password": 1}])
        # ...but well-shaped input against the missing ring does reach storage.
        with self.assertRaises(FileNotFoundError):
            missing_ring.rotate_password_batch([{"key_id": "k", "new_password": "n"}])

    def test_validation_never_touches_storage(self) -> None:
        self.ring.seal("k", "secret", PASSWORD, iterations=1_000)
        before = self.ring.path.read_bytes()
        for bad in (
            [],
            [{}],
            [{"key_id": "k", "new_password": "n", "iterations": 0}],
            [{"key_id": "k", "new_password": "n", "revoke_source": 1}],
            [{"key_id": "k", "new_password": "n", "bogus": True}],
            [{"key_id": "", "new_password": "n"}],
            [{"key_id": "k", "new_password": "n"},
             {"key_id": "k", "new_password": "m"}],
        ):
            with self.assertRaises(ValueError):
                self.ring.rotate_password_batch(bad)
        self.assertEqual(self.ring.path.read_bytes(), before)


class ErrorOrderTests(BatchTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.sealed = self.ring.seal("a", "secret-a", PASSWORD, iterations=1_000)
        self.plain = self.ring.seal("b", "secret-b")

    def _assert_unchanged(self, requests, error_type) -> None:
        before = self.ring.path.read_bytes()
        with self.assertRaises(error_type):
            self.ring.rotate_password_batch(requests)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_unknown_key_then_valid_item_is_keyerror_with_no_partial_result(self) -> None:
        self._assert_unchanged(
            [{"key_id": "missing", "new_password": "n"},
             {"key_id": "b", "new_password": "n2"}], KeyError)
        self.assertEqual(self.ring.active("b"), self.plain)

    def test_unknown_version_on_second_item_aborts_first_item_too(self) -> None:
        self._assert_unchanged(
            [{"key_id": "b", "new_password": "n2"},
             {"key_id": "a", "new_password": "n1", "password": PASSWORD,
              "version": 99, "iterations": 1_000}], KeyError)
        # Nothing was appended: history is still the single source version.
        self.assertEqual(self.ring.versions("a"), [self.sealed])
        self.assertEqual(self.ring.versions("b"), [self.plain])

    def test_revoked_source_in_request_order(self) -> None:
        self.ring.revoke("a", self.sealed)
        self._assert_unchanged(
            [{"key_id": "b", "new_password": "n2"},
             {"key_id": "a", "new_password": "n1", "password": PASSWORD,
              "iterations": 1_000}], core.RevokedVersionError)
        self.assertEqual(self.ring.versions("b"), [self.plain])
        self._assert_unchanged(
            [{"key_id": "a", "new_password": "n1", "iterations": 1_000}],
            core.RevokedVersionError)

    def test_legacy_derived_source_is_unrecoverable(self) -> None:
        document = self._document()
        document["keys"]["a"]["versions"][0] = {
            "version": self.sealed, "scheme": core.LEGACY_DERIVE_SCHEME,
            "revoked": False}
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        self._assert_unchanged(
            [{"key_id": "b", "new_password": "n2"},
             {"key_id": "a", "new_password": "n1", "password": PASSWORD,
              "iterations": 1_000}], core.UnrecoverableRecordError)

    def test_missing_old_password(self) -> None:
        self._assert_unchanged(
            [{"key_id": "a", "new_password": "n1", "iterations": 1_000}],
            core.MissingPasswordError)

    def test_wrong_old_password_fails_the_whole_batch(self) -> None:
        # Failure at item 1 and at item 2 both abort everything, including the
        # other (plain, otherwise valid) item.
        self._assert_unchanged(
            [{"key_id": "a", "new_password": "n1", "password": "wrong",
              "iterations": 1_000},
             {"key_id": "b", "new_password": "n2"}], core.BadPasswordError)
        self._assert_unchanged(
            [{"key_id": "b", "new_password": "n2"},
             {"key_id": "a", "new_password": "n1", "password": "wrong",
              "iterations": 1_000}], core.BadPasswordError)

    def test_correct_password_against_tampered_record_is_corrupt(self) -> None:
        document = self._document()
        material = bytearray(base64.b64decode(
            document["keys"]["a"]["versions"][0]["material"]))
        material[0] ^= 0x01
        document["keys"]["a"]["versions"][0]["material"] = \
            base64.b64encode(bytes(material)).decode("ascii")
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        self._assert_unchanged(
            [{"key_id": "b", "new_password": "n2"},
             {"key_id": "a", "new_password": "n1", "password": PASSWORD,
              "iterations": 1_000}], core.CorruptRecordError)

    def test_whole_store_is_validated_before_request_order(self) -> None:
        # Corruption in an untouched key fails the batch even though the first
        # request itself names a valid key.
        document = self._document()
        document["keys"]["b"]["versions"][0]["material"] = "!!not base64!!"
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.rotate_password_batch([
                {"key_id": "a", "new_password": "n1", "password": PASSWORD,
                 "iterations": 1_000}])
        self.assertEqual(self.ring.path.read_bytes(), before)
        # Unparseable document: same verdict before any key is resolved.
        self.ring.path.write_text("{not json", encoding="utf-8")
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.rotate_password_batch([
                {"key_id": "missing", "new_password": "n"}])
        self.assertEqual(self.ring.path.read_bytes(), before)


class ConcurrencyTests(BatchTestBase):
    def test_concurrent_batches_only_see_pre_or_post_state(self) -> None:
        self.ring.seal("a", "ma")
        self.ring.seal("b", "mb")
        count = 6
        barrier = threading.Barrier(count)
        lock = threading.Lock()
        results: list[tuple[int, list[int]]] = []
        errors: list[BaseException] = []

        def worker(i: int) -> None:
            barrier.wait()
            try:
                # Pin the plain v1 source of every key: it never gets a
                # passphrase, so each queued batch can authenticate despite
                # earlier batches repointing active (same trick the
                # single-rotation concurrency test relies on).
                numbers = self.ring.rotate_password_batch([
                    {"key_id": "a", "new_password": f"a-{i}", "version": 1},
                    {"key_id": "b", "new_password": f"b-{i}", "version": 1},
                ])
                with lock:
                    results.append((i, numbers))
            except BaseException as error:  # noqa: BLE001 - surfaced below
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        # Each key independently serialised to the same gapless sequence.
        a_owners = {numbers[0]: i for i, numbers in results}
        b_owners = {numbers[1]: i for i, numbers in results}
        self.assertEqual(sorted(a_owners), list(range(2, 2 + count)))
        self.assertEqual(sorted(b_owners), list(range(2, 2 + count)))
        # The commit is atomic: the winning versions on a and b came out of the
        # same batch and both open under that batch's passwords.
        document = self._document()
        active_a, active_b = document["keys"]["a"]["active"], document["keys"]["b"]["active"]
        winner = a_owners[active_a]
        self.assertEqual(b_owners[active_b], winner)
        self.assertEqual(self.ring.load("a", password=f"a-{winner}"), b"ma")
        self.assertEqual(self.ring.load("b", password=f"b-{winner}"), b"mb")

    def test_batch_races_with_single_seals_without_losing_history(self) -> None:
        self.ring.seal("a", "ma", PASSWORD, iterations=200)
        self.ring.seal("b", "mb")
        seal_count = 8
        barrier = threading.Barrier(seal_count + 1)
        errors: list[BaseException] = []

        def sealer(i: int) -> None:
            barrier.wait()
            try:
                self.ring.seal("k", f"m{i}")
            except BaseException as error:  # noqa: BLE001 - surfaced below
                errors.append(error)

        threads = [threading.Thread(target=sealer, args=(i,)) for i in range(seal_count)]
        for thread in threads:
            thread.start()
        barrier.wait()
        rotated = self.ring.rotate_password_batch([
            {"key_id": "a", "new_password": "na", "password": PASSWORD,
             "iterations": 200},
            {"key_id": "b", "new_password": "nb"},
        ])
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        # No seal was lost: the raced key keeps a complete, gapless history.
        self.assertEqual(self.ring.versions("k"), list(range(1, seal_count + 1)))
        self.assertEqual(self.ring.versions("a"), [1, rotated[0]])
        self.assertEqual(self.ring.versions("b"), [1, rotated[1]])
        self.assertEqual(self.ring.load("a", password="na"), b"ma")
        self.assertEqual(self.ring.load("b", password="nb"), b"mb")

    def test_reader_cannot_observe_a_half_committed_batch(self) -> None:
        self.ring.seal("a", "ma", PASSWORD, iterations=1_000)
        self.ring.seal("b", "mb")
        entered, release = threading.Event(), threading.Event()
        real_derive = core._derive

        def slow_derive(password: str, salt: bytes, iterations: int, length: int = 32):
            entered.set()
            release.wait(timeout=5)
            return real_derive(password, salt, iterations, length)

        outcome: dict[str, object] = {}

        def batch() -> None:
            try:
                outcome["versions"] = self.ring.rotate_password_batch([
                    {"key_id": "a", "new_password": "na", "password": PASSWORD,
                     "iterations": 1_000},
                    {"key_id": "b", "new_password": "nb"}])
            except BaseException as error:  # noqa: BLE001 - surfaced below
                outcome["error"] = error

        core._derive = slow_derive
        try:
            writer = threading.Thread(target=batch)
            writer.start()
            self.assertTrue(entered.wait(timeout=5), "batch never entered the lock")

            def reader() -> None:
                # Default version resolved inside one snapshot: this either runs
                # before the batch commits (old password still good) or after
                # (active requires the new password), never against a
                # half-rotated ring.
                try:
                    outcome["material"] = self.ring.load("a", password=PASSWORD)
                except BaseException as error:  # noqa: BLE001 - surfaced below
                    outcome["read_error"] = error

            reader_thread = threading.Thread(target=reader)
            reader_thread.start()
            time.sleep(0.4)
            # The exclusive lock covers the whole commit: the reader is queued.
            self.assertNotIn("material", outcome)
            self.assertNotIn("read_error", outcome)
            release.set()
            writer.join(timeout=10)
            reader_thread.join(timeout=10)
        finally:
            core._derive = real_derive
        self.assertIn("versions", outcome)
        # The reader committed after the batch: the old password no longer
        # opens the active version and the new one does.
        self.assertIsInstance(outcome["read_error"], core.BadPasswordError)
        self.assertEqual(self.ring.load("a", password="na"), b"ma")
        self.assertEqual(self.ring.load("b", password="nb"), b"mb")

    def test_write_lock_timeout_leaves_file_unchanged(self) -> None:
        self.ring.seal("a", "ma")
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
                self.ring.rotate_password_batch([{"key_id": "a", "new_password": "n"}])
            self.assertEqual(self.ring.path.read_bytes(), before)
        finally:
            core.LOCK_TIMEOUT_SECONDS = original_timeout
            holder.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
