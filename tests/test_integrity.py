"""Storage-integrity tests: every entry point validates the whole state.

A tampered, truncated or structurally illegal keyring.json must be rejected
uniformly:

* every state-reading entry (load with and without a version, versions,
  active, is_revoked) raises CorruptRecordError before returning anything;
* every writing entry (seal, set_active, revoke) validates inside the write
  lock and commits nothing on a corrupt snapshot;
* the CLI maps CorruptRecordError to exit code 1 while unknown key/version
  remain KeyError/exit code 2;
* a structurally complete legacy derived-only record stays
  UnrecoverableRecordError -- it is never misreported as a bad passphrase or
  as corruption;
* well-formed state (including legacy records and UTF-8 edge cases) keeps
  working.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from seal_derive import core

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEY = "k"
PLAIN_KEY = "p"
PASSWORD = "correct horse"


class IntegrityTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()
        self.v1 = self.ring.seal(KEY, "材料-sealed", PASSWORD, iterations=2_000)
        self.v2 = self.ring.seal(KEY, "材料-sealed-2", PASSWORD, iterations=2_000)
        self.v_plain = self.ring.seal(PLAIN_KEY, "材料-plain")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    # -- state mutation helpers --------------------------------------------

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _put_document(self, document) -> None:
        self.ring.path.write_text(json.dumps(document), encoding="utf-8")

    def _put_raw(self, text: str) -> None:
        self.ring.path.write_text(text, encoding="utf-8")

    def _entry(self, document: dict, key: str = KEY) -> dict:
        return document["keys"][key]

    @staticmethod
    def _sealed_record(document: dict, key: str = KEY) -> dict:
        return document["keys"][key]["versions"][0]

    def _ring_with_one_sealed(self, name: str = "single") -> tuple[core.KeyRing, int]:
        ring = core.KeyRing(self.root / name)
        ring.init()
        version = ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        return ring, version

    # -- assertions ---------------------------------------------------------

    def _assert_all_readers_reject(self, ring: core.KeyRing, version: int) -> None:
        with self.assertRaises(core.CorruptRecordError):
            ring.load(KEY, password=PASSWORD)
        with self.assertRaises(core.CorruptRecordError):
            ring.load(KEY, version=version, password=PASSWORD)
        with self.assertRaises(core.CorruptRecordError):
            ring.load(PLAIN_KEY)
        with self.assertRaises(core.CorruptRecordError):
            ring.versions(KEY)
        with self.assertRaises(core.CorruptRecordError):
            ring.versions(PLAIN_KEY)
        with self.assertRaises(core.CorruptRecordError):
            ring.active(KEY)
        with self.assertRaises(core.CorruptRecordError):
            ring.is_revoked(KEY, version)
        with self.assertRaises(core.CorruptRecordError):
            ring.is_revoked(PLAIN_KEY, self.v_plain)


class FileLevelCorruptionTests(IntegrityTestBase):
    def test_truncated_json_rejected_everywhere(self) -> None:
        self._put_raw('{"keys": {"k": {"versions": [')
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_non_utf8_bytes_rejected_everywhere(self) -> None:
        self.ring.path.write_bytes(b'{"keys": {"k": \xff\xfe}}')
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_top_level_not_object(self) -> None:
        self._put_document([1, 2, 3])
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_keys_missing_or_wrong_type(self) -> None:
        self._put_document({})
        self._assert_all_readers_reject(self.ring, self.v2)
        self._put_document({"keys": []})
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_extra_top_level_fields_still_valid(self) -> None:
        # Validation must not reject forward-compatible extra fields.
        document = self._document()
        document["future"] = {"anything": True}
        self._put_document(document)
        self.assertEqual(self.ring.load(PLAIN_KEY), "材料-plain".encode("utf-8"))


class EntryStructureCorruptionTests(IntegrityTestBase):
    def test_entry_not_object(self) -> None:
        document = self._document()
        document["keys"][KEY] = []
        self._put_document(document)
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_versions_not_list(self) -> None:
        document = self._document()
        self._entry(document)["versions"] = {}
        self._put_document(document)
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_version_record_not_object(self) -> None:
        document = self._document()
        self._entry(document)["versions"][0] = 3
        self._put_document(document)
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_active_wrong_types(self) -> None:
        for bad in (None, True, "2", 0, -1, 1.0):
            with self.subTest(bad=bad):
                document = self._document()
                self._entry(document)["active"] = bad
                self._put_document(document)
                with self.assertRaises(core.CorruptRecordError):
                    self.ring.active(KEY)

    def test_active_points_at_missing_version(self) -> None:
        document = self._document()
        self._entry(document)["active"] = 999
        self._put_document(document)
        self._assert_all_readers_reject(self.ring, self.v2)

    def test_empty_history_with_non_positive_active_is_corrupt(self) -> None:
        # A truncated history is corruption, not an empty key.
        document = self._document()
        document["keys"]["ghost"] = {"versions": [], "active": 0}
        self._put_document(document)
        with self.assertRaises(core.CorruptRecordError):
            self.ring.versions("ghost")

    def test_version_number_rules(self) -> None:
        for bad in (None, True, "1", 0, -3, 1.5):
            with self.subTest(bad=bad):
                document = self._document()
                self._entry(document)["versions"][0]["version"] = bad
                self._put_document(document)
                with self.assertRaises(core.CorruptRecordError):
                    self.ring.versions(KEY)

    def test_duplicate_version_numbers(self) -> None:
        document = self._document()
        versions = self._entry(document)["versions"]
        versions[0] = dict(versions[0])
        versions.append(versions[0])
        self._entry(document)["active"] = versions[0]["version"]
        self._put_document(document)
        self._assert_all_readers_reject(self.ring, self.v1)

    def test_versions_must_be_ascending(self) -> None:
        document = self._document()
        entry = self._entry(document)
        first, second = entry["versions"]
        entry["versions"] = [second, first]
        self._put_document(document)
        self._assert_all_readers_reject(self.ring, self.v1)

    def test_revoked_must_be_boolean(self) -> None:
        for bad in (0, 1, None, "false"):
            with self.subTest(bad=bad):
                document = self._document()
                self._entry(document)["versions"][0]["revoked"] = bad
                self._put_document(document)
                with self.assertRaises(core.CorruptRecordError):
                    self.ring.is_revoked(PLAIN_KEY, self.v_plain)


class RecordContentCorruptionTests(IntegrityTestBase):
    def test_unknown_and_typed_schemes_rejected(self) -> None:
        for bad in (None, "aes-256", 1, True):
            with self.subTest(bad=bad):
                document = self._document()
                document["keys"][PLAIN_KEY]["versions"][0]["scheme"] = bad
                self._put_document(document)
                with self.assertRaises(core.CorruptRecordError):
                    self.ring.load(PLAIN_KEY)

    def test_plain_missing_material(self) -> None:
        document = self._document()
        del document["keys"][PLAIN_KEY]["versions"][0]["material"]
        self._put_document(document)
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load(PLAIN_KEY)

    def test_plain_material_must_be_base64(self) -> None:
        document = self._document()
        document["keys"][PLAIN_KEY]["versions"][0]["material"] = "not base64!"
        self._put_document(document)
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load(PLAIN_KEY)

    def test_plain_material_must_be_utf8(self) -> None:
        document = self._document()
        document["keys"][PLAIN_KEY]["versions"][0]["material"] = \
            base64.b64encode(b"\xff\xfe").decode()
        self._put_document(document)
        # Even metadata reads reject the document; load never hands back bytes
        # that could not have been the original UTF-8 material.
        with self.assertRaises(core.CorruptRecordError):
            self.ring.versions(PLAIN_KEY)
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load(PLAIN_KEY)

    def test_sealed_missing_fields(self) -> None:
        for omitted in ("salt", "iterations", "material", "check", "tag"):
            with self.subTest(omitted=omitted):
                ring, version = self._ring_with_one_sealed(f"miss-{omitted}")
                document = json.loads(ring.path.read_text(encoding="utf-8"))
                del document["keys"][KEY]["versions"][0][omitted]
                ring.path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(core.CorruptRecordError):
                    ring.load(KEY, version=version, password=PASSWORD)

    def test_sealed_fixed_length_fields(self) -> None:
        ring, version = self._ring_with_one_sealed()
        document = json.loads(ring.path.read_text(encoding="utf-8"))
        record = self._sealed_record(document)
        record["salt"] = base64.b64encode(b"short").decode()
        record["check"] = base64.b64encode(b"x" * 31).decode()
        record["tag"] = base64.b64encode(b"x" * 33).decode()
        ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            ring.load(KEY, version=version, password=PASSWORD)
        with self.assertRaises(core.CorruptRecordError):
            ring.versions(KEY)

    def test_iterations_must_be_positive_int(self) -> None:
        for bad in (0, -1, "1000", 1.5, True, None):
            with self.subTest(bad=bad):
                ring, _ = self._ring_with_one_sealed(f"iter-{type(bad).__name__}")
                document = json.loads(ring.path.read_text(encoding="utf-8"))
                self._sealed_record(document)["iterations"] = bad
                ring.path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(core.CorruptRecordError):
                    ring.load(KEY, password=PASSWORD)


class SealedAuthenticationTests(IntegrityTestBase):
    def test_tampered_ciphertext_is_corrupt_not_bad_password(self) -> None:
        ring, version = self._ring_with_one_sealed()
        document = json.loads(ring.path.read_text(encoding="utf-8"))
        record = self._sealed_record(document)
        material = bytearray(base64.b64decode(record["material"]))
        material[0] ^= 0x01
        record["material"] = base64.b64encode(bytes(material)).decode()
        ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            ring.load(KEY, version=version, password=PASSWORD)

    def test_wrong_password_remains_bad_password(self) -> None:
        ring, version = self._ring_with_one_sealed()
        with self.assertRaises(core.BadPasswordError):
            ring.load(KEY, version=version, password="wrong")

    def test_missing_password_remains_missing_password(self) -> None:
        ring, version = self._ring_with_one_sealed()
        with self.assertRaises(core.MissingPasswordError):
            ring.load(KEY, version=version)


class LegacyRecordTests(IntegrityTestBase):
    def _make_legacy(self, name: str) -> tuple[core.KeyRing, int]:
        ring = core.KeyRing(self.root / name)
        ring.init()
        version = ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        document = json.loads(ring.path.read_text(encoding="utf-8"))
        document["keys"][KEY]["versions"][0] = {
            "version": version, "scheme": core.LEGACY_DERIVE_SCHEME, "revoked": False}
        ring.path.write_text(json.dumps(document), encoding="utf-8")
        return ring, version

    def test_structural_legacy_record_is_unrecoverable(self) -> None:
        ring, version = self._make_legacy("legacy")
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            ring.load(KEY, version=version, password=PASSWORD)

    def test_legacy_record_is_not_bad_password_or_corruption(self) -> None:
        ring, version = self._make_legacy("legacy2")
        # No passphrase at all: still unrecoverable, never MissingPassword.
        with self.assertRaises(core.UnrecoverableRecordError):
            ring.load(KEY, version=version)
        # Metadata reads accept the structurally valid legacy record.
        self.assertEqual(ring.versions(KEY), [version])
        self.assertEqual(ring.active(KEY), version)
        self.assertFalse(ring.is_revoked(KEY, version))

    def test_legacy_record_with_bad_version_number_is_corrupt(self) -> None:
        ring, version = self._make_legacy("legacy3")
        document = json.loads(ring.path.read_text(encoding="utf-8"))
        document["keys"][KEY]["versions"][0]["version"] = True
        document["keys"][KEY]["active"] = version
        ring.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            ring.versions(KEY)


class WriterValidationTests(IntegrityTestBase):
    def test_writers_validate_corrupt_snapshot_and_commit_nothing(self) -> None:
        ring, version = self._ring_with_one_sealed()
        ring.path.write_text("{not json", encoding="utf-8")
        before = ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            ring.seal(KEY, "more")
        with self.assertRaises(core.CorruptRecordError):
            ring.set_active(KEY, version)
        with self.assertRaises(core.CorruptRecordError):
            ring.revoke(KEY, version)
        self.assertEqual(ring.path.read_bytes(), before)

    def test_writer_rejects_structurally_corrupt_other_entry(self) -> None:
        # Corrupt the *other* key: sealing into a fresh key must still fail
        # because the whole document is validated, not just the touched entry.
        document = self._document()
        document["keys"][PLAIN_KEY]["versions"][0]["material"] = "!!not b64!!"
        self._put_document(document)
        before = self.ring.path.read_bytes()
        with self.assertRaises(core.CorruptRecordError):
            self.ring.seal("brand-new", "x")
        with self.assertRaises(core.CorruptRecordError):
            self.ring.set_active(PLAIN_KEY, self.v_plain)
        with self.assertRaises(core.CorruptRecordError):
            self.ring.revoke(PLAIN_KEY, self.v_plain)
        self.assertEqual(self.ring.path.read_bytes(), before)

    def test_init_rebuilds_after_corruption_and_leaves_no_temp_files(self) -> None:
        ring, _ = self._ring_with_one_sealed()
        ring.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(core.CorruptRecordError):
            ring.seal(KEY, "more")
        # init restores the empty-ring semantics regardless of the bad file.
        ring.init()
        self.assertEqual(list(ring.directory.glob(".keyring-*.tmp")), [])
        version = ring.seal(KEY, "again")
        self.assertEqual(version, 1)
        self.assertEqual(ring.load(KEY), b"again")


class ErrorClassificationTests(IntegrityTestBase):
    def test_unknown_key_remains_keyerror(self) -> None:
        with self.assertRaises(KeyError):
            self.ring.load("missing")
        with self.assertRaises(KeyError):
            self.ring.versions("missing")
        with self.assertRaises(KeyError):
            self.ring.active("missing")
        with self.assertRaises(KeyError):
            self.ring.is_revoked("missing", 1)
        with self.assertRaises(KeyError):
            self.ring.set_active("missing", 1)
        with self.assertRaises(KeyError):
            self.ring.revoke("missing", 1)

    def test_unknown_version_remains_keyerror(self) -> None:
        with self.assertRaises(KeyError):
            self.ring.load(PLAIN_KEY, version=42)
        with self.assertRaises(KeyError):
            self.ring.set_active(PLAIN_KEY, 42)
        with self.assertRaises(KeyError):
            self.ring.revoke(PLAIN_KEY, 42)
        with self.assertRaises(KeyError):
            self.ring.is_revoked(PLAIN_KEY, 42)

    def test_bad_arguments_remain_valueerror(self) -> None:
        with self.assertRaises(ValueError):
            self.ring.load(PLAIN_KEY, version=0)
        with self.assertRaises(ValueError):
            self.ring.load(PLAIN_KEY, version=True)
        with self.assertRaises(ValueError):
            self.ring.seal(KEY, "x", iterations=0)
        with self.assertRaises(ValueError):
            self.ring.set_active(KEY, True)

    def test_missing_ring_remains_filenotfound(self) -> None:
        missing = core.KeyRing(self.root / "nonexistent")
        with self.assertRaises(FileNotFoundError):
            missing.load(KEY)
        with self.assertRaises(FileNotFoundError):
            missing.seal(KEY, "x")
        with self.assertRaises(FileNotFoundError):
            missing.versions(KEY)


class CliIntegrityTests(IntegrityTestBase):
    def _run(self, ring: core.KeyRing, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(ring.directory), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)

    def test_corrupt_state_exit_code_one_for_each_command(self) -> None:
        ring, version = self._ring_with_one_sealed()
        ring.path.write_text("{not json", encoding="utf-8")
        invocations = [
            ("load", KEY, "--password", PASSWORD),
            ("load", KEY, "--version", str(version), "--password", PASSWORD),
            ("versions", KEY),
            ("active", KEY),
            ("seal", KEY, "more"),
            ("set-active", KEY, str(version)),
            ("revoke", KEY, str(version)),
        ]
        for invocation in invocations:
            with self.subTest(invocation=invocation):
                result = self._run(ring, *invocation)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("记录损坏", result.stderr)
        # No command produced anything before failing.
        self.assertEqual(ring.path.read_text(encoding="utf-8"), "{not json")

    def test_structural_corruption_exit_code_one(self) -> None:
        ring, _ = self._ring_with_one_sealed()
        document = json.loads(ring.path.read_text(encoding="utf-8"))
        self._sealed_record(document)["salt"] = base64.b64encode(b"short").decode()
        ring.path.write_text(json.dumps(document), encoding="utf-8")
        result = self._run(ring, "active", KEY)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_unknown_key_still_exit_code_two(self) -> None:
        ring, _ = self._ring_with_one_sealed()
        self.assertEqual(self._run(ring, "load", "missing").returncode, 2)
        self.assertEqual(self._run(ring, "versions", "missing").returncode, 2)

    def test_legacy_record_exit_code_one_but_not_password_error(self) -> None:
        ring = core.KeyRing(self.root / "legacy-cli")
        ring.init()
        version = ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        document = json.loads(ring.path.read_text(encoding="utf-8"))
        document["keys"][KEY]["versions"][0] = {
            "version": version, "scheme": core.LEGACY_DERIVE_SCHEME, "revoked": False}
        ring.path.write_text(json.dumps(document), encoding="utf-8")
        result = self._run(ring, "load", KEY, "--password", PASSWORD)
        self.assertEqual(result.returncode, 1)
        self.assertIn("不可恢复的旧记录", result.stderr)
        self.assertNotIn("口令不匹配", result.stderr)


class HappyPathTests(IntegrityTestBase):
    def test_all_entries_work_on_valid_state(self) -> None:
        self.assertEqual(self.ring.load(PLAIN_KEY), "材料-plain".encode("utf-8"))
        self.assertEqual(self.ring.load(KEY, password=PASSWORD),
                         "材料-sealed-2".encode("utf-8"))
        self.assertEqual(self.ring.versions(PLAIN_KEY), [self.v_plain])
        self.assertEqual(self.ring.active(KEY), self.v2)
        self.assertFalse(self.ring.is_revoked(KEY, self.v2))
        next_version = self.ring.seal(PLAIN_KEY, "更多")
        self.assertEqual(self.ring.versions(PLAIN_KEY), [self.v_plain, next_version])
        self.ring.set_active(PLAIN_KEY, self.v_plain)
        self.assertEqual(self.ring.active(PLAIN_KEY), self.v_plain)
        self.ring.revoke(PLAIN_KEY, next_version)
        self.assertTrue(self.ring.is_revoked(PLAIN_KEY, next_version))

    def test_unicode_plain_round_trip(self) -> None:
        for material in ("", "é" * 100, "😀‍‍"):
            version = self.ring.seal("u", material)
            self.assertEqual(self.ring.load("u", version=version), material.encode("utf-8"))

    def test_default_load_without_version_validates(self) -> None:
        # The no-version path resolves active inside the validated snapshot.
        document = self._document()
        self._entry(document, PLAIN_KEY)["active"] = 12345
        self._put_document(document)
        with self.assertRaises(core.CorruptRecordError):
            self.ring.load(PLAIN_KEY)


if __name__ == "__main__":
    unittest.main()
