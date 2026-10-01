"""Key-binding tests for the ``pbkdf2-sha256-sealed-v2`` scheme.

New passphrase seals bind the exact ``key_id`` into the authentication tag:

* ``seal`` with a passphrase always writes a v2 record; password-less seals
  keep using ``plain``; round trips return the original UTF-8 bytes;
* copying or moving a record to another key, renaming the owning key,
  rewriting the version number, or tampering with the ciphertext/tag makes
  ``load`` raise ``CorruptRecordError`` (never the material);
* key names are full strings -- Chinese, emoji, spaces and separator bytes,
  different case and different Unicode spellings are distinct keys and can
  never authenticate each other's records;
* versions of one key keep reading by the old rules and moving the whole
  store directory does not invalidate anything;
* legacy ``pbkdf2-sha256-sealed`` (v1) records still open with the original
  passphrase, reads do not rewrite them, and they gain no retroactive
  cross-key binding; legacy ``pbkdf2-sha256`` records stay unrecoverable;
* the v2 error surface (missing/wrong passphrase, revocation, messages and
  CLI exit codes) is unchanged.

Stdlib only: ``python3 -m unittest discover`` from the project root.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from seal_derive import core

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEY = "k"
OTHER = "other"
PASSWORD = "correct horse"

NFC_NAME = "caf" + chr(0xE9)        # "café" as one code point
NFD_NAME = "caf" + chr(0x65) + chr(0x301)  # "café" as e + combining acute


class V2TestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ring = core.KeyRing(self.root)
        self.ring.init()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    # -- state mutation helpers --------------------------------------------

    def _document(self) -> dict:
        return json.loads(self.ring.path.read_text(encoding="utf-8"))

    def _put_document(self, document: dict) -> None:
        self.ring.path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")

    def _record(self, document: dict, key: str = KEY, index: int = -1) -> dict:
        return document["keys"][key]["versions"][index]

    def _tamper(self, mutation) -> None:
        document = self._document()
        mutation(document)
        self.ring.path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")

    def _flip_first_byte(self, document: dict, field: str, key: str = KEY) -> None:
        raw = bytearray(base64.b64decode(self._record(document, key)[field]))
        raw[0] ^= 0x01
        self._record(document, key)[field] = base64.b64encode(bytes(raw)).decode("ascii")

    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seal_derive", "--root", str(self.root), *arguments],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=20)


class SealSchemeTests(V2TestBase):
    def test_password_seal_writes_v2(self) -> None:
        version = self.ring.seal(KEY, "材料", PASSWORD, iterations=1_000)
        record = self._record(self._document())
        self.assertEqual(record["version"], version)
        self.assertEqual(record["scheme"], core.SEALED_V2_SCHEME)
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), "材料".encode("utf-8"))

    def test_default_iterations_are_kept(self) -> None:
        self.ring.seal(KEY, "材料", PASSWORD)
        self.assertEqual(self._record(self._document())["iterations"], 200_000)

    def test_plain_seal_stays_plain(self) -> None:
        self.ring.seal(KEY, "材料")
        self.assertEqual(self._record(self._document())["scheme"], core.PLAIN_SCHEME)
        self.assertEqual(self.ring.load(KEY), "材料".encode("utf-8"))

    def test_version_bumping_and_active_update_keep_old_rules(self) -> None:
        first = self.ring.seal(KEY, "一", PASSWORD, iterations=1_000)
        second = self.ring.seal(KEY, "二", PASSWORD, iterations=1_000)
        self.assertEqual((first, second), (1, 2))
        self.assertEqual(self.ring.active(KEY), second)
        self.assertEqual(self.ring.versions(KEY), [first, second])
        self.assertEqual(self.ring.load(KEY, version=first, password=PASSWORD), "一".encode("utf-8"))
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), "二".encode("utf-8"))


class KeyBindingTamperTests(V2TestBase):
    def setUp(self) -> None:
        super().setUp()
        self.version = self.ring.seal(KEY, "机密🔐", PASSWORD, iterations=1_000)

    def _assert_corrupt_when_loading(self, key: str = KEY, version: int | None = None) -> None:
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load(key, version=version, password=PASSWORD)

    def test_record_copied_under_another_key_is_corrupt(self) -> None:
        self._tamper(lambda d: d["keys"].__setitem__(
            OTHER, {"versions": [copy.deepcopy(self._record(d))], "active": self.version}))
        self._assert_corrupt_when_loading(OTHER)
        # The original record is untouched and still openable.
        self.assertEqual(self.ring.load(KEY, password=PASSWORD), "机密🔐".encode("utf-8"))

    def test_owning_key_renamed_is_corrupt(self) -> None:
        self._tamper(lambda d: d["keys"].__setitem__("renamed", d["keys"].pop(KEY)))
        self._assert_corrupt_when_loading("renamed")

    def test_record_moved_between_existing_keys_is_corrupt(self) -> None:
        self.ring.seal(OTHER, "别的材料", PASSWORD, iterations=1_000)
        def move(document: dict) -> None:
            foreign = copy.deepcopy(self._record(document, KEY))
            document["keys"][OTHER]["versions"] = [foreign]
            document["keys"][OTHER]["active"] = foreign["version"]
        self._tamper(move)
        self._assert_corrupt_when_loading(OTHER)

    def test_version_rewritten_is_corrupt(self) -> None:
        def rewrite(document: dict) -> None:
            self._record(document)["version"] = 7
            document["keys"][KEY]["active"] = 7
        self._tamper(rewrite)
        self._assert_corrupt_when_loading(KEY, version=7)

    def test_ciphertext_tampered_is_corrupt(self) -> None:
        self._tamper(lambda d: self._flip_first_byte(d, "material"))
        self._assert_corrupt_when_loading()

    def test_tag_tampered_is_corrupt(self) -> None:
        self._tamper(lambda d: self._flip_first_byte(d, "tag"))
        self._assert_corrupt_when_loading()

    def test_wrong_password_still_bad_password_under_tampered_record(self) -> None:
        self._tamper(lambda d: d["keys"].__setitem__(
            OTHER, {"versions": [copy.deepcopy(self._record(d))], "active": self.version}))
        with self.assertRaises(core.BadPasswordError):
            self.ring.load(OTHER, password="wrong")

    def test_scheme_field_rewritten_either_way_is_corrupt(self) -> None:
        self._tamper(lambda d: self._record(d).__setitem__("scheme", core.SEALED_SCHEME))
        self._assert_corrupt_when_loading()

    def test_cli_reports_exit_code_one_for_moved_record(self) -> None:
        self._tamper(lambda d: d["keys"].__setitem__(
            OTHER, {"versions": [copy.deepcopy(self._record(d))], "active": self.version}))
        result = self._run_cli("load", OTHER, "--password", PASSWORD)
        self.assertEqual(result.returncode, 1)
        self.assertIn("记录损坏", result.stderr)
        self.assertEqual(result.stdout, "")


class KeyNameDiscriminationTests(V2TestBase):
    def test_chinese_emoji_spaces_and_separators_round_trip(self) -> None:
        for name in ("中文键", "键 😀/a|b\\", "  ", "a/b|c\\d"):
            with self.subTest(name=name):
                version = self.ring.seal(name, "M", PASSWORD, iterations=1_000)
                self.assertEqual(self.ring.load(name, version=version, password=PASSWORD), b"M")

    def test_case_trailing_space_and_separator_variants_are_distinct(self) -> None:
        name = "中文 键😀/a|b\\"
        self.ring.seal(name, "M", PASSWORD, iterations=1_000)
        for other in (name.upper(), name + " ", name.replace(" ", ""),
                      "中文 键😀/a|b", "中文 键😀x/a|b\\"):
            with self.subTest(other=other):
                with self.assertRaises(KeyError):
                    self.ring.load(other, password=PASSWORD)

    def test_different_unicode_spellings_do_not_cross_authenticate(self) -> None:
        self.assertNotEqual(NFC_NAME, NFD_NAME)
        self.ring.seal(NFC_NAME, "aa", PASSWORD, iterations=1_000)
        self.ring.seal(NFD_NAME, "bb", PASSWORD, iterations=1_000)
        self.assertEqual(self.ring.load(NFC_NAME, password=PASSWORD), b"aa")
        self.assertEqual(self.ring.load(NFD_NAME, password=PASSWORD), b"bb")
        # Copy the NFD record into the NFC entry's history: the bound name
        # differs even though the rendered key looks identical.
        def cross(document: dict) -> None:
            foreign = copy.deepcopy(document["keys"][NFD_NAME]["versions"][0])
            foreign["version"] = 9
            document["keys"][NFC_NAME]["versions"].append(foreign)
            document["keys"][NFC_NAME]["active"] = 9
        self._tamper(cross)
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load(NFC_NAME, password=PASSWORD)
        # Each genuine record still opens.
        self.assertEqual(self.ring.load(NFC_NAME, version=1, password=PASSWORD), b"aa")
        self.assertEqual(self.ring.load(NFD_NAME, password=PASSWORD), b"bb")


class DirectoryRelocationTests(V2TestBase):
    def test_versions_survive_directory_move(self) -> None:
        first = self.ring.seal(KEY, "一", PASSWORD, iterations=1_000)
        second = self.ring.seal(KEY, "二", PASSWORD, iterations=1_000)
        relocated = Path(tempfile.mkdtemp()) / "moved-store"
        self.addCleanup(shutil.rmtree, relocated.parent, ignore_errors=True)
        shutil.move(str(self.root), str(relocated))
        moved_ring = core.KeyRing(relocated)
        self.assertEqual(moved_ring.load(KEY, version=first, password=PASSWORD), "一".encode("utf-8"))
        self.assertEqual(moved_ring.load(KEY, version=second, password=PASSWORD), "二".encode("utf-8"))


class LegacyCompatibilityTests(V2TestBase):
    def _replace_with_v1_record(self, plaintext: bytes) -> int:
        version = self.ring.seal(KEY, plaintext.decode(), PASSWORD, iterations=1_000)
        document = self._document()
        record = self._record(document)
        salt = base64.b64decode(record["salt"])
        iterations = record["iterations"]
        derived = core._derive(PASSWORD, salt, iterations, 3 * core._KEY_BYTES)
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
        return version

    def test_v1_sealed_record_still_opens(self) -> None:
        version = self._replace_with_v1_record(b"legacy-secret")
        self.assertEqual(self.ring.load(KEY, version=version, password=PASSWORD),
                         b"legacy-secret")

    def test_reading_v1_record_does_not_rewrite_it(self) -> None:
        version = self._replace_with_v1_record(b"legacy-secret")
        before = self.ring.path.read_bytes()
        self.ring.load(KEY, version=version, password=PASSWORD)
        self.assertEqual(before, self.ring.path.read_bytes())
        self.assertEqual(self._record(self._document())["scheme"], core.SEALED_SCHEME)

    def test_v1_record_has_no_retroactive_cross_key_binding(self) -> None:
        version = self._replace_with_v1_record(b"legacy-secret")
        self._tamper(lambda d: d["keys"].__setitem__(
            OTHER, {"versions": [copy.deepcopy(self._record(d))], "active": version}))
        # Old behaviour preserved: v1 records never gain the new key binding.
        self.assertEqual(self.ring.load(OTHER, password=PASSWORD), b"legacy-secret")

    def test_v1_upgrade_claim_is_corrupt(self) -> None:
        self._replace_with_v1_record(b"legacy-secret")
        self._tamper(lambda d: self._record(d).__setitem__("scheme", core.SEALED_V2_SCHEME))
        with self.assertRaisesRegex(core.CorruptRecordError, "记录损坏"):
            self.ring.load(KEY, password=PASSWORD)

    def test_legacy_derived_record_stays_unrecoverable(self) -> None:
        version = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self._tamper(lambda d: d["keys"][KEY]["versions"].__setitem__(
            0, {"version": version, "scheme": core.LEGACY_DERIVE_SCHEME, "revoked": False}))
        with self.assertRaisesRegex(core.UnrecoverableRecordError, "不可恢复的旧记录"):
            self.ring.load(KEY, version=version, password=PASSWORD)
        self.assertEqual(self.ring.versions(KEY), [version])


class V2ErrorSurfaceTests(V2TestBase):
    def test_missing_password(self) -> None:
        version = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        with self.assertRaisesRegex(core.MissingPasswordError, "缺少口令"):
            self.ring.load(KEY, version=version)

    def test_bad_password(self) -> None:
        version = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        with self.assertRaisesRegex(core.BadPasswordError, "口令不匹配"):
            self.ring.load(KEY, version=version, password="wrong")

    def test_revoked_version(self) -> None:
        version = self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.ring.revoke(KEY, version)
        with self.assertRaisesRegex(core.RevokedVersionError, "已吊销"):
            self.ring.load(KEY, version=version, password=PASSWORD)

    def test_cli_error_exit_codes_preserved(self) -> None:
        self.ring.seal(KEY, "secret", PASSWORD, iterations=1_000)
        self.assertEqual(self._run_cli("load", KEY).returncode, 1)
        self.assertEqual(self._run_cli("load", KEY, "--password", "wrong").returncode, 1)
        self.assertEqual(self._run_cli("load", "missing").returncode, 2)
        self.ring.revoke(KEY, 1)
        revoked = self._run_cli("load", KEY, "--password", PASSWORD)
        self.assertEqual(revoked.returncode, 2)
        self.assertIn("已吊销", revoked.stderr)


if __name__ == "__main__":
    unittest.main()
