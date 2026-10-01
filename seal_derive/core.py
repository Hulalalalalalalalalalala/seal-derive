"""Versioned sealed material, recoverable with a passphrase when one was given."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

__all__ = ["KeyRing"]

RING_FILE = "keyring.json"

PLAIN_SCHEME = "plain"
#: Older passphrase records that only stored the derived value: the original
#: material is gone, so they can never be opened as sealed records.
LEGACY_DERIVE_SCHEME = "pbkdf2-sha256"
#: New passphrase records: the original material is encrypted and authenticated,
#: so it can be recovered by anyone who supplies the right passphrase.
SEALED_SCHEME = "pbkdf2-sha256-sealed"

_SALT_BYTES = 16
_KEY_BYTES = 32
_CHECK_LABEL = b"seal_derive/pbkdf2-sha256-sealed/v1/password-check"
_TAG_LABEL = b"seal_derive/pbkdf2-sha256-sealed/v1"


def _derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=length)


def _keystream(key: bytes, length: int) -> bytes:
    """HMAC-SHA256 in counter mode: a stdlib keystream over ``key``."""
    blocks: list[bytes] = []
    counter = 1
    produced = 0
    while produced < length:
        blocks.append(hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha256).digest())
        produced += 32
        counter += 1
    return b"".join(blocks)[:length]


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _aad(version: int, salt: bytes, iterations: int, check: bytes) -> bytes:
    return b"|".join((
        _TAG_LABEL,
        str(int(version)).encode("ascii"),
        str(int(iterations)).encode("ascii"),
        salt,
        check,
    ))


class SealError(ValueError):
    """A verification failure while opening a sealed version (CLI exit code 1)."""


class MissingPasswordError(SealError):
    """A passphrase-sealed version was opened without a passphrase."""


class BadPasswordError(SealError):
    """The supplied passphrase does not match the sealed version."""


class CorruptRecordError(SealError):
    """A stored record is truncated, missing parameters, or fails authentication."""


class UnrecoverableRecordError(SealError):
    """A legacy derived-only record cannot yield the original material."""


class RevokedVersionError(ValueError):
    """A revoked version was requested through ``load``.

    Not a :class:`SealError`: this is an invalid use rather than a storage or
    verification failure, so the CLI reports it as a usage error (exit 2).
    """


def _record_field(record: dict, name: str):
    if not isinstance(record, dict) or name not in record:
        raise CorruptRecordError(f"记录损坏：字段 {name} 缺失或参数不全")
    return record[name]


def _b64_field(record: dict, name: str, length: int | None = None) -> bytes:
    value = _record_field(record, name)
    if not isinstance(value, str):
        raise CorruptRecordError(f"记录损坏：字段 {name} 不是合法文本")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise CorruptRecordError(f"记录损坏：字段 {name} 无法解码") from error
    if length is not None and len(raw) != length:
        raise CorruptRecordError(f"记录损坏：字段 {name} 被截断或长度非法")
    return raw


def _positive_int_field(record: dict, name: str) -> int:
    value = _record_field(record, name)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CorruptRecordError(f"记录损坏：参数 {name} 缺失或非法")
    return value


class KeyRing:
    """A single-process key ring rooted at ``root``."""

    def __init__(self, root: str | Path) -> None:
        self.directory = Path(root)
        self.path = self.directory / RING_FILE

    def init(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write({"keys": {}})

    def _read(self) -> dict:
        if not self.path.is_file():
            raise FileNotFoundError(f"no key ring at {self.path}; run init first")
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise CorruptRecordError("记录损坏：密钥环文件被截断或无法解析") from error
        if not isinstance(document, dict) or not isinstance(document.get("keys"), dict):
            raise CorruptRecordError("记录损坏：密钥环结构非法")
        return document

    def _write(self, document: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and not os.access(self.path, os.W_OK):
            raise PermissionError(f"key ring file is not writable: {self.path}")
        payload = json.dumps(document, sort_keys=True, indent=2)
        # Write to a sibling temp file, fsync it, then atomically replace
        # keyring.json: a crash leaves either the old or the new document.
        handle, temporary = tempfile.mkstemp(dir=self.directory, prefix=".keyring-", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        self._fsync_directory()

    def _fsync_directory(self) -> None:
        # Persist the rename itself. Windows cannot fsync directories, but
        # os.replace is already atomic there, so this is a no-op off POSIX.
        if not hasattr(os, "O_DIRECTORY"):
            return
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _check_key_id(key_id: str) -> str:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be a non-empty string")
        return key_id

    @staticmethod
    def _check_version(version: int | None) -> int | None:
        if version is None:
            return None
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError("version must be a positive integer")
        return version

    def _entry(self, document: dict, key_id: str) -> dict:
        if key_id not in document["keys"]:
            raise KeyError(f"unknown key {key_id!r}")
        entry = document["keys"][key_id]
        if not isinstance(entry, dict) or not isinstance(entry.get("versions"), list) \
                or not isinstance(entry.get("active"), int):
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的版本历史结构非法")
        for item in entry["versions"]:
            if not isinstance(item, dict):
                raise CorruptRecordError(f"记录损坏：{key_id!r} 含非法版本记录")
            self._version_number(item, key_id)
            if "revoked" in item and not isinstance(item["revoked"], bool):
                raise CorruptRecordError(f"记录损坏：{key_id!r} 的吊销标记非法")
        return entry

    def _version_number(self, item: dict, key_id: str) -> int:
        value = item.get("version")
        if isinstance(value, bool) or not isinstance(value, int):
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的版本号缺失或非法")
        if value <= 0:
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的版本号非法")
        return value

    def seal(self, key_id: str, material: str, password: str | None = None, iterations: int = 200_000) -> int:
        key_id = self._check_key_id(key_id)
        if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations <= 0:
            raise ValueError("iterations must be positive")
        document = self._read()
        if key_id in document["keys"]:
            entry = self._entry(document, key_id)
        else:
            entry = {"versions": [], "active": 0}
            document["keys"][key_id] = entry
        version = max((self._version_number(item, key_id) for item in entry["versions"]), default=0) + 1
        if password is None:
            record = {"version": version, "scheme": PLAIN_SCHEME,
                      "material": base64.b64encode(material.encode("utf-8")).decode("ascii")}
        else:
            plaintext = material.encode("utf-8")
            salt = secrets.token_bytes(_SALT_BYTES)
            derived = _derive(password, salt, iterations, 3 * _KEY_BYTES)
            enc_key, mac_key, check_key = derived[:_KEY_BYTES], derived[_KEY_BYTES:2 * _KEY_BYTES], derived[2 * _KEY_BYTES:]
            ciphertext = _xor(plaintext, _keystream(enc_key, len(plaintext)))
            check = hmac.new(check_key, _CHECK_LABEL, hashlib.sha256).digest()
            tag = hmac.new(mac_key, _aad(version, salt, iterations, check) + ciphertext, hashlib.sha256).digest()
            record = {"version": version, "scheme": SEALED_SCHEME, "iterations": iterations,
                      "salt": base64.b64encode(salt).decode("ascii"),
                      "material": base64.b64encode(ciphertext).decode("ascii"),
                      "check": base64.b64encode(check).decode("ascii"),
                      "tag": base64.b64encode(tag).decode("ascii")}
        record["revoked"] = False
        entry["versions"].append(record)
        entry["active"] = version
        self._write(document)
        return version

    def versions(self, key_id: str) -> list[int]:
        self._check_key_id(key_id)
        document = self._read()
        return [self._version_number(item, key_id) for item in self._entry(document, key_id)["versions"]]

    def active(self, key_id: str) -> int:
        self._check_key_id(key_id)
        return int(self._entry(self._read(), key_id)["active"])

    def _record(self, key_id: str, version: int | None) -> dict:
        entry = self._entry(self._read(), key_id)
        wanted = entry["active"] if version is None else int(version)
        for item in entry["versions"]:
            if self._version_number(item, key_id) == wanted:
                return item
        raise KeyError(f"unknown version {wanted} for {key_id!r}")

    def load(self, key_id: str, version: int | None = None, password: str | None = None) -> bytes:
        self._check_key_id(key_id)
        version = self._check_version(version)
        record = self._record(key_id, version)
        if not isinstance(record, dict) or "scheme" not in record:
            raise CorruptRecordError("记录损坏：缺少封存方案")
        if record.get("revoked"):
            raise RevokedVersionError(f"version {record.get('version', version)!r} of {key_id!r} 已吊销")
        scheme = record["scheme"]
        if scheme == PLAIN_SCHEME:
            return _b64_field(record, "material")
        if scheme == LEGACY_DERIVE_SCHEME:
            # Only the PBKDF2 output was ever stored; the original material is
            # not recoverable, even when the passphrase is supplied.
            raise UnrecoverableRecordError(
                "不可恢复的旧记录：该版本仅保存了口令派生值，无法取回原始 material")
        if scheme == SEALED_SCHEME:
            return self._open_sealed(record, password)
        raise CorruptRecordError(f"记录损坏：未知封存方案 {scheme!r}")

    def _open_sealed(self, record: dict, password: str | None) -> bytes:
        # Parse and validate every stored parameter first: truncation, missing
        # fields and malformed encodings are record corruption, even when no
        # passphrase was supplied. The version number was validated when the
        # entry was loaded.
        version = record["version"]
        salt = _b64_field(record, "salt", _SALT_BYTES)
        iterations = _positive_int_field(record, "iterations")
        ciphertext = _b64_field(record, "material")
        check = _b64_field(record, "check", _KEY_BYTES)
        tag = _b64_field(record, "tag", _KEY_BYTES)
        if password is None:
            raise MissingPasswordError("缺少口令：该版本由口令封存，load 时必须提供 password")
        derived = _derive(password, salt, iterations, 3 * _KEY_BYTES)
        enc_key, mac_key, check_key = derived[:_KEY_BYTES], derived[_KEY_BYTES:2 * _KEY_BYTES], derived[2 * _KEY_BYTES:]
        expected_check = hmac.new(check_key, _CHECK_LABEL, hashlib.sha256).digest()
        # The check value authenticates the passphrase independently of the
        # ciphertext, so a wrong passphrase is distinguishable from tampering.
        if not secrets.compare_digest(check, expected_check):
            raise BadPasswordError("口令不匹配：password 与封存该版本时使用的口令不一致")
        expected_tag = hmac.new(mac_key, _aad(version, salt, iterations, check) + ciphertext,
                                hashlib.sha256).digest()
        if not secrets.compare_digest(tag, expected_tag):
            raise CorruptRecordError("记录损坏：密文未通过认证，记录可能被篡改或截断")
        return _xor(ciphertext, _keystream(enc_key, len(ciphertext)))

    def set_active(self, key_id: str, version: int) -> None:
        key_id = self._check_key_id(key_id)
        version = self._check_version(version)
        document = self._read()
        entry = self._entry(document, key_id)
        self._record(key_id, version)
        entry["active"] = int(version)
        self._write(document)

    def revoke(self, key_id: str, version: int) -> None:
        key_id = self._check_key_id(key_id)
        version = self._check_version(version)
        document = self._read()
        self._record(key_id, version)
        for item in self._entry(document, key_id)["versions"]:
            if item["version"] == version:
                item["revoked"] = True
        self._write(document)

    def is_revoked(self, key_id: str, version: int) -> bool:
        self._check_key_id(key_id)
        self._check_version(version)
        return bool(self._record(key_id, version)["revoked"])
