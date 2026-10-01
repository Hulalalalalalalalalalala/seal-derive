"""Versioned sealed material, derived from a passphrase when one is given."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

__all__ = ["KeyRing"]

RING_FILE = "keyring.json"

#: Scheme written by :meth:`KeyRing.seal` when a password is given. The
#: original material is encrypted under a PBKDF2-derived key, so ``load``
#: can recover it; the legacy ``pbkdf2-sha256`` scheme stored only the
#: derived value and is unrecoverable by design.
SEALED_SCHEME = "pbkdf2-sha256-seal"
LEGACY_SCHEME = "pbkdf2-sha256"
PLAIN_SCHEME = "plain"


def _derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=length)


def _seal_keys(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """Split a PBKDF2 master key into independent encryption and MAC keys."""
    master = _derive(password, salt, iterations, 32)
    enc_key = hmac.new(master, b"seal-derive/enc", hashlib.sha256).digest()
    mac_key = hmac.new(master, b"seal-derive/mac", hashlib.sha256).digest()
    return enc_key, mac_key


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC counter-mode keystream; stdlib-only stand-in for a stream cipher."""
    blocks = bytearray()
    counter = 0
    while len(blocks) < length:
        blocks += hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(blocks[:length])


def _verifier(mac_key: bytes, salt: bytes) -> bytes:
    """Password check tag: depends only on the password and salt, so a wrong
    password is distinguishable from a tampered ciphertext."""
    return hmac.new(mac_key, b"seal-derive/verify\x00" + salt, hashlib.sha256).digest()


def _seal_tag(mac_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(mac_key, b"seal-derive/tag\x00" + nonce + ciphertext, hashlib.sha256).digest()


def _b64decode_field(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("记录损坏：字段类型不正确")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:
        raise ValueError("记录损坏：字段不是合法的 base64") from None


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
        return json.loads(self.path.read_text(encoding="utf-8"))

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

    def _entry(self, document: dict, key_id: str) -> dict:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be a non-empty string")
        if key_id not in document["keys"]:
            raise KeyError(f"unknown key {key_id!r}")
        return document["keys"][key_id]

    def seal(self, key_id: str, material: str, password: str | None = None, iterations: int = 200_000) -> int:
        if not key_id:
            raise ValueError("key_id must be non-empty")
        if iterations <= 0:
            raise ValueError("iterations must be positive")
        document = self._read()
        entry = document["keys"].setdefault(key_id, {"versions": [], "active": 0})
        version = (max(int(item["version"]) for item in entry["versions"]) if entry["versions"] else 0) + 1
        plaintext = material.encode("utf-8")
        if password is None:
            record = {"version": version, "scheme": PLAIN_SCHEME,
                      "material": base64.b64encode(plaintext).decode("ascii")}
        else:
            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(16)
            enc_key, mac_key = _seal_keys(password, salt, iterations)
            stream = _keystream(enc_key, nonce, len(plaintext))
            ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
            record = {"version": version, "scheme": SEALED_SCHEME, "iterations": iterations,
                      "salt": base64.b64encode(salt).decode("ascii"),
                      "nonce": base64.b64encode(nonce).decode("ascii"),
                      "verifier": base64.b64encode(_verifier(mac_key, salt)).decode("ascii"),
                      "material": base64.b64encode(ciphertext).decode("ascii"),
                      "tag": base64.b64encode(_seal_tag(mac_key, nonce, ciphertext)).decode("ascii")}
        record["revoked"] = False
        entry["versions"].append(record)
        entry["active"] = version
        self._write(document)
        return version

    def versions(self, key_id: str) -> list[int]:
        return [int(item["version"]) for item in self._entry(self._read(), key_id)["versions"]]

    def active(self, key_id: str) -> int:
        return int(self._entry(self._read(), key_id)["active"])

    def _record(self, key_id: str, version: int | None) -> dict:
        entry = self._entry(self._read(), key_id)
        if version is None:
            wanted = entry["active"]
        else:
            try:
                wanted = int(version)
            except (TypeError, ValueError):
                raise ValueError(f"invalid version {version!r}") from None
            if wanted <= 0:
                raise ValueError("version must be a positive integer")
        for item in entry["versions"]:
            if int(item["version"]) == wanted:
                return item
        raise KeyError(f"unknown version {wanted} for {key_id!r}")

    def load(self, key_id: str, version: int | None = None, password: str | None = None) -> bytes:
        record = self._record(key_id, version)
        scheme = record.get("scheme")
        if scheme == PLAIN_SCHEME:
            if record["revoked"]:
                raise ValueError(f"version {record['version']} of {key_id!r} is revoked")
            return base64.b64decode(record["material"])
        if scheme == LEGACY_SCHEME:
            # Legacy records kept only the derived value, never the sealed
            # material, so the original bytes cannot be recovered from them.
            raise ValueError(
                f"不可恢复的旧记录：version {record.get('version')} of {key_id!r} "
                "只保存了派生值，请用原 material 重新 seal")
        if scheme != SEALED_SCHEME:
            raise ValueError(f"记录损坏：无法识别的封存方案 {scheme!r}")
        return self._unseal(record, key_id, password)

    @staticmethod
    def _unseal(record: dict, key_id: str, password: str | None) -> bytes:
        required = ("version", "iterations", "salt", "nonce", "verifier", "material", "tag", "revoked")
        if any(field not in record for field in required):
            raise ValueError("记录损坏：受口令记录的参数不全")
        if record["revoked"]:
            raise ValueError(f"version {record['version']} of {key_id!r} is revoked")
        try:
            iterations = int(record["iterations"])
        except (TypeError, ValueError):
            raise ValueError("记录损坏：iterations 不是整数") from None
        if iterations <= 0:
            raise ValueError("记录损坏：iterations 必须为正整数")
        salt = _b64decode_field(record["salt"])
        nonce = _b64decode_field(record["nonce"])
        verifier = _b64decode_field(record["verifier"])
        ciphertext = _b64decode_field(record["material"])
        tag = _b64decode_field(record["tag"])
        if password is None:
            raise ValueError("缺少口令：该版本由口令封存，取回时必须提供 password")
        enc_key, mac_key = _seal_keys(password, salt, iterations)
        if not secrets.compare_digest(verifier, _verifier(mac_key, salt)):
            raise ValueError("口令不匹配：提供的口令无法解封该版本")
        if not secrets.compare_digest(tag, _seal_tag(mac_key, nonce, ciphertext)):
            raise ValueError("记录损坏：密文认证失败，记录可能被篡改")
        stream = _keystream(enc_key, nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, stream))

    def set_active(self, key_id: str, version: int) -> None:
        document = self._read()
        entry = self._entry(document, key_id)
        self._record(key_id, version)
        entry["active"] = int(version)
        self._write(document)

    def revoke(self, key_id: str, version: int) -> None:
        document = self._read()
        self._record(key_id, version)
        for item in self._entry(document, key_id)["versions"]:
            if int(item["version"]) == int(version):
                item["revoked"] = True
        self._write(document)

    def is_revoked(self, key_id: str, version: int) -> bool:
        return bool(self._record(key_id, version)["revoked"])
