"""Versioned sealed material, derived from a passphrase when one is given."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

__all__ = ["KeyRing"]

RING_FILE = "keyring.json"

#: Scratch file staged next to the ring file; never read back as ring state.
TEMP_FILE = f".{RING_FILE}.tmp"


def _derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=length)


def _fsync_directory(directory: Path) -> None:
    """Make a rename/replace in *directory* durable; a no-op on Windows.

    Windows has no fsync for directory handles; ``os.replace`` there is already
    an atomic replace (MoveFileExW), so durability of the swap needs no extra
    step. On POSIX the directory entry change must be synced separately.
    """
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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
        """Crash-consistent replace of the ring file.

        The full document is written to a scratch file in the same directory,
        flushed and synced, then swapped in with ``os.replace`` (an atomic
        replace on both POSIX and Windows) followed by a directory fsync on
        POSIX. A process killed at any point therefore leaves either the
        previous or the new complete document at :attr:`path`; the scratch
        file is never read as ring state and is unlinked on failure.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        # os.replace on POSIX would succeed over a read-only target; keep the
        # baseline behaviour of writing through keyring.json and failing with
        # OSError when that file is not writable.
        previous_mode = None
        if self.path.exists():
            previous_mode = stat.S_IMODE(self.path.stat().st_mode)
            if not os.access(self.path, os.W_OK):
                raise PermissionError(f"key ring file is not writable: {self.path}")
        payload = json.dumps(document, sort_keys=True, indent=2)
        temp = self.directory / TEMP_FILE
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666)
        try:
            # fdopen owns fd: the scratch file is fully closed before the
            # replace, which matters for Windows' sharing rules.
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            # Truncating in place (the old write path) preserved the file's
            # mode; carry it onto the replacement before the atomic swap.
            if previous_mode is not None:
                os.chmod(temp, previous_mode)
            os.replace(temp, self.path)
        except BaseException:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            raise
        else:
            _fsync_directory(self.directory)

    def _entry(self, document: dict, key_id: str) -> dict:
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
        version = (entry["versions"][-1]["version"] if entry["versions"] else 0) + 1
        salt = secrets.token_bytes(16)
        if password is None:
            record = {"version": version, "scheme": "plain", "material": base64.b64encode(material.encode("utf-8")).decode("ascii")}
        else:
            record = {"version": version, "scheme": "pbkdf2-sha256", "iterations": iterations,
                      "salt": base64.b64encode(salt).decode("ascii"),
                      "material": base64.b64encode(_derive(password, salt, iterations)).decode("ascii")}
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
        wanted = entry["active"] if version is None else int(version)
        for item in entry["versions"]:
            if int(item["version"]) == wanted:
                return item
        raise KeyError(f"unknown version {wanted} for {key_id!r}")

    def load(self, key_id: str, version: int | None = None, password: str | None = None) -> bytes:
        record = self._record(key_id, version)
        if record["revoked"]:
            raise ValueError(f"version {record['version']} of {key_id!r} is revoked")
        raw = base64.b64decode(record["material"])
        if record["scheme"] == "plain":
            return raw
        if password is None:
            raise ValueError("this version was derived from a passphrase; supply one")
        # The derived material is re-derived from the caller's passphrase and compared to the stored one.
        expected = _derive(password, base64.b64decode(record["salt"]), int(record["iterations"]), len(raw))
        if not secrets.compare_digest(expected, raw):
            raise ValueError("passphrase does not match this version")
        return raw

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
