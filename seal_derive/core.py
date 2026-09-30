"""Versioned sealed material, derived from a passphrase when one is given."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from pathlib import Path

__all__ = ["KeyRing"]

RING_FILE = "keyring.json"


def _derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=length)


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
        self.path.write_text(json.dumps(document, sort_keys=True, indent=2), encoding="utf-8")

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
