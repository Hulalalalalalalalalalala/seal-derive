"""Versioned sealed material, recoverable with a passphrase when one was given."""

from __future__ import annotations

import base64
import binascii
import contextlib
import errno
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path

__all__ = ["KeyRing"]

RING_FILE = "keyring.json"
#: Sibling file carrying the cross-process exclusive write lock. It is never
#: business state: it is only a lock byte stream and may be created/removed
#: freely; keyring.json itself is never touched while taking over a lock.
LOCK_FILE = ".keyring.lock"
#: Wait this long for the write lock before reporting a timeout, both across
#: processes and between callers (threads) in one process.
LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_POLL_SECONDS = 0.05
_TMP_GLOB = ".keyring-*.tmp"

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl
    fcntl = None
try:  # Windows
    import msvcrt
except ImportError:  # pragma: no cover - POSIX has no msvcrt
    msvcrt = None

PLAIN_SCHEME = "plain"
#: Older passphrase records that only stored the derived value: the original
#: material is gone, so they can never be opened as sealed records.
LEGACY_DERIVE_SCHEME = "pbkdf2-sha256"
#: New passphrase records: the original material is encrypted and authenticated,
#: so it can be recovered by anyone who supplies the right passphrase.
SEALED_SCHEME = "pbkdf2-sha256-sealed"

#: Schemes a stored record is allowed to name. A legacy derived-only record is
#: structurally valid -- its parameters need not be complete -- but the value
#: itself can never be recovered.
_KNOWN_SCHEMES = frozenset({PLAIN_SCHEME, LEGACY_DERIVE_SCHEME, SEALED_SCHEME})

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


class _FileLock:
    """A cross-process lock backed by an OS advisory lock on one file.

    POSIX uses ``flock`` (associated with the open file description, released
    automatically when the process dies, however it dies); Windows uses
    ``msvcrt.locking`` (byte-range LOCKFILE_EXCLUSIVE_LOCK with the same
    auto-release on process exit semantics). A caller killed with SIGKILL or
    crashing while holding the lock therefore can never leave a permanent
    stale lock: the kernel releases it, and the next waiter takes over within
    the polling window -- no rewriting or deleting of keyring.json is needed.
    """

    def __init__(self, path: Path, exclusive: bool, timeout: float) -> None:
        self.path = path
        self.exclusive = exclusive
        self.timeout = timeout
        self.handle: int | None = None

    def __enter__(self) -> "_FileLock":
        self.handle = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            self._acquire()
        except BaseException:
            os.close(self.handle)
            self.handle = None
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.handle is None:
            return
        try:
            self._release()
        finally:
            os.close(self.handle)
            self.handle = None

    def _acquire(self) -> None:
        deadline = time.monotonic() + self.timeout
        while True:
            if self._try_lock():
                return
            if time.monotonic() >= deadline:
                raise TimeoutError("获取密钥环写锁超时")
            time.sleep(_LOCK_POLL_SECONDS)

    def _try_lock(self) -> bool:
        if fcntl is not None:
            operation = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
            try:
                fcntl.flock(self.handle, operation | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                    raise
                return False
            return True
        # Windows: lock one byte at the start of the file.
        mode = msvcrt.LK_NBLCK if self.exclusive else msvcrt.LK_NBRLCK
        try:
            msvcrt.locking(self.handle, mode, 1)
        except OSError as error:
            if error.errno not in (errno.EDEADLK, errno.EACCES, errno.EAGAIN):
                raise
            return False
        return True

    def _release(self) -> None:
        if fcntl is not None:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
        else:
            os.lseek(self.handle, 0, os.SEEK_SET)
            msvcrt.locking(self.handle, msvcrt.LK_UNLCK, 1)


@contextlib.contextmanager
def _locked(ring: "KeyRing", exclusive: bool):
    """Serialise same-process callers (threads) then take the OS file lock.

    Both gates share one five-second budget: a caller that has not entered the
    critical section after that long gets ``TimeoutError``, whether it waited
    on another thread in this process or on another process holding the file.

    ``init`` creates ``root`` before locking. Any other call against a missing
    ``root`` fails here (or in ``_read`` for a directory without keyring.json)
    with the same ``FileNotFoundError`` text as in the single-process baseline;
    there is no check-then-act window in which such a call could write.
    """
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    if not ring._caller_lock.acquire(timeout=LOCK_TIMEOUT_SECONDS):
        raise TimeoutError("获取密钥环写锁超时")
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("获取密钥环写锁超时")
        try:
            with _FileLock(ring.lock_path, exclusive, remaining):
                yield
        except FileNotFoundError:
            # The lock file's parent directory vanished under us: report the
            # uninitialised ring, identical wording to _read().
            raise FileNotFoundError(
                f"no key ring at {ring.path}; run init first") from None
    finally:
        ring._caller_lock.release()


class KeyRing:
    """A key ring rooted at ``root``, safe for concurrent processes/callers."""

    def __init__(self, root: str | Path) -> None:
        self.directory = Path(root)
        self.path = self.directory / RING_FILE
        self.lock_path = self.directory / LOCK_FILE
        # This only serialises threads sharing this KeyRing instance before
        # they contend for the cross-process file lock.
        self._caller_lock = threading.RLock()

    def init(self) -> None:
        # Create the directory before taking the lock: the lock file needs a
        # home, and mkdir is idempotent. The empty-document write itself is
        # still serialised like every other mutation.
        self.directory.mkdir(parents=True, exist_ok=True)
        with _locked(self, exclusive=True):
            self._write({"keys": {}})

    def _read(self) -> dict:
        if not self.path.is_file():
            raise FileNotFoundError(f"no key ring at {self.path}; run init first")
        try:
            text = self.path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise CorruptRecordError("记录损坏：密钥环文件被截断或无法解析") from error
        try:
            document = json.loads(text)
        except json.JSONDecodeError as error:
            raise CorruptRecordError("记录损坏：密钥环文件被截断或无法解析") from error
        # Every entry point gets the same verdict: the whole document is either
        # structurally sound or rejected as one corrupt record.
        self._validate_document(document)
        return document

    def _validate_document(self, document: object) -> None:
        if not isinstance(document, dict) or not isinstance(document.get("keys"), dict):
            raise CorruptRecordError("记录损坏：密钥环结构非法")
        for key_id, entry in document["keys"].items():
            self._validate_entry(key_id, entry)

    def _validate_entry(self, key_id: str, entry: object) -> None:
        if not isinstance(entry, dict) or not isinstance(entry.get("versions"), list):
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的版本历史结构非法")
        active = entry.get("active")
        # bool is a subtype of int: an explicit bool is never a valid pointer.
        if isinstance(active, bool) or not isinstance(active, int) or active <= 0:
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的活动版本缺失或非法")
        numbers: list[int] = []
        seen: set[int] = set()
        for item in entry["versions"]:
            if not isinstance(item, dict):
                raise CorruptRecordError(f"记录损坏：{key_id!r} 含非法版本记录")
            number = self._version_number(item, key_id)
            if number in seen:
                raise CorruptRecordError(f"记录损坏：{key_id!r} 的版本号重复")
            seen.add(number)
            numbers.append(number)
            if not isinstance(item.get("revoked"), bool):
                raise CorruptRecordError(f"记录损坏：{key_id!r} 的吊销标记非法")
            self._validate_record_scheme(item, key_id)
        if numbers != sorted(numbers):
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的版本历史未按版本号升序")
        if active not in seen:
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的活动版本未指向真实版本")

    def _validate_record_scheme(self, item: dict, key_id: str) -> None:
        scheme = item.get("scheme")
        if not isinstance(scheme, str) or scheme not in _KNOWN_SCHEMES:
            raise CorruptRecordError(f"记录损坏：{key_id!r} 的封存方案缺失或未识别")
        if scheme == LEGACY_DERIVE_SCHEME:
            # Structurally a valid record; only the derived value was stored, so
            # load() still reports it as unrecoverable rather than corrupt.
            return
        if scheme == PLAIN_SCHEME:
            raw = _b64_field(item, "material")
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise CorruptRecordError(
                    f"记录损坏：{key_id!r} 的 material 不是合法 UTF-8") from error
            return
        # Sealed records: every parameter must be present with a legal encoding
        # and fixed length. The passphrase-bound check/tag are authenticated at
        # load time, when the passphrase is available.
        _b64_field(item, "salt", _SALT_BYTES)
        _positive_int_field(item, "iterations")
        _b64_field(item, "material")
        _b64_field(item, "check", _KEY_BYTES)
        _b64_field(item, "tag", _KEY_BYTES)

    def _write(self, document: dict) -> None:
        # Never persist a structurally invalid document, even one assembled in
        # process; callers validated the snapshot they mutated, this validates
        # the document they are about to atomically commit.
        self._validate_document(document)
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and not os.access(self.path, os.W_OK):
            raise PermissionError(f"key ring file is not writable: {self.path}")
        # The exclusive write lock is held here, so any sibling temp files are
        # leftovers of a process that died mid-write; its rename either
        # completed or never happened, so these partial documents are dead.
        for leftover in self.directory.glob(_TMP_GLOB):
            try:
                leftover.unlink()
            except OSError:
                pass
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
        # The whole document (this entry included) was validated by _read()
        # under the same lock snapshot; here we only resolve the key.
        if key_id not in document["keys"]:
            raise KeyError(f"unknown key {key_id!r}")
        return document["keys"][key_id]

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
        # Read, validate, assign the next version, mutate and atomically replace
        # all inside one exclusive lock: concurrent sealers queue and observe
        # each other's committed versions, so numbers stay gapless and unique
        # and the final active version is the last seal to complete.
        with _locked(self, exclusive=True):
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
        with _locked(self, exclusive=False):
            document = self._read()
            return [self._version_number(item, key_id) for item in self._entry(document, key_id)["versions"]]

    def active(self, key_id: str) -> int:
        self._check_key_id(key_id)
        with _locked(self, exclusive=False):
            return int(self._entry(self._read(), key_id)["active"])

    def _record_in(self, entry: dict, key_id: str, version: int | None) -> dict:
        wanted = entry["active"] if version is None else int(version)
        for item in entry["versions"]:
            if self._version_number(item, key_id) == wanted:
                return item
        raise KeyError(f"unknown version {wanted} for {key_id!r}")

    def _record(self, key_id: str, version: int | None) -> dict:
        with _locked(self, exclusive=False):
            entry = self._entry(self._read(), key_id)
            return self._record_in(entry, key_id, version)

    def load(self, key_id: str, version: int | None = None, password: str | None = None) -> bytes:
        self._check_key_id(key_id)
        version = self._check_version(version)
        # One shared-lock snapshot for the whole open: resolving the version
        # (including the default, which reads ``active``), checking revocation
        # and decrypting all see the same committed document. A concurrent
        # revoke/set-active either committed before this snapshot (its new
        # state is used) or waits for the shared lock and only commits once the
        # load has finished -- never a revoked record handed back as material,
        # a half-resolved active, or fields read mid-change.
        with _locked(self, exclusive=False):
            entry = self._entry(self._read(), key_id)
            record = self._record_in(entry, key_id, version)
            return self._material_from(record, key_id, password)

    # Call only while holding the load snapshot: the record is fresh from the
    # document read under the shared lock and no writer can commit until this
    # returns, so revocation state observed here stays true through decrypt.
    def _material_from(self, record: dict, key_id: str, password: str | None) -> bytes:
        if not isinstance(record, dict) or "scheme" not in record:
            raise CorruptRecordError("记录损坏：缺少封存方案")
        if record.get("revoked"):
            raise RevokedVersionError(f"version {record.get('version')!r} of {key_id!r} 已吊销")
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
        with _locked(self, exclusive=True):
            document = self._read()
            entry = self._entry(document, key_id)
            self._record_in(entry, key_id, version)
            entry["active"] = int(version)
            self._write(document)

    def revoke(self, key_id: str, version: int) -> None:
        key_id = self._check_key_id(key_id)
        version = self._check_version(version)
        with _locked(self, exclusive=True):
            document = self._read()
            entry = self._entry(document, key_id)
            self._record_in(entry, key_id, version)
            for item in entry["versions"]:
                if item["version"] == version:
                    item["revoked"] = True
            self._write(document)

    def is_revoked(self, key_id: str, version: int) -> bool:
        self._check_key_id(key_id)
        self._check_version(version)
        return bool(self._record(key_id, version)["revoked"])
