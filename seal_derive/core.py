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
from typing import NamedTuple

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
#: Current passphrase records: identical derivation to :data:`SEALED_SCHEME`,
#: but the authentication tag additionally binds the exact ``key_id``. A record
#: copied or moved to another key, whose owning key was renamed, or whose
#: version was rewritten can no longer authenticate -- only the original key
#: name under which it was sealed opens it. The store directory is deliberately
#: not bound, so relocating the whole directory keeps every record readable.
SEALED_V2_SCHEME = "pbkdf2-sha256-sealed-v2"

#: Schemes a stored record is allowed to name. A legacy derived-only record is
#: structurally valid -- its parameters need not be complete -- but the value
#: itself can never be recovered.
_KNOWN_SCHEMES = frozenset(
    {PLAIN_SCHEME, LEGACY_DERIVE_SCHEME, SEALED_SCHEME, SEALED_V2_SCHEME})

_SALT_BYTES = 16
_KEY_BYTES = 32
_CHECK_LABEL = b"seal_derive/pbkdf2-sha256-sealed/v1/password-check"
_TAG_LABEL = b"seal_derive/pbkdf2-sha256-sealed/v1"
_TAG_LABEL_V2 = b"seal_derive/pbkdf2-sha256-sealed/v2"


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


def _aad(version: int, salt: bytes, iterations: int, check: bytes, key_id: str | None = None) -> bytes:
    if key_id is None:
        return b"|".join((
            _TAG_LABEL,
            str(int(version)).encode("ascii"),
            str(int(iterations)).encode("ascii"),
            salt,
            check,
        ))
    # v2 binds the exact key name as its UTF-8 bytes. The 64-bit length prefix
    # makes the name boundary unambiguous even when the name contains the
    # separator byte, digits or non-ASCII text: a name copied onto another
    # key, renamed, or represented with a different Unicode spelling can never
    # reproduce this AAD. The store path is intentionally absent, so moving the
    # whole directory does not invalidate records.
    name = key_id.encode("utf-8")
    return b"|".join((
        _TAG_LABEL_V2,
        len(name).to_bytes(8, "big") + name,
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


class ActiveVersionConflictError(SealError):
    """The active version no longer matches the caller's precondition.

    Raised by ``rotate_password``/``rotate_password_batch``/
    ``set_active_batch`` when an ``expected_active`` precondition is given
    and the key's current active version differs from it -- another change
    committed first. Like every :class:`SealError` this is a verification
    failure (CLI exit code 1), not a usage mistake.
    """


class RevokedVersionError(ValueError):
    """A revoked version was requested through ``load``.

    Not a :class:`SealError`: this is an invalid use rather than a storage or
    verification failure, so the CLI reports it as a usage error (exit 2).
    """


class _BatchRequest(NamedTuple):
    """One normalised item of a ``rotate_password_batch`` request list.

    Defaults and allowed fields mirror ``rotate_password`` exactly: only
    ``key_id`` and ``new_password`` are required; the old ``password`` defaults
    to ``None`` (active sources are plain in the un-sealed case, otherwise the
    sealed check reports the missing passphrase), ``version`` to active,
    ``iterations`` to 200_000, ``revoke_source`` to ``False`` and
    ``expected_active`` to ``None`` (no active-version precondition).
    """

    key_id: str
    new_password: str
    password: str | None = None
    version: int | None = None
    iterations: int = 200_000
    revoke_source: bool = False
    expected_active: int | None = None


class _LoadRequest(NamedTuple):
    """One normalised item of a ``load_batch`` request list.

    Defaults mirror ``load`` exactly: only ``key_id`` is required; ``version``
    defaults to ``None`` (the active version) and ``password`` to ``None``.
    Unlike the rotation batch, a key_id may appear any number of times, even
    asking for different historical versions in one batch.
    """

    key_id: str
    version: int | None = None
    password: str | None = None


class _SetActiveRequest(NamedTuple):
    """One normalised item of a ``set_active_batch`` request list.

    Unlike ``set_active`` the target ``version`` is always explicit (there is
    no active-default to resolve) and must be unrevoked at commit time;
    ``expected_active`` defaults to ``None`` (no active-version
    precondition). A key_id may appear only once in the batch.
    """

    key_id: str
    version: int
    expected_active: int | None = None


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

    @staticmethod
    def _check_expected_active(expected_active: int | None) -> int | None:
        # ``None`` (or omitting the argument) keeps the unconditional
        # behaviour; anything else must be a non-bool positive integer and is
        # rejected before any storage is touched.
        if expected_active is None:
            return None
        if isinstance(expected_active, bool) or not isinstance(expected_active, int) \
                or expected_active <= 0:
            raise ValueError("expected_active must be a positive integer")
        return expected_active

    @staticmethod
    def _check_active_precondition(entry: dict, key_id: str,
                                   expected_active: int | None) -> None:
        """Compare the caller's precondition against the snapshot's active.

        Only the current active version *number* is compared: the expected
        value need not exist in the history, and matching it says nothing
        about whether the rest of the history changed. A mismatch is a
        conflict no matter whether the expected version exists.
        """
        if expected_active is None:
            return
        actual = int(entry["active"])
        if actual != expected_active:
            raise ActiveVersionConflictError(
                f"活动版本冲突：{key_id!r} 的预期活动版本为 {expected_active}，"
                f"实际活动版本为 {actual}")

    @staticmethod
    def _check_batch_requests(requests) -> list[_BatchRequest]:
        """Validate and normalise a whole batch before any storage is touched.

        The outer value must be a non-empty list of plain dicts; every item
        must name exactly ``key_id`` and ``new_password`` plus any subset of
        ``password``/``version``/``iterations``/``revoke_source``/
        ``expected_active``. Per-field rules and defaults are identical to
        ``rotate_password``, and a ``key_id`` may only appear once in the
        batch. The caller's objects are only read, never copied from or
        mutated: the returned tuples are what the commit phase works from.
        """
        if not isinstance(requests, list) or not requests:
            raise ValueError("requests must be a non-empty list")
        allowed = frozenset(_BatchRequest._fields)
        required = ("key_id", "new_password")
        normalised: list[_BatchRequest] = []
        seen: set[str] = set()
        for request in requests:
            if not isinstance(request, dict):
                raise ValueError("each request must be a dict")
            fields = request.keys()
            unknown = fields - allowed
            if unknown:
                raise ValueError(f"unknown field {next(iter(unknown))!r}")
            missing = [name for name in required if name not in request]
            if missing:
                raise ValueError(f"missing field {missing[0]!r}")
            key_id = KeyRing._check_key_id(request["key_id"])
            if key_id in seen:
                raise ValueError(f"duplicate key_id {key_id!r} in batch")
            seen.add(key_id)
            new_password = request["new_password"]
            if not isinstance(new_password, str):
                raise ValueError("new_password must be a string")
            password = request.get("password")
            if password is not None and not isinstance(password, str):
                raise ValueError("password must be a string or None")
            version = KeyRing._check_version(request.get("version"))
            iterations = request.get("iterations", 200_000)
            if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations <= 0:
                raise ValueError("iterations must be positive")
            revoke_source = request.get("revoke_source", False)
            if not isinstance(revoke_source, bool):
                raise ValueError("revoke_source must be a boolean")
            expected_active = KeyRing._check_expected_active(request.get("expected_active"))
            normalised.append(_BatchRequest(
                key_id=key_id, new_password=new_password, password=password,
                version=version, iterations=iterations, revoke_source=revoke_source,
                expected_active=expected_active))
        return normalised

    @staticmethod
    def _check_load_requests(requests) -> list[_LoadRequest]:
        """Validate and normalise a whole ``load_batch`` before storage access.

        The outer value must be a non-empty list of plain dicts; every item
        must name ``key_id`` and may additionally name only ``version`` and
        ``password``. A missing/``None`` version means the active version; a
        version must otherwise be a non-bool positive integer, and a
        passphrase must be a string or ``None``. The same ``key_id`` may appear
        repeatedly, including for different historical versions. The caller's
        objects are only read, never copied from or mutated: the returned
        tuples are what the open phase works from.
        """
        if not isinstance(requests, list) or not requests:
            raise ValueError("requests must be a non-empty list")
        allowed = frozenset(_LoadRequest._fields)
        normalised: list[_LoadRequest] = []
        for request in requests:
            if not isinstance(request, dict):
                raise ValueError("each request must be a dict")
            fields = request.keys()
            unknown = fields - allowed
            if unknown:
                raise ValueError(f"unknown field {next(iter(unknown))!r}")
            if "key_id" not in request:
                raise ValueError("missing field 'key_id'")
            key_id = KeyRing._check_key_id(request["key_id"])
            version = KeyRing._check_version(request.get("version"))
            password = request.get("password")
            if password is not None and not isinstance(password, str):
                raise ValueError("password must be a string or None")
            normalised.append(_LoadRequest(key_id=key_id, version=version,
                                           password=password))
        return normalised

    @staticmethod
    def _check_set_active_requests(requests) -> list[_SetActiveRequest]:
        """Validate and normalise a whole ``set_active_batch`` up front.

        The outer value must be a non-empty list of plain dicts; every item
        must name exactly ``key_id`` and ``version`` plus optionally
        ``expected_active``. The key id follows ``set_active``'s rule, the
        target version must be a non-bool positive integer (``None`` is not a
        valid explicit target here), and ``expected_active`` follows
        ``rotate_password``'s precondition rule. A ``key_id`` may only appear
        once in the batch. The caller's objects are only read, never copied
        from or mutated: the returned tuples are what the commit phase works
        from.
        """
        if not isinstance(requests, list) or not requests:
            raise ValueError("requests must be a non-empty list")
        allowed = frozenset(_SetActiveRequest._fields)
        required = ("key_id", "version")
        normalised: list[_SetActiveRequest] = []
        seen: set[str] = set()
        for request in requests:
            if not isinstance(request, dict):
                raise ValueError("each request must be a dict")
            fields = request.keys()
            unknown = fields - allowed
            if unknown:
                raise ValueError(f"unknown field {next(iter(unknown))!r}")
            missing = [name for name in required if name not in request]
            if missing:
                raise ValueError(f"missing field {missing[0]!r}")
            key_id = KeyRing._check_key_id(request["key_id"])
            if key_id in seen:
                raise ValueError(f"duplicate key_id {key_id!r} in batch")
            seen.add(key_id)
            version = KeyRing._check_version(request["version"])
            if version is None:
                raise ValueError("version must be a positive integer")
            expected_active = KeyRing._check_expected_active(
                request.get("expected_active"))
            normalised.append(_SetActiveRequest(
                key_id=key_id, version=version, expected_active=expected_active))
        return normalised

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

    @staticmethod
    def _sealed_v2_record(version: int, key_id: str, plaintext: bytes,
                          password: str, iterations: int) -> dict:
        """Build a v2 sealed record for ``plaintext`` under ``password``.

        Shared by ``seal`` and ``rotate_password`` so a password rotation
        rewrites the same material bytes with a fresh salt, the requested
        iteration count, and the key name/version bound into the tag.
        """
        salt = secrets.token_bytes(_SALT_BYTES)
        derived = _derive(password, salt, iterations, 3 * _KEY_BYTES)
        enc_key, mac_key, check_key = derived[:_KEY_BYTES], derived[_KEY_BYTES:2 * _KEY_BYTES], derived[2 * _KEY_BYTES:]
        ciphertext = _xor(plaintext, _keystream(enc_key, len(plaintext)))
        # The check label stays shared with v1: it only certifies the
        # passphrase independently of the payload. The v2/v1 split
        # lives entirely in the tag AAD, so rewriting the scheme field
        # (v2->v1 downgrade or v1->v2 upgrade) fails the tag and is
        # reported as record corruption, not as a wrong passphrase.
        check = hmac.new(check_key, _CHECK_LABEL, hashlib.sha256).digest()
        tag = hmac.new(
            mac_key, _aad(version, salt, iterations, check, key_id) + ciphertext,
            hashlib.sha256).digest()
        return {"version": version, "scheme": SEALED_V2_SCHEME, "iterations": iterations,
                "salt": base64.b64encode(salt).decode("ascii"),
                "material": base64.b64encode(ciphertext).decode("ascii"),
                "check": base64.b64encode(check).decode("ascii"),
                "tag": base64.b64encode(tag).decode("ascii")}

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
                record = self._sealed_v2_record(
                    version, key_id, material.encode("utf-8"), password, iterations)
            record["revoked"] = False
            entry["versions"].append(record)
            entry["active"] = version
            self._write(document)
        return version

    def rotate_password(self, key_id: str, new_password: str, password: str | None = None,
                        version: int | None = None, iterations: int = 200_000,
                        revoke_source: bool = False,
                        expected_active: int | None = None) -> int:
        key_id = self._check_key_id(key_id)
        if not isinstance(new_password, str):
            raise ValueError("new_password must be a string")
        if password is not None and not isinstance(password, str):
            raise ValueError("password must be a string or None")
        version = self._check_version(version)
        if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations <= 0:
            raise ValueError("iterations must be positive")
        if not isinstance(revoke_source, bool):
            raise ValueError("revoke_source must be a boolean")
        expected_active = self._check_expected_active(expected_active)
        # Everything happens inside one exclusive lock: authenticate against
        # the committed snapshot (load's order and verdicts), then append the
        # re-sealed version, repoint active and optionally revoke the source
        # before a single atomic replace. No failure path mutates the file.
        # The precondition check and the rotation it guards are one atomic
        # unit: a concurrent change commits either before this snapshot (and
        # is what the precondition compares against) or after the commit.
        with _locked(self, exclusive=True):
            document = self._read()
            entry = self._entry(document, key_id)
            # The precondition follows the key lookup but precedes source
            # resolution, so a conflict outranks this item's unknown source
            # version, revocation and passphrase failures.
            self._check_active_precondition(entry, key_id, expected_active)
            source = self._record_in(entry, key_id, version)
            # Recover the original material with load's exact checks: plain
            # ignores the old password; v1/v2 authenticate it. Every failure
            # type and wording therefore matches load, and the revoked check
            # happens against the snapshot we are about to mutate.
            plaintext = self._material_from(source, key_id, password)
            new_version = max(
                (self._version_number(item, key_id) for item in entry["versions"]), default=0) + 1
            record = self._sealed_v2_record(
                new_version, key_id, plaintext, new_password, iterations)
            record["revoked"] = False
            entry["versions"].append(record)
            entry["active"] = new_version
            if revoke_source:
                source["revoked"] = True
            self._write(document)
        return new_version

    def rotate_password_batch(self, requests) -> list[int]:
        """Rotate several keys in one key ring as a single change.

        ``requests`` is a non-empty list of dicts with the same fields as
        :meth:`rotate_password` (``key_id`` and ``new_password`` required);
        the whole list is structurally validated first, without touching
        storage. Every item is then resolved against one committed snapshot:
        an item carrying ``expected_active`` first compares it against that
        key's current active version (a mismatch raises
        :class:`ActiveVersionConflictError` before that item's source
        resolution), then the source version (active by default) is
        authenticated with ``load``'s exact order and verdicts, and its
        material bytes are re-sealed as a fresh v2 record using a new salt. The version number is that key's own
        history max plus one; each new version is unrevoked and active, and
        only that item's ``revoke_source`` revokes its source. Failures are
        reported in request order and abort the batch before any mutation, so
        ``keyring.json`` keeps its exact prior bytes. On success one atomic
        replace commits every item, and the new version numbers are returned
        in request order.
        """
        normalised = self._check_batch_requests(requests)
        # One exclusive lock for the entire batch: concurrent callers observe
        # only the snapshot before the batch or the document after it commits,
        # never a partially applied list. All reads, authentications and the
        # single atomic write happen against that one snapshot, so nothing is
        # re-read per item and no failure path can persist part of the batch.
        with _locked(self, exclusive=True):
            document = self._read()
            # Resolve every item in request order first; the first failure
            # (unknown key/version, revoked/unrecoverable source, missing or
            # bad passphrase, failed authentication) aborts before the
            # document is mutated anywhere.
            resolved: list[tuple[_BatchRequest, dict, dict, bytes, int]] = []
            for request in normalised:
                entry = self._entry(document, request.key_id)
                # Per item, in request order: key lookup, then the active
                # precondition, then source resolution and authentication --
                # so a conflict outranks this item's unknown source version,
                # revocation and passphrase failures, but never an earlier
                # item's failure.
                self._check_active_precondition(
                    entry, request.key_id, request.expected_active)
                source = self._record_in(entry, request.key_id, request.version)
                plaintext = self._material_from(
                    source, request.key_id, request.password)
                new_version = max(
                    (self._version_number(item, request.key_id)
                     for item in entry["versions"]), default=0) + 1
                resolved.append((request, entry, source, plaintext, new_version))
            # Every source authenticated: now build and append the fresh v2
            # records. Distinct key_ids within the batch (checked up front)
            # mean each entry is touched by at most one item, so the per-key
            # max-plus-one numbers computed above cannot collide.
            new_versions: list[int] = []
            for request, entry, source, plaintext, new_version in resolved:
                record = self._sealed_v2_record(
                    new_version, request.key_id, plaintext,
                    request.new_password, request.iterations)
                record["revoked"] = False
                entry["versions"].append(record)
                entry["active"] = new_version
                if request.revoke_source:
                    source["revoked"] = True
                new_versions.append(new_version)
            self._write(document)
        return new_versions

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

    def load_batch(self, requests) -> list[bytes]:
        """Open several materials from one key ring against one snapshot.

        ``requests`` is a non-empty list of dicts; each item requires
        ``key_id`` and may additionally name only ``version`` and
        ``password`` with the same defaults and rules as :meth:`load`. The
        whole list is structurally validated first, without touching storage,
        and the caller's objects are never mutated. A ``key_id`` may appear
        repeatedly, including requests for different historical versions.

        Every item is resolved against one committed snapshot taken under a
        shared lock: active pointers, revocation state and record contents all
        come from the same document, so a concurrent batch rotation,
        ``set_active`` or ``revoke`` is observed only whole, as the state
        entirely before its commit or entirely after it; a change committed
        after the batch finished never negates the materials already read.
        The whole store is validated first, so structural damage in a record
        no item requested still raises ``CorruptRecordError``. Items are then
        opened in request order with ``load``'s exact verdicts; the first
        failure aborts the batch and no partial materials are returned. On
        success the materials come back in request order, preserving
        duplicates; ``keyring.json`` is never rewritten.
        """
        normalised = self._check_load_requests(requests)
        # One shared-lock snapshot for the whole batch, exactly like load:
        # version resolution (including active defaults), revocation checks
        # and decryption all see the same committed document, and no writer
        # (a batch rotation, set_active or revoke) can commit in between.
        with _locked(self, exclusive=False):
            document = self._read()
            entries: dict[str, dict] = {}
            materials: list[bytes] = []
            for request in normalised:
                # Resolve and open strictly in request order so the first
                # failing item is the one reported (a set lookup here could
                # surface a later unknown key first); nothing is returned on
                # failure, so earlier decrypted materials never escape.
                entry = entries.get(request.key_id)
                if entry is None:
                    entry = self._entry(document, request.key_id)
                    entries[request.key_id] = entry
                record = self._record_in(entry, request.key_id, request.version)
                materials.append(
                    self._material_from(record, request.key_id, request.password))
        return materials

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
        if scheme in (SEALED_SCHEME, SEALED_V2_SCHEME):
            return self._open_sealed(record, password, key_id)
        raise CorruptRecordError(f"记录损坏：未知封存方案 {scheme!r}")

    def _open_sealed(self, record: dict, password: str | None, key_id: str) -> bytes:
        # Parse and validate every stored parameter first: truncation, missing
        # fields and malformed encodings are record corruption, even when no
        # passphrase was supplied. The version number was validated when the
        # entry was loaded.
        scheme = record["scheme"]
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
        # v2 tags bind the exact key_id; v1 tags keep their original AAD so
        # legacy sealed records stay openable. A rewritten version, a record
        # moved or copied onto another key, or a renamed owning key changes the
        # AAD (or fails document structure first) and surfaces here as
        # corruption, never as a wrong-passphrase error.
        bound_key = key_id if scheme == SEALED_V2_SCHEME else None
        expected_tag = hmac.new(
            mac_key, _aad(version, salt, iterations, check, bound_key) + ciphertext,
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

    def set_active_batch(self, requests) -> None:
        """Repoint several keys' active versions as a single change.

        ``requests`` is a non-empty list of dicts; each item requires
        ``key_id`` and ``version`` and may additionally name only
        ``expected_active``. The whole list is structurally validated first,
        without touching storage, and the caller's objects are never mutated.
        A ``key_id`` may appear only once. Unlike :meth:`set_active`, the
        batch refuses a revoked target: repointing several keys onto revoked
        versions in one commit is never a legitimate whole switch.

        Every item is checked against one committed snapshot read under the
        exclusive lock, after the whole store validates (structural damage in
        a record no item requested still raises ``CorruptRecordError``). Items
        are checked in request order -- key lookup, then the
        ``expected_active`` precondition (only the active version *number* is
        compared; the expected value need not exist in the history), then
        target existence, then the target's revocation flag -- and the first
        failure (``KeyError``, ``ActiveVersionConflictError``, ``KeyError``,
        ``RevokedVersionError``) aborts the batch before anything is mutated,
        so ``keyring.json`` keeps its exact prior bytes. A target that is
        already active still goes through every check.

        Once every item passes, all active pointers move together and commit
        with one atomic replace: no versions are appended, no material is
        decrypted, and other keys, histories and revocation flags are
        untouched. If no item actually moves its pointer the file is not
        rewritten at all. Concurrent readers observe only the state entirely
        before or entirely after the batch, and of two batches expecting the
        same old active version on a shared key at most one commits. On
        success ``None`` is returned.
        """
        normalised = self._check_set_active_requests(requests)
        # One exclusive lock for the entire batch: the snapshot every item is
        # checked against, the precondition comparisons and the single atomic
        # commit are one unit, so a concurrent change is visible only whole,
        # before this batch or after it, and no failure path persists part of
        # the switch.
        with _locked(self, exclusive=True):
            document = self._read()
            # Check every item in request order first; the first failure
            # (unknown key, active-precondition conflict, unknown target
            # version, revoked target) aborts before the document is mutated
            # anywhere.
            resolved: list[tuple[_SetActiveRequest, dict]] = []
            for request in normalised:
                entry = self._entry(document, request.key_id)
                self._check_active_precondition(
                    entry, request.key_id, request.expected_active)
                record = self._record_in(entry, request.key_id, request.version)
                if record["revoked"]:
                    raise RevokedVersionError(
                        f"version {record.get('version')!r} of "
                        f"{request.key_id!r} 已吊销")
                resolved.append((request, entry))
            # Distinct key_ids within the batch (checked up front) mean each
            # entry is repointed by at most one item.
            moved = False
            for request, entry in resolved:
                if int(entry["active"]) != request.version:
                    entry["active"] = request.version
                    moved = True
            # A batch that switches nothing must not rewrite keyring.json.
            if moved:
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
