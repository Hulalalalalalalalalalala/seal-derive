"""Acceptance checks for crash-consistent KeyRing persistence. Run from repo root."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import seal_derive
from seal_derive import core
from seal_derive.core import KeyRing

REPO = Path(__file__).resolve().parent
FAILURES = []


def check(name, cond, detail=""):
    print(("PASS" if cond else "FAIL"), name, detail)
    if not cond:
        FAILURES.append(name)


def cli(root, *args):
    return subprocess.run(
        [sys.executable, "-m", "seal_derive", "--root", str(root), *args],
        capture_output=True, text=True, cwd=REPO)


# ---------- 1. sequential semantics survive, output unchanged ----------
d = Path(tempfile.mkdtemp())
try:
    r = KeyRing(d)
    r.init()
    check("init empty", r._read() == {"keys": {}})
    v1 = r.seal("k", "secret")
    v2 = r.seal("k", "secret2", password="pw", iterations=1000)
    check("seal versions", (v1, v2) == (1, 2))
    r2 = KeyRing(d)
    check("reopen versions", r2.versions("k") == [1, 2])
    check("reopen active", r2.active("k") == 2)
    check("reopen plain load", r2.load("k", 1) == b"secret")
    mat = r2.load("k", 2, password="pw")
    check("reopen derived load len", len(mat) == 32 and mat != b"secret2")
    # PBKDF2 determinism: re-derive expected record material directly
    doc = r2._read()
    rec2 = [x for x in doc["keys"]["k"]["versions"] if x["version"] == 2][0]
    check("record format unchanged",
          set(rec2) == {"version", "scheme", "iterations", "salt", "material", "revoked"})
    check("scheme unchanged", rec2["scheme"] == "pbkdf2-sha256" and rec2["iterations"] == 1000)
    r2.set_active("k", 1)
    check("set_active reopen", KeyRing(d).active("k") == 1)
    check("set_active only pointer", KeyRing(d).versions("k") == [1, 2])
    r2.revoke("k", 2)
    check("revoke reopen", KeyRing(d).is_revoked("k", 2) is True)
    check("v1 not revoked", KeyRing(d).is_revoked("k", 1) is False)
    try:
        KeyRing(d).load("k", 2, password="pw")
        check("revoked load raises", False)
    except ValueError:
        check("revoked load raises", True)
    files = sorted(p.name for p in d.iterdir())
    check("no leaked artifacts after clean writes", files == ["keyring.json"], str(files))
finally:
    shutil.rmtree(d)

# ---------- 2. CLI surface unchanged ----------
d = Path(tempfile.mkdtemp())
try:
    p = cli(d, "init")
    check("cli init rc/out", p.returncode == 0 and p.stdout.strip() == f"initialised {d/'keyring.json'}",
          (p.returncode, p.stdout, p.stderr))
    p = cli(d, "seal", "a", "m1")
    check("cli seal prints version", p.returncode == 0 and p.stdout.strip() == "1", p.stderr)
    p = cli(d, "seal", "a", "m2")
    check("cli seal v2", p.stdout.strip() == "2")
    p = cli(d, "versions", "a")
    check("cli versions", p.returncode == 0 and p.stdout.strip() == "[1, 2]")
    p = cli(d, "active", "a")
    check("cli active", p.stdout.strip() == "2")
    p = cli(d, "load", "a", "--version", "1")
    check("cli load", p.returncode == 0 and p.stdout.strip() == "m1", p.stderr)
    p = cli(d, "set-active", "a", "1")
    check("cli set-active", p.returncode == 0 and p.stdout.strip() == "ok")
    p = cli(d, "revoke", "a", "2")
    check("cli revoke", p.returncode == 0 and p.stdout.strip() == "ok")
    p = cli(d, "report")
    rep = json.loads(p.stdout)
    check("cli report fields",
          set(rep) == {"domain", "version", "sourceCategories", "tags", "components", "readiness"}
          and rep["domain"] == "key-management" and rep["components"] == ["keyring", "derive"],
          str(rep)[:120])
    check("cli init idempotent", cli(d, "init").returncode == 0)
    # baseline: init (re)creates an empty ring, so prior keys are gone
    check("cli init resets to empty", cli(d, "versions", "a").returncode == 2
          and KeyRing(d)._read() == {"keys": {}})
finally:
    shutil.rmtree(d)

# ---------- 3. deterministic errors and exit codes ----------
d = Path(tempfile.mkdtemp())
try:
    KeyRing(d).init()
    # missing file
    missing = Path(tempfile.mkdtemp())
    try:
        KeyRing(missing).versions("k")
        check("missing -> FileNotFoundError", False)
    except FileNotFoundError:
        check("missing -> FileNotFoundError", True)
    p = cli(missing, "versions", "k")
    check("missing cli exit 1", p.returncode == 1)
    shutil.rmtree(missing)
    # corrupt json
    (d / "keyring.json").write_text("{ not json", encoding="utf-8")
    try:
        KeyRing(d).versions("k")
        check("corrupt -> JSONDecodeError", False)
    except json.JSONDecodeError:
        check("corrupt -> JSONDecodeError", True)
    for args in [("versions", "k"), ("seal", "k", "m"), ("active", "k")]:
        p = cli(d, *args)
        check(f"corrupt cli exit 1: {' '.join(args)}", p.returncode == 1, f"rc={p.returncode}")
    # bad inputs -> ValueError/KeyError, cli exit 2
    (d / "keyring.json").write_text(json.dumps({"keys": {}}), encoding="utf-8")
    for args, exc in [(("seal", "", "m"), ValueError),
                      (("seal", "k", "m", "--iterations", "0"), ValueError),
                      (("seal", "k", "m", "--iterations", "-3"), ValueError),
                      (("versions", "ghost"), KeyError),
                      (("active", "ghost"), KeyError),
                      (("set-active", "ghost", "1"), KeyError),
                      (("revoke", "ghost", "1"), KeyError)]:
        p = cli(d, *args)
        check(f"bad input cli exit 2: {' '.join(args)}", p.returncode == 2, f"rc={p.returncode} {p.stderr.strip()}")
    check("argparse usage exit 2", cli(d).returncode == 2)
finally:
    shutil.rmtree(d)

# ---------- 4. unwritable root / file -> OSError, cli exit 1 ----------
d = Path(tempfile.mkdtemp())
try:
    os.chmod(d, 0o555)
    try:
        KeyRing(d).init()
        check("readonly root init -> OSError", False)
    except OSError:
        check("readonly root init -> OSError", True)
    p = subprocess.run([sys.executable, "-m", "seal_derive", "--root", str(d), "init"],
                       capture_output=True, text=True, cwd=REPO)
    check("readonly root cli exit 1", p.returncode == 1, f"rc={p.returncode}")
finally:
    os.chmod(d, 0o755)
    shutil.rmtree(d)

d = Path(tempfile.mkdtemp())
try:
    r = KeyRing(d); r.init(); r.seal("k", "m")
    os.chmod(d / "keyring.json", 0o444)
    try:
        KeyRing(d).seal("k", "m2")
        check("readonly file seal -> OSError", False)
    except OSError:
        check("readonly file seal -> OSError", True)
    p = cli(d, "seal", "k", "m2")
    check("readonly file cli exit 1", p.returncode == 1, f"rc={p.returncode}")
    # reads still work
    check("readonly file read ok", KeyRing(d).versions("k") == [1])
finally:
    os.chmod(d / "keyring.json", stat.S_IRWXU)
    shutil.rmtree(d)

# ---------- 5. crash injection in child processes ----------
CHILD = r'''
import os, sys
sys.path.insert(0, %r)
from seal_derive import core
from seal_derive.core import KeyRing
point = os.environ["CRASH_POINT"]
real_fsync = os.fsync
real_replace = os.replace
if point == "after_file_fsync":
    def fake_fsync(fd):
        real_fsync(fd)
        os._exit(42)
    os.fsync = fake_fsync
elif point == "before_replace":
    def fake_replace(src, dst):
        os._exit(42)
    os.replace = fake_replace
elif point == "after_replace":
    def fake_replace(src, dst):
        real_replace(src, dst)
        os._exit(42)
    os.replace = fake_replace
elif point == "dir_fsync":
    def fake_dir_fsync(directory):
        os._exit(42)
    core._fsync_directory = fake_dir_fsync
elif point == "mid_temp":
    # kill after the first user write, leaving a truncated/partial scratch
    orig_fdopen = os.fdopen
    def fake_fdopen(fd, *a, **k):
        f = orig_fdopen(fd, *a, **k)
        orig_write = f.write
        def fake_write(s):
            r = orig_write(s[: max(1, len(s)//2)])
            f.flush()
            os._exit(42)
        f.write = fake_write
        return f
    os.fdopen = fake_fdopen
n = int(os.environ["SEAL_N"])
ring = KeyRing(os.environ["ROOT"])
ring.seal("k", f"material{n}")
print("should-not-reach")
''' % str(REPO)


def run_crash(root, point, n):
    env = dict(os.environ, ROOT=str(root), CRASH_POINT=point, SEAL_N=str(n))
    return subprocess.run([sys.executable, "-c", CHILD], capture_output=True, text=True, env=env)


def state_is_consistent(root, expect_versions):
    """Ring parses; versions are a prefix 1..n; active points at one of them."""
    p = root / "keyring.json"
    if not p.is_file():
        return False, "no keyring.json", 0
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return False, f"half json: {e}", 0
    try:
        if "k" not in doc["keys"]:
            # old state before the first seal ever committed: empty ring
            return ((True, "n=0", 0) if 0 in expect_versions
                    else (False, "k missing", 0))
        entry = doc["keys"]["k"]
        vs = [int(x["version"]) for x in entry["versions"]]
    except (KeyError, TypeError) as e:
        return False, f"shape: {e}", 0
    if vs != list(range(1, len(vs) + 1)):
        return False, f"non-prefix versions {vs}", len(vs)
    if vs and int(entry["active"]) not in vs:
        return False, f"dangling active {entry['active']}", len(vs)
    for x in entry["versions"]:
        if x.get("revoked") is not False:
            return False, "unexpected revoked", len(vs)
    if len(vs) not in expect_versions:
        return False, f"version count {len(vs)} not in {expect_versions}", len(vs)
    # material round-trips: labels are a fresh prefix after a skipped commit,
    # so each plain record must decode to some unique material<N>.
    import re
    r = KeyRing(root)
    seen = set()
    for i in vs:
        raw = r.load("k", i)
        if not re.fullmatch(rb"material\d+|clean-recovery", raw) or raw in seen:
            return False, f"bad/duplicate material v{i}: {raw!r}", len(vs)
        seen.add(raw)
    return True, f"n={len(vs)}", len(vs)


d = Path(tempfile.mkdtemp())
try:
    KeyRing(d).init()
    points = ["after_file_fsync", "before_replace", "after_replace", "dir_fsync", "mid_temp"]
    n = 0
    committed = 0
    for i in range(40):
        point = points[i % len(points)]
        n += 1
        proc = run_crash(d, point, n)
        check(f"crash child killed ({point})", proc.returncode == 42,
              f"rc={proc.returncode} err={proc.stderr[-200:]}")
        # After "after_replace"/"dir_fsync" the new state is already swapped in;
        # earlier kill points leave the old state. Either is acceptable.
        ok, detail, count = state_is_consistent(d, {committed, committed + 1})
        check(f"state old-or-new after crash {i} [{point}]", ok, detail)
        if not ok:
            break
        committed = count
    # leftover scratch file must never be read as state and must not block writes
    leftover = d / ".keyring.json.tmp"
    if leftover.exists():
        check("leftover temp ignored on read", KeyRing(d).versions("k")[0] == 1)
        p = cli(d, "seal", "k", "clean-recovery")
        check("write succeeds with stale temp", p.returncode == 0 and json.loads(p.stdout) >= 1, p.stderr)
        ok, detail, _ = state_is_consistent(d, {committed + 1})
        check("state consistent after recovery write", ok, detail)
        check("temp removed after clean write", not leftover.exists())
    # set_active / revoke crash points: crash before replace => pointer untouched
    cur_active = KeyRing(d).active("k")
    proc = subprocess.run([sys.executable, "-c", CHILD.replace(
        'ring.seal("k", f"material{n}")',
        'ring.set_active("k", 1)')],
        capture_output=True, text=True,
        env=dict(os.environ, ROOT=str(d), CRASH_POINT="before_replace", SEAL_N="0"))
    check("set_active crash child killed", proc.returncode == 42, proc.stderr[-200:])
    check("set_active atomic (old pointer)", KeyRing(d).active("k") == cur_active)
    check("set_active new attempt ok", cli(d, "set-active", "k", "1").returncode == 0)
    check("set_active persisted", KeyRing(d).active("k") == 1)
finally:
    shutil.rmtree(d)

# ---------- 6. explicit partial-temp leftovers are harmless ----------
d = Path(tempfile.mkdtemp())
try:
    r = KeyRing(d); r.init(); r.seal("k", "material1")
    (d / ".keyring.json.tmp").write_text("{partial", encoding="utf-8")
    check("partial temp ignored", KeyRing(d).versions("k") == [1])
    check("partial temp cli read ok", cli(d, "active", "k").stdout.strip() == "1")
    check("write over partial temp", cli(d, "seal", "k", "material2").returncode == 0)
    check("post-temp versions", KeyRing(d).versions("k") == [1, 2])
    check("no temp remains", not (d / ".keyring.json.tmp").exists())
finally:
    shutil.rmtree(d)

# ---------- 7. windows-style path: os.replace + skipped dir fsync ----------
d = Path(tempfile.mkdtemp())
try:
    os_name = os.name

    class FakeOsName:
        def __eq__(self, other): return other == "nt"

    # emulate the nt branch of _fsync_directory
    orig_name = core.os.name
    core.os.name = "nt"
    try:
        core._fsync_directory(d)  # must return without opening
        check("dir fsync no-op on nt", True)
    finally:
        core.os.name = orig_name
    # replace primitive used is the atomic one on both platforms
    check("uses os.replace atomic primitive",
          "os.replace" in Path(core.__file__).read_text(encoding="utf-8"))
    # same-directory staging is what makes os.replace atomic
    check("temp staged inside root",
          str(KeyRing(d).directory / core.TEMP_FILE).startswith(str(d)))
finally:
    shutil.rmtree(d)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURES:", FAILURES)
    sys.exit(1)
print("ALL CHECKS PASSED")
