"""Subprocess worker for the cross-process load snapshot tests.

Runs ``rounds`` ``load`` calls against one key ring, deliberately slowing
PBKDF2 so each load's shared-lock snapshot is held open long enough for a
competing ``revoke`` process to queue behind it. Emits one result line per load:

  ok:<material>   - material returned
  revoked         - RevokedVersionError
  error:<type>:<message> - anything else (fails the test)

Signals two files so the parent can order itself without sleeps:
* ``ready_file`` is touched once the worker is patched and about to load;
* ``entered_file`` is touched from inside the slowed key derivation, i.e. while
  the load's shared-lock snapshot is open and before revocation is checked.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from seal_derive import core


def main() -> None:
    (root, key_id, password, ready_file, entered_file,
     stagger, rounds) = sys.argv[1:8]
    stagger, rounds = float(stagger), int(rounds)

    real_derive = core._derive

    def slow_derive(password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
        # Hold the load snapshot open: this runs after the shared lock and the
        # document snapshot were taken and before revocation is checked.
        Path(entered_file).touch()
        time.sleep(0.8)
        return real_derive(password, salt, iterations, length)

    core._derive = slow_derive
    ring = core.KeyRing(root)
    Path(ready_file).touch()
    time.sleep(stagger)
    for _ in range(rounds):
        try:
            material = ring.load(key_id, password=password)
        except core.RevokedVersionError:
            print("revoked", flush=True)
        except Exception as error:  # noqa: BLE001 - report type to the parent
            print(f"error:{type(error).__name__}:{error}", flush=True)
        else:
            print("ok:" + material.decode("utf-8"), flush=True)


if __name__ == "__main__":
    main()
