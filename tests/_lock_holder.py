"""Hold the cross-process exclusive write lock, for timeout tests.

Usage: _lock_holder.py <root> <seconds> [ready_file]

Touches ``ready_file`` once the exclusive lock is actually held, so callers do
not have to guess when it is safe to contend.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from seal_derive.core import _FileLock


def main() -> None:
    root, seconds = sys.argv[1], float(sys.argv[2])
    ready_file = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    with _FileLock(Path(root) / ".keyring.lock", exclusive=True, timeout=seconds + 5):
        if ready_file is not None:
            ready_file.touch()
        time.sleep(seconds)


if __name__ == "__main__":
    main()
