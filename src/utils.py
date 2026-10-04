"""Shared helper functions used across the project."""

import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def atomic_path(path, retries: int = 10):
    """Yield a temp file path; on success, atomically move it to `path`.

    On Windows another process (antivirus, indexer, the dashboard) can briefly lock a
    file, which makes a direct open-for-write fail with OSError. Writing to a temp file
    and retrying the replace avoids flaky failures and never leaves a half-written file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    os.close(fd)
    try:
        yield tmp
        for attempt in range(retries):
            try:
                os.replace(tmp, path)
                break
            except OSError:
                if attempt == retries - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def write_text_atomic(path, text: str, retries: int = 10) -> Path:
    """Write text to `path` via a temp file and atomic replace (see atomic_path)."""
    with atomic_path(path, retries) as tmp:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    return Path(path)
