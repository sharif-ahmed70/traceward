"""Shared helper functions used across the project."""

import os
import tempfile
import time
from pathlib import Path


def write_text_atomic(path, text: str, retries: int = 5) -> Path:
    """Write text to `path` via a temp file and atomic replace.

    On Windows another process (antivirus, indexer, the dashboard) can briefly lock a
    file, which makes a direct open-for-write fail with OSError. Writing to a temp file
    and retrying the replace avoids flaky failures and never leaves a half-written file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        for attempt in range(retries):
            try:
                os.replace(tmp, path)
                return path
            except OSError:
                if attempt == retries - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path
