from __future__ import annotations

import tempfile
from pathlib import Path

from app.parsers.linux import LinuxLogParser
from app.schemas.event import NormalizedEvent


class LinuxSystemLogTail:
    """Read only newly appended Linux auth/audit lines between samples."""

    def __init__(self, path: str | Path, *, hostname: str, ip: str | None = None) -> None:
        self.path = Path(path)
        self.parser = LinuxLogParser(hostname=hostname, ip=ip)
        self.offset = 0

    def collect_once(self) -> list[NormalizedEvent]:
        if not self.path.exists():
            return []
        with self.path.open("rb") as source:
            source.seek(self.offset)
            chunk = source.read()
            self.offset = source.tell()
        if not chunk:
            return []
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as temporary:
            temporary.write(chunk)
            temporary_path = Path(temporary.name)
        try:
            return self.parser.parse(temporary_path)
        finally:
            temporary_path.unlink(missing_ok=True)
