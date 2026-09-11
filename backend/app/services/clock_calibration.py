from __future__ import annotations

import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ClockCalibration:
    offset_ms: int = 0
    source: str = "unspecified"
    confidence: float = 0.0
    synchronized: bool = False
    details: dict[str, Any] = field(default_factory=dict)


class ClockCalibrationService:
    """Read local Windows/Linux time-sync state for event provenance."""

    def measure(self) -> ClockCalibration:
        override = os.getenv("ATTACK_TRACE_CLOCK_OFFSET_MS")
        if override:
            try:
                return ClockCalibration(
                    offset_ms=int(float(override)),
                    source="environment_override",
                    confidence=0.5,
                    synchronized=True,
                )
            except ValueError:
                pass

        system = platform.system().lower()
        if system == "windows":
            return self._windows()
        if system == "linux":
            return self._linux()
        return ClockCalibration(source=f"unsupported:{system}")

    def _windows(self) -> ClockCalibration:
        output = self._run(["w32tm", "/query", "/status"])
        if not output:
            return ClockCalibration(source="w32tm", details={"available": False})
        stratum = _field(output, "Stratum")
        synchronized = bool(_field(output, "Last Successful Sync Time"))
        return ClockCalibration(
            source="w32tm",
            confidence=0.8 if synchronized else 0.2,
            synchronized=synchronized,
            details={"stratum": stratum, "last_sync": _field(output, "Last Successful Sync Time")},
        )

    def _linux(self) -> ClockCalibration:
        chrony = self._run(["chronyc", "tracking"])
        if chrony:
            offset = _seconds_field(chrony, "System time")
            synchronized = _field(chrony, "Stratum") not in {None, "0"}
            return ClockCalibration(
                offset_ms=round(offset * 1000),
                source="chrony",
                confidence=0.9 if synchronized else 0.2,
                synchronized=synchronized,
                details={"stratum": _field(chrony, "Stratum"), "reference": _field(chrony, "Reference ID")},
            )

        timedatectl = self._run(["timedatectl", "show", "--property=NTPSynchronized", "--value"])
        synchronized = timedatectl.strip().lower() == "yes" if timedatectl else False
        return ClockCalibration(
            source="timedatectl",
            confidence=0.6 if synchronized else 0.1,
            synchronized=synchronized,
            details={"available": bool(timedatectl)},
        )

    @staticmethod
    def _run(command: list[str]) -> str:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return result.stdout.strip() if result.returncode == 0 else ""


def _field(output: str, label: str) -> str | None:
    pattern = re.compile(rf"^{re.escape(label)}\s*:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
    match = pattern.search(output)
    return match.group(1).strip() if match else None


def _seconds_field(output: str, label: str) -> float:
    value = _field(output, label)
    if not value:
        return 0.0
    match = re.search(r"[+-]?\d+(?:\.\d+)?", value)
    try:
        return float(match.group(0)) if match else 0.0
    except ValueError:
        return 0.0
