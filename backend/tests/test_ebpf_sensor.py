import importlib.util
import os
from pathlib import Path

import pytest
from pathlib import Path


_SENSOR_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ebpf_syscall_sensor.py"
_SPEC = importlib.util.spec_from_file_location("ebpf_syscall_sensor", _SENSOR_PATH)
assert _SPEC and _SPEC.loader
_SENSOR = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SENSOR)


def test_syscall_architecture_normalization() -> None:
    assert _SENSOR.normalize_arch("arm64") == "aarch64"
    assert _SENSOR.normalize_arch("x86_64") == "x86_64"


def test_arm64_syscall_names_include_memory_and_execution_calls() -> None:
    names = _SENSOR.SYSCALL_NAMES_BY_ARCH["aarch64"]

    assert names[221] == "execve"
    assert names[270] == "process_vm_writev"
    assert names[279] == "memfd_create"


def test_process_context_reads_current_process_metadata() -> None:
    if not Path("/proc").exists():
        pytest.skip("Linux /proc is required for eBPF process context enrichment")
    context = _SENSOR._process_context(os.getpid())

    assert context["ppid"] > 0
    assert context["exe"]
    assert "pytest" in context["command_line"] or "python" in context["command_line"]
