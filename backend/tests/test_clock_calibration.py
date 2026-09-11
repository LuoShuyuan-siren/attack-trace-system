from app.services.clock_calibration import ClockCalibrationService


def test_linux_chrony_calibration_parses_offset(monkeypatch) -> None:
    monkeypatch.setattr("app.services.clock_calibration.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        ClockCalibrationService,
        "_run",
        staticmethod(
            lambda command: (
                "Reference ID    : 192.0.2.1\n"
                "Stratum         : 3\n"
                "System time     : -0.012345678 seconds slow of NTP time\n"
                if command == ["chronyc", "tracking"]
                else ""
            )
        ),
    )

    result = ClockCalibrationService().measure()

    assert result.source == "chrony"
    assert result.offset_ms == -12
    assert result.synchronized is True
    assert result.confidence == 0.9


def test_invalid_environment_override_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("ATTACK_TRACE_CLOCK_OFFSET_MS", "invalid")
    monkeypatch.setattr("app.services.clock_calibration.platform.system", lambda: "Other")

    result = ClockCalibrationService().measure()

    assert result.source == "unsupported:other"
    assert result.offset_ms == 0
