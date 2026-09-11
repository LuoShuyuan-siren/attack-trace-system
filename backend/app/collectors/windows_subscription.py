from __future__ import annotations

import queue
from typing import Any


class WindowsNativeEventSubscription:
    """Optional pywin32 wrapper around Windows Event Log EvtSubscribe."""

    def __init__(self, channels: tuple[str, ...]) -> None:
        self.channels = channels
        self._events: queue.Queue[tuple[str, str]] = queue.Queue()
        self._handles: list[Any] = []
        self._started = False

    def start(self) -> bool:
        if self._started:
            return True
        try:
            import win32evtlog
        except ImportError:
            return False

        flags = getattr(win32evtlog, "EvtSubscribeToFutureEvents", 1)

        for channel in self.channels:
            def callback(action, context, event, channel_name=channel):
                del action, context
                try:
                    xml = win32evtlog.EvtRender(
                        event,
                        win32evtlog.EvtRenderEventXml,
                    )
                    if isinstance(xml, bytes):
                        xml = xml.decode("utf-8", errors="replace")
                    self._events.put((channel_name, str(xml)))
                except Exception:
                    return 0
                return 0

            try:
                handle = win32evtlog.EvtSubscribe(
                    channel,
                    None,
                    None,
                    callback,
                    None,
                    None,
                    flags,
                )
            except Exception:
                self.close()
                return False
            self._handles.append(handle)

        self._started = True
        return True

    def collect_once(self) -> list[tuple[str, str]]:
        if not self.start():
            return []
        events: list[tuple[str, str]] = []
        while True:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                return events

    def close(self) -> None:
        if self._handles:
            try:
                import win32evtlog

                for handle in self._handles:
                    win32evtlog.EvtClose(handle)
            except (ImportError, Exception):
                pass
        self._handles.clear()
        self._started = False
