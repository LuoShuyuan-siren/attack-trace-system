from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from hashlib import sha256
from typing import Any

from app.schemas.event import NormalizedEvent


class SessionReconstructionService:
    """重建登录会话并检测高风险进程活动。"""

    _LOGIN_EVENTS = {"logon", "user_login", "authenticate"}
    _LOGOUT_EVENTS = {"logoff", "user_logout", "logout"}

    def reconstruct_sessions(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)

        for event in events:
            if event.subject is None or event.subject.user is None:
                continue
            if event.event_type not in (
                self._LOGIN_EVENTS
                | self._LOGOUT_EVENTS
                | {"process_create", "process_exec", "execute"}
            ):
                continue
            key = (event.host.hostname or "unknown", event.subject.user)
            grouped[key].append(event)

        sessions: list[dict[str, Any]] = []
        for (hostname, user), user_events in grouped.items():
            active: list[dict[str, Any]] = []
            for event in sorted(user_events, key=lambda item: item.timestamp):
                if event.event_type in self._LOGIN_EVENTS:
                    active.append(self._new_session(hostname, user, event))
                    continue
                if event.event_type in self._LOGOUT_EVENTS:
                    session_index = self._matching_session_index(active, event)
                    if session_index is not None:
                        session = active.pop(session_index)
                        self._close_session(session, event)
                        sessions.append(session)
                    continue
                if event.event_type in {"process_create", "process_exec", "execute"}:
                    session_index = self._matching_session_index(active, event)
                    if session_index is not None:
                        process = event.raw_data.get("process_name") or (
                            event.subject.name if event.subject else None
                        )
                        if process:
                            active[session_index]["processes"].append(process)

            sessions.extend(active)

        return sessions

    @staticmethod
    def _new_session(
        hostname: str,
        user: str,
        event: NormalizedEvent,
    ) -> dict[str, Any]:
        session_id = "sess-" + sha256(
            f"{hostname}|{user}|{event.event_id}".encode("utf-8")
        ).hexdigest()[:16]
        return {
            "session_id": session_id,
            "hostname": hostname,
            "user": user,
            "src_ip": event.network.src_ip if event.network else None,
            "login_at": event.timestamp,
            "logout_at": None,
            "duration_seconds": 0,
            "login_event_id": event.event_id,
            "logout_event_id": None,
            "logon_id": SessionReconstructionService._event_logon_id(event),
            "processes": [],
        }

    @classmethod
    def _matching_session_index(
        cls,
        active: list[dict[str, Any]],
        event: NormalizedEvent,
    ) -> int | None:
        if not active:
            return None
        logon_id = cls._event_logon_id(event)
        if logon_id is not None:
            for index, session in enumerate(active):
                if session.get("logon_id") == logon_id:
                    return index
        return 0

    @staticmethod
    def _event_logon_id(event: NormalizedEvent) -> str | None:
        value = event.raw_data.get("logon_id") or event.raw_data.get("session_id")
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @staticmethod
    def _close_session(session: dict[str, Any], event: NormalizedEvent) -> None:
        session["logout_at"] = event.timestamp
        session["logout_event_id"] = event.event_id
        session["duration_seconds"] = int(
            (event.timestamp - session["login_at"]).total_seconds()
        )

    def build_summary(self, events: list[NormalizedEvent]) -> dict[str, Any]:
        sessions = self.reconstruct_sessions(events)
        suspicious_processes: list[dict[str, str]] = []
        seen: set[str] = set()

        for event in events:
            if event.event_type != "process_create":
                continue
            process_name = event.raw_data.get("process_name") or (event.subject.name if event.subject else None)
            if not process_name:
                continue
            key = str(process_name)
            if key in seen:
                continue
            seen.add(key)
            suspicious_processes.append({
                "name": key,
                "host": event.host.hostname or "unknown",
                "user": event.subject.user if event.subject else "unknown",
            })

        return {
            "session_count": len(sessions),
            "sessions": sessions,
            "suspicious_processes": suspicious_processes,
        }
