import re
from datetime import datetime, timezone
from pathlib import Path

from app.core.parser import BaseParser
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, ObjectInfo, SubjectInfo


class LinuxLogParser(BaseParser):
    """Parse common Linux auth and auditd lines into NormalizedEvent."""

    _auth = re.compile(r"^(?P<ts>\w{3} +\d+ \d\d:\d\d:\d\d) (?P<host>\S+) sshd(?:\[\d+\])?: (?P<body>.*)$")
    _syslog = re.compile(r"^(?P<ts>\w{3} +\d+ \d\d:\d\d:\d\d) (?P<host>\S+) (?P<program>[\w.-]+)(?:\[(?P<pid>\d+)\])?: (?P<body>.*)$")
    _audit = re.compile(r"^type=(?P<type>\w+) msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\): (?P<body>.*)$")
    _syscall_names = {
        "0": "read", "1": "write", "2": "open", "3": "close", "9": "mmap",
        "39": "getpid", "41": "socket", "42": "connect", "44": "sendto",
        "45": "recvfrom", "56": "clone", "57": "fork", "59": "execve",
        "60": "exit", "61": "wait4", "83": "mkdir", "87": "unlink",
        "202": "futex", "217": "getdents64", "231": "exit_group",
        "257": "openat", "263": "unlinkat", "316": "renameat2", "322": "execveat",
    }

    def __init__(self, hostname: str, ip: str | None = None, year: int | None = None) -> None:
        self.hostname, self.ip, self.year = hostname, ip, year or datetime.now(timezone.utc).year

    @property
    def name(self) -> str:
        return "linux_log_parser"

    @property
    def source_type(self) -> str:
        return "host_log"

    def parse(self, source: Path) -> list[NormalizedEvent]:
        lines = [line.strip() for line in source.read_text(encoding="utf-8-sig", errors="replace").splitlines()]
        syscall_context: dict[str, dict[str, str]] = {}
        for line in lines:
            match = self._audit.match(line)
            if match and match.group("type") == "SYSCALL":
                syscall_context[self._audit_key(match)] = self._fields(match.group("body"))
        events: list[NormalizedEvent] = []
        for line in lines:
            match = self._audit.match(line)
            context = syscall_context.get(self._audit_key(match)) if match else None
            event = self._parse_line(line, context)
            if event:
                events.append(event)
        return events

    @staticmethod
    def _audit_key(match: re.Match[str]) -> str:
        return f"{match.group('ts')}:{match.group('serial')}"

    @staticmethod
    def _fields(body: str) -> dict[str, str]:
        return {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S+)', body)}

    def _base(self, timestamp: datetime, source: str, event_type: str, action: str, severity: str = "info", **kwargs: object) -> NormalizedEvent:
        return NormalizedEvent(timestamp=timestamp, source_type="host_log", source=source, host=HostInfo(hostname=self.hostname, ip=self.ip, os="linux"), event_type=event_type, action=action, severity=severity, **kwargs)

    def _timestamp(self, value: str, auth: bool = False) -> datetime:
        if auth:
            return datetime.strptime(f"{self.year} {value}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    def _parse_line(self, line: str, syscall_context: dict[str, str] | None = None) -> NormalizedEvent | None:
        match = self._auth.match(line)
        if match:
            body = match.group("body")
            user = re.search(r"for (?:invalid user )?(\S+)", body)
            src = re.search(r"from ([\da-fA-F:.]+)", body)
            success = "Accepted" in body
            username = user.group(1) if user else None
            return self._base(self._timestamp(match.group("ts"), True), "linux_auth", "user_login", "login_success" if success else "login_failure", "info" if success else "medium", subject=SubjectInfo(type="user", name=username, user=username), network=NetworkInfo(src_ip=src.group(1) if src else None, dst_ip=self.ip, dst_port=22, protocol="ssh"), raw_data={"message": body}, tags=["ssh", "login", "success" if success else "failed"])
        match = self._syslog.match(line)
        if match and match.group("program") != "sshd":
            pid = int(match.group("pid")) if match.group("pid") else None
            body = match.group("body")
            return self._base(self._timestamp(match.group("ts"), True), "linux_syslog", "process_create", "execute_command", subject=SubjectInfo(type="process", name=match.group("program"), pid=pid), raw_data={"message": body, "command_line": body}, tags=["syslog", "process"])
        match = self._audit.match(line)
        if match:
            body, kind = match.group("body"), match.group("type")
            clean = self._fields(body)
            if kind == "EXECVE" and syscall_context:
                raw = dict(syscall_context)
                raw.update(clean)
                args = [value for key, value in sorted(clean.items()) if re.fullmatch(r"a\d+", key)]
                if args:
                    raw["command_line"] = " ".join(args)
                raw["parent_pid"] = raw.pop("ppid", None)
                raw.setdefault("parent_process_name", raw.get("ppcomm") or raw.get("parent_comm"))
                raw.setdefault("arch", raw.get("arch"))
                pid = int(raw["pid"]) if raw.get("pid", "").isdigit() else None
                name = raw.get("comm") or raw.get("exe", "").rsplit("/", 1)[-1]
                return self._base(self._timestamp(match.group("ts")), "linux_auditd", "process_create", "execute_command", subject=SubjectInfo(type="process", name=name, pid=pid, user=raw.get("uid")), raw_data=raw, tags=["process", "auditd"])
            if kind in {"EXECVE", "SYSCALL"}:
                pid = int(clean["pid"]) if clean.get("pid", "").isdigit() else None
                name = clean.get("comm") or clean.get("exe", "").rsplit("/", 1)[-1]
                raw = dict(clean)
                if "ppid" in raw:
                    raw["parent_pid"] = raw.pop("ppid")
                raw.setdefault("parent_process_name", raw.get("ppcomm") or raw.get("parent_comm"))
                raw.setdefault("command_line", raw.get("cmdline"))
                if clean.get("syscall"):
                    raw["syscall_name"] = self._syscall_names.get(clean["syscall"], clean["syscall"])
                raw.setdefault("arch", clean.get("arch"))
                event_type = "system_call" if kind == "SYSCALL" and clean.get("syscall") else "process_create"
                if event_type == "system_call":
                    raw.setdefault("arguments", [raw[key] for key in ("a0", "a1", "a2", "a3") if key in raw])
                    raw.setdefault("result", raw.get("success") or raw.get("exit"))
                return self._base(self._timestamp(match.group("ts")), "linux_auditd", event_type, "system_call" if event_type == "system_call" else "execute_command", subject=SubjectInfo(type="process", name=name, pid=pid, user=clean.get("uid")), raw_data=raw, tags=["process", "auditd"])
            if kind == "USER_LOGIN":
                username = clean.get("acct")
                return self._base(self._timestamp(match.group("ts")), "linux_auditd", "user_login", "login_success" if clean.get("res") == "success" else "login_failure", subject=SubjectInfo(type="user", name=username, user=username), raw_data=clean, tags=["login", "auditd"])
            if kind == "PATH" and clean.get("name"):
                if syscall_context:
                    merged = dict(syscall_context)
                    merged.update(clean)
                    clean = merged
                operation = clean.get("nametype", "normal").lower()
                event_type = {"create": "file_create", "created": "file_create", "modify": "file_modify", "modified": "file_modify", "delete": "file_delete", "deleted": "file_delete"}.get(operation, "file_read")
                pid = int(clean["pid"]) if clean.get("pid", "").isdigit() else None
                process_name = clean.get("comm") or clean.get("exe", "").rsplit("/", 1)[-1] or None
                subject = SubjectInfo(type="process", name=process_name, pid=pid, user=clean.get("uid")) if (process_name or pid is not None or clean.get("uid")) else None
                return self._base(self._timestamp(match.group("ts")), "linux_auditd", event_type, event_type.replace("file_", ""), subject=subject, object=ObjectInfo(type="file", name=clean["name"], path=clean["name"]), raw_data=clean, tags=["file", "auditd"])
        return None
