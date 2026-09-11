import re
from datetime import datetime, timezone
from pathlib import Path

from app.core.parser import BaseParser
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, ObjectInfo, SubjectInfo


class LinuxLogParser(BaseParser):
    """Parse common Linux auth and auditd lines into NormalizedEvent."""

    _auth = re.compile(
        r"^(?P<ts>(?:\d{4}-\d{2}-\d{2}T\S+|\w{3} +\d+ \d\d:\d\d:\d\d)) "
        r"(?P<host>\S+) sshd(?:-session)?(?:\[\d+\])?: (?P<body>.*)$"
    )
    _su_auth = re.compile(
        r"^(?P<ts>\w{3} +\d+ \d\d:\d\d:\d\d) (?P<host>\S+) su(?:\[\d+\])?: "
        r"(?P<body>.*session opened for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?.*)$"
    )
    _syslog = re.compile(r"^(?P<ts>\w{3} +\d+ \d\d:\d\d:\d\d) (?P<host>\S+) (?P<program>[\w.-]+)(?:\[(?P<pid>\d+)\])?: (?P<body>.*)$")
    _audit = re.compile(
        r"^(?:.*?\baudit:\s+)?type=(?P<type>\w+) (?:msg=)?audit\("
        r"(?P<ts>.+):(?P<serial>\d+)\)\s*:\s*(?P<body>.*)$"
    )
    _audit_types = {"1300": "SYSCALL", "1302": "PATH", "1309": "EXECVE", "1327": "PROCTITLE"}
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
            if match and self._audit_kind(match) == "SYSCALL":
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

    def _audit_kind(self, match: re.Match[str]) -> str:
        return self._audit_types.get(match.group("type"), match.group("type"))

    @staticmethod
    def _fields(body: str) -> dict[str, str]:
        return {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S+)', body)}

    def _base(self, timestamp: datetime, source: str, event_type: str, action: str, severity: str = "info", **kwargs: object) -> NormalizedEvent:
        return NormalizedEvent(timestamp=timestamp, source_type="host_log", source=source, host=HostInfo(hostname=self.hostname, ip=self.ip, os="linux"), event_type=event_type, action=action, severity=severity, **kwargs)

    def _timestamp(self, value: str, auth: bool = False) -> datetime:
        if auth:
            if re.match(r"^\d{4}-\d{2}-\d{2}T", value):
                return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
            return datetime.strptime(f"{self.year} {value}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        if "/" in value:
            return datetime.strptime(value, "%m/%d/%Y %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    @staticmethod
    def _decode_proctitle(value: str) -> str:
        if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
            try:
                return bytes.fromhex(value).replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            except ValueError:
                pass
        return value

    def _parse_line(self, line: str, syscall_context: dict[str, str] | None = None) -> NormalizedEvent | None:
        match = self._auth.match(line)
        if match:
            body = match.group("body")
            success = "Accepted" in body
            failure = "Failed password" in body or "authentication failure" in body
            if not (success or failure):
                return None
            user = re.search(r"for (?:invalid user )?(\S+)", body) or re.search(r"\buser=(\S+)", body)
            src = re.search(r"from ([\da-fA-F:.]+)", body) or re.search(r"\brhost=([\da-fA-F:.]+)", body)
            src_port = re.search(r"\bport (\d+)", body)
            username = user.group(1) if user else None
            return self._base(self._timestamp(match.group("ts"), True), "linux_auth", "user_login", "login_success" if success else "login_failure", "info" if success else "medium", subject=SubjectInfo(type="user", name=username, user=username), network=NetworkInfo(src_ip=src.group(1) if src else None, src_port=int(src_port.group(1)) if src_port else None, dst_ip=self.ip, dst_port=22, protocol="ssh"), raw_data={"message": body}, tags=["ssh", "login", "success" if success else "failed"])
        match = self._su_auth.match(line)
        if match:
            username, uid = match.group("user"), match.group("uid")
            severity = "medium" if uid == "0" else "info"
            return self._base(self._timestamp(match.group("ts"), True), "linux_auth", "user_login", "login_success", severity, subject=SubjectInfo(type="user", name=username, user=username), raw_data={"message": match.group("body"), "uid": uid, "auth_method": "su"}, tags=["su", "login", "privilege_escalation"])
        match = self._syslog.match(line)
        if match and match.group("program") != "sshd" and "audit: type=" not in match.group("body"):
            pid = int(match.group("pid")) if match.group("pid") else None
            body = match.group("body")
            return self._base(self._timestamp(match.group("ts"), True), "linux_syslog", "process_create", "execute_command", subject=SubjectInfo(type="process", name=match.group("program"), pid=pid), raw_data={"message": body, "command_line": body}, tags=["syslog", "process"])
        match = self._audit.match(line)
        if match:
            body, kind = match.group("body"), self._audit_kind(match)
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
                raw = dict(clean)
                args = [value for key, value in sorted(clean.items()) if re.fullmatch(r"a\d+", key)]
                name = clean.get("comm") or clean.get("exe", "").rsplit("/", 1)[-1] or (args[0] if args else None)
                if kind == "EXECVE" and args:
                    raw["command_line"] = " ".join(args)
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
            if kind in {"USER_END", "USER_LOGOUT"}:
                username = clean.get("acct") or clean.get("user")
                return self._base(self._timestamp(match.group("ts")), "linux_auditd", "user_logout", "logout", subject=SubjectInfo(type="user", name=username, user=username), raw_data=clean, tags=["logout", "auditd"])
            if kind == "PROCTITLE" and clean.get("proctitle"):
                proctitle = re.search(r"\bproctitle=(.*)$", body)
                command_line = self._decode_proctitle(proctitle.group(1).strip() if proctitle else clean["proctitle"])
                raw = dict(syscall_context or {})
                raw.update(clean)
                raw["command_line"] = command_line
                if "ppid" in raw:
                    raw["parent_pid"] = raw.pop("ppid")
                raw.setdefault("parent_process_name", raw.get("ppcomm") or raw.get("parent_comm"))
                pid = int(raw["pid"]) if raw.get("pid", "").isdigit() else None
                name = raw.get("comm") or raw.get("exe", "").rsplit("/", 1)[-1] or command_line.split(" ", 1)[0]
                return self._base(self._timestamp(match.group("ts")), "linux_auditd", "process_create", "execute_command", subject=SubjectInfo(type="process", name=name, pid=pid, user=raw.get("uid")), raw_data=raw, tags=["process", "auditd", "proctitle"])
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
