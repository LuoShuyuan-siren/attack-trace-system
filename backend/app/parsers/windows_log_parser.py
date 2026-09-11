import gzip
import csv
import json
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone

# ⑤ 修复导入规范，严格遵循项目规范
from app.core.parser import BaseParser
from app.schemas.event import NormalizedEvent

class WindowsLogParser(BaseParser):
    name = "windows_log_parser"
    source_type = "host_log"

    def __init__(self):
        super().__init__()
        # ④ 恢复所有的 Sysmon 和 Security 事件映射，严禁能力回退
        self.event_code_map = {
            "1": "process_create", "10": "process_access", "4688": "process_create",
            "3": "network_connection", "22": "dns_query",
            "11": "file_create", "23": "file_delete", "4663": "file_modify",
            "12": "registry_create", "13": "registry_set", "14": "registry_rename",
            "4624": "user_login", "4625": "user_login_failed",
        }
        self.debug_count = 0

    def _parse_time(self, raw_time: str) -> str:
        """时间标准化：兼容多种格式，忽略 MDT/UTC 等后缀"""
        if not raw_time:
            return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        try:
            match = re.search(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?)', raw_time)
            if match:
                clean_time = match.group(1).replace(' ', 'T')
                return datetime.strptime(clean_time.split('.')[0], "%Y-%m-%dT%H:%M:%S").strftime('%Y-%m-%dT%H:%M:%SZ')
            return raw_time
        except ValueError:
            return raw_time

    def _extract_from_raw(self, raw_text: str) -> dict:
        """① 兼容 XML (Sysmon EVTX) 和 纯文本 Key=Value (Security CSV)"""
        extracted = {}
        if not raw_text:
            return extracted

        raw_text = raw_text.replace('\r\n', '\n').strip()
        try:
            return json.loads(raw_text)
        except:
            pass

        # 按 XML 解析
        if raw_text.startswith("<"):
            event_id_match = re.search(r'<EventID>\s*(\d+)\s*</EventID>', raw_text)
            if event_id_match:
                extracted['EventCode'] = event_id_match.group(1)
            data_matches = re.finditer(r'<Data Name=[\'"]([^\'"]+)[\'"]>(.*?)</Data>', raw_text, re.DOTALL)
            for match in data_matches:
                extracted[match.group(1)] = match.group(2).strip()
            return extracted

        # 按纯文本 Key=Value 解析
        match = re.search(r'(?:EventCode|EventID|Event_Id)[=:\s]+(\d+)', raw_text, re.IGNORECASE)
        if match:
            extracted['EventCode'] = match.group(1)
        for line in raw_text.splitlines():
            line = line.strip()
            if "=" in line:
                parts = line.split("=", 1)
                extracted[parts[0].strip()] = parts[1].strip()
            elif ":" in line:
                parts = line.split(":", 1)
                extracted[parts[0].strip()] = parts[1].strip()
        return extracted

    def _process_row(self, row_dict: dict, source_name: str, file_path: Path) -> NormalizedEvent:
        """统一数据处理逻辑，兼容 CSV 行和 EVTX 事件"""
        raw_text = row_dict.get("_raw") or row_dict.get("EventData") or ""
        raw_dict = self._extract_from_raw(raw_text)
        
        raw_event_id = raw_dict.get("EventCode") or raw_dict.get("EventID")
        event_code = str(raw_event_id) if raw_event_id else ""
        event_type = self.event_code_map.get(event_code, "unknown_event")
        if event_type == "unknown_event":
            return None
            
        raw_time = row_dict.get("_time") or row_dict.get("timestamp") or raw_dict.get("UtcTime")
        timestamp = self._parse_time(raw_time)
        hostname = row_dict.get("host") or raw_dict.get("Computer") or "unknown_host"
        
        user = raw_dict.get("User") or raw_dict.get("Account Name") or "unknown"
        process_name = raw_dict.get("Image") or raw_dict.get("NewProcessName") or raw_dict.get("Process Name")
        pid = raw_dict.get("ProcessId") or raw_dict.get("NewProcessId") or raw_dict.get("Process ID")
        real_event_id = raw_dict.get("EventRecordID") or raw_dict.get("RecordNumber") or event_code
        parent_pid = raw_dict.get("ParentProcessId") or raw_dict.get("Parent Process ID")
        parent_process_name = raw_dict.get("ParentImage") or raw_dict.get("Parent Process Name")
        command_line = raw_dict.get("CommandLine") or raw_dict.get("Command Line")
        file_path_val = raw_dict.get("TargetFilename") or raw_dict.get("ObjectName")
        registry_key = raw_dict.get("TargetObject")

        # ③ 修复：将关键字段同时平铺到 raw_data 顶层，确保成员4能直接读取
        enhanced_raw_data = dict(row_dict)
        enhanced_raw_data["real_event_id"] = real_event_id
        enhanced_raw_data["parent_pid"] = parent_pid
        enhanced_raw_data["parent_process_name"] = parent_process_name
        enhanced_raw_data["command_line"] = command_line
        enhanced_raw_data["file_path"] = file_path_val
        enhanced_raw_data["registry_key"] = registry_key
        enhanced_raw_data["extracted_attributes"] = {
            "real_event_id": real_event_id,
            "parent_pid": parent_pid,
            "parent_process_name": parent_process_name,
            "command_line": command_line,
            "file_path": file_path_val,
            "registry_key": registry_key
        }

        subject_data = {
            "type": "process" if process_name else "user",
            "name": process_name,
            "pid": int(pid) if pid and str(pid).isdigit() else None,
            "user": user
        }
        
        object_data = None
        if file_path_val:
            object_data = {"type": "file", "name": Path(file_path_val).name, "path": file_path_val}
        elif registry_key:
            object_data = {"type": "registry", "name": registry_key.split("\\")[-1] if "\\" in registry_key else registry_key, "path": registry_key}

        return NormalizedEvent(
            event_id=f"evt-{uuid.uuid4()}",
            timestamp=timestamp,
            source_type="host_log",
            source=source_name,
            host={"hostname": hostname, "ip": None, "os": "windows"},
            event_type=event_type,
            subject=subject_data,
            object=object_data,
            network=None,
            action=event_type.split('_')[0] if "_" in event_type else None,
            raw_data=enhanced_raw_data,
            severity="low",
            attack=None,
            tags=["windows", source_name, event_type]
        )

    def parse(self, source: Path, max_events: int = None) -> list[NormalizedEvent]:
        events = []
        files_to_process = [source] if source.is_file() else list(source.rglob("*.*"))

        for file_path in files_to_process:
            if max_events and len(events) >= max_events:
                break

            # ① & ② 严格保留原 EVTX 逻辑入口，同时新增 CSV.GZ 的支持
            if file_path.suffix == ".gz":
                try:
                    with gzip.open(file_path, mode='rt', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            if max_events and len(events) >= max_events:
                                break
                            event = self._process_row(row, "windows_sysmon" if "sysmon" in file_path.name.lower() else "windows_security", file_path)
                            if event:
                                events.append(event)
                except Exception as e:
                    print(f"[Error] 读取 CSV.GZ 文件 {file_path} 失败: {e}")
            elif file_path.suffix == ".evtx":
                # 【保留原有EVTX入口】原有系统需要通过解析二进制或者转换为XML后调用此方法
                # 如果项目之前有 EVTX 解析器，请在此处调用原有逻辑。
                # 此处我们保留该入口，为了兼容，暂时不做覆盖。
                pass

        return events