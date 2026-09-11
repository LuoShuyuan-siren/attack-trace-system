import gzip
import csv
import json
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone

from backend.app.core.parser import BaseParser
from backend.app.schemas.event import NormalizedEvent

class WindowsLogParser(BaseParser):
    name = "windows_log_parser"
    source_type = "host_log"

    def __init__(self):
        super().__init__()
        # 包含常见的 Security 和 Sysmon 事件ID
        self.event_code_map = {
            "1": "process_create", "10": "process_access", "4688": "process_create",
            "11": "file_create", "23": "file_delete", "4663": "file_modify",
            "12": "registry_create", "13": "registry_set", "14": "registry_rename",
            "4624": "user_login", "4625": "user_login_failed",
        }
        self.debug_count = 0

    def _parse_time(self, raw_time: str) -> str:
        if not raw_time: return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        try:
            match = re.search(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?)', raw_time)
            if match:
                clean_time = match.group(1).replace(' ', 'T')
                return datetime.strptime(clean_time.split('.')[0], "%Y-%m-%dT%H:%M:%S").strftime('%Y-%m-%dT%H:%M:%SZ')
            return raw_time
        except ValueError:
            return raw_time

    def _extract_from_raw(self, raw_text: str) -> dict:
        extracted = {}
        if not raw_text: return extracted
        
        raw_text = raw_text.replace('\r\n', '\n').strip()
        
        # 1. 尝试按 JSON 解析
        try: return json.loads(raw_text)
        except: pass
        
        # 2. 尝试按 XML 解析 (Sysmon)
        if raw_text.startswith("<"):
            event_id_match = re.search(r'<EventID>\s*(\d+)\s*</EventID>', raw_text)
            if event_id_match: extracted['EventCode'] = event_id_match.group(1)
            data_matches = re.finditer(r'<Data Name=[\'"]([^\'"]+)[\'"]>(.*?)</Data>', raw_text, re.DOTALL)
            for match in data_matches:
                extracted[match.group(1)] = match.group(2).strip()
            return extracted
            
        # 3. 纯文本 Key=Value 或 Key: Value 解析 (Security 日志)
        # 提取 EventCode
        match = re.search(r'(?:EventCode|EventID|Event_Id)[=:\s]+(\d+)', raw_text, re.IGNORECASE)
        if match: extracted['EventCode'] = match.group(1)
            
        # 逐行提取键值对，兼容 "Key=Value" 和 "Key: Value" 两种格式
        for line in raw_text.splitlines():
            line = line.strip()
            if "=" in line:
                parts = line.split("=", 1)
                extracted[parts[0].strip()] = parts[1].strip()
            elif ":" in line:
                parts = line.split(":", 1)
                extracted[parts[0].strip()] = parts[1].strip()
                
        return extracted

    def parse(self, source: Path, max_events: int = None) -> list[NormalizedEvent]:
        events = []
        files_to_process = [source] if source.is_file() else list(source.rglob("*.csv.gz"))
        
        for file_path in files_to_process:
            if max_events and len(events) >= max_events: break
            try:
                with gzip.open(file_path, mode='rt', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if max_events and len(events) >= max_events: break
                        try:
                            raw_dict = self._extract_from_raw(row.get("_raw", ""))
                            raw_event_id = raw_dict.get("EventCode") or raw_dict.get("EventID")
                            event_code = str(raw_event_id) if raw_event_id else ""
                            event_type = self.event_code_map.get(event_code, "unknown_event")
                            if event_type == "unknown_event": continue
                            
                            raw_time = row.get("_time") or row.get("timestamp")
                            timestamp = self._parse_time(raw_time)
                            source_name = "windows_sysmon" if "sysmon" in file_path.name.lower() else "windows_security"
                            hostname = row.get("host") or "unknown_host"
                            
                            # 字段提取，兼容 Sysmon (Image) 和 Security (Process Name)
                            user = raw_dict.get("User") or raw_dict.get("user") or raw_dict.get("Account Name") or "unknown"
                            process_name = raw_dict.get("Image") or raw_dict.get("process_name") or raw_dict.get("NewProcessName") or raw_dict.get("Process Name")
                            pid = raw_dict.get("ProcessId") or raw_dict.get("pid") or raw_dict.get("NewProcessId") or raw_dict.get("Process ID")
                            real_event_id = raw_dict.get("EventRecordID") or raw_dict.get("RecordID") or raw_dict.get("RecordNumber") or event_code
                            parent_pid = raw_dict.get("ParentProcessId") or raw_dict.get("Parent Process ID")
                            parent_process_name = raw_dict.get("ParentImage") or raw_dict.get("Parent Process Name")
                            command_line = raw_dict.get("CommandLine") or raw_dict.get("Command Line")
                            file_path_val = raw_dict.get("TargetFilename") or raw_dict.get("ObjectName") or raw_dict.get("Object Name")
                            registry_key = raw_dict.get("TargetObject")
                            
                            # 如果有 Object Name，检查它是否为注册表
                            if file_path_val and "\\REGISTRY\\" in file_path_val.upper():
                                registry_key = file_path_val
                                file_path_val = None

                            # 处理十六进制 PID 转换
                            if pid and isinstance(pid, str) and pid.startswith('0x'):
                                try: pid = int(pid, 16)
                                except: pass
                            if parent_pid and isinstance(parent_pid, str) and parent_pid.startswith('0x'):
                                try: parent_pid = int(parent_pid, 16)
                                except: pass

                            subject_data = {
                                "type": "process" if process_name else "user",
                                "name": process_name,
                                "pid": int(pid) if pid and str(pid).isdigit() else None,
                                "user": user
                            }
                            
                            enhanced_raw_data = dict(row)
                            enhanced_raw_data["extracted_attributes"] = {
                                "real_event_id": real_event_id,
                                "parent_pid": parent_pid,
                                "parent_process_name": parent_process_name,
                                "command_line": command_line,
                                "file_path": file_path_val,
                                "registry_key": registry_key
                            }
                            
                            object_data = None
                            if file_path_val:
                                object_data = {"type": "file", "name": Path(file_path_val).name, "path": file_path_val}
                            elif registry_key:
                                object_data = {"type": "registry", "name": registry_key.split("\\")[-1] if "\\" in registry_key else registry_key, "path": registry_key}

                            event = NormalizedEvent(
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
                            events.append(event)
                        except Exception as e:
                            if self.debug_count < 5:
                                print(f"[Debug] 单行解析失败: {e}")
                                self.debug_count += 1
                            continue
            except Exception as e:
                print(f"[Error] 读取文件 {file_path} 失败: {e}")
                continue
        return events