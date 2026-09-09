import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import Evtx.Evtx as evtx
import xmltodict


class WindowsLogParser:
    def __init__(self):
        self.name = "Windows Event Log Parser"

    def parse(self, evtx_path: str) -> list:
        """解析 .evtx 日志文件主入口"""
        results = []
        evtx_file = Path(evtx_path)
        if not evtx_file.exists():
            raise FileNotFoundError(f"找不到日志文件: {evtx_path}")

        with evtx.Evtx(str(evtx_file)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    event_dict = xmltodict.parse(xml_str)
                    if not isinstance(event_dict, dict):
                        continue
                    event_raw = event_dict.get("Event", {}) or {}

                    parsed_event = self.parse_single_event(event_raw)
                    if parsed_event:
                        results.append(parsed_event)
                except Exception as e:
                    logging.warning(f"跳过无法解析的记录: {e}")
                    continue
        return results

    def _extract_event_data(self, event_data_raw: Any) -> Dict[str, str]:
        """安全提取 EventData/UserData 节点映射为 key-value 字典"""
        data_dict = {}
        if not event_data_raw:
            return data_dict

        data_list = event_data_raw if isinstance(event_data_raw, list) else [event_data_raw]
        for item in data_list:
            if isinstance(item, dict):
                name = item.get("@Name") or item.get("Name")
                text = item.get("#text") or item.get("Text") or ""
                if name:
                    data_dict[name] = text
            elif isinstance(item, str):
                data_dict[f"field_{len(data_dict)}"] = item
        return data_dict

    def parse_single_event(self, event_raw: Dict[str, Any]):
        """单条 Windows 安全日志与 Sysmon 日志解析"""
        if not isinstance(event_raw, dict):
            event_raw = {}

        system_info = event_raw.get("System", {}) or {}
        event_data_node = event_raw.get("EventData") or event_raw.get("UserData") or {}
        
        # 兼容不同结构的 EventData Data 节点
        if isinstance(event_data_node, dict):
            event_data_raw = event_data_node.get("Data", [])
        else:
            event_data_raw = []
        event_data = self._extract_event_data(event_data_raw)

        # 提取基础字段
        event_id_obj = system_info.get("EventID", {})
        if isinstance(event_id_obj, dict):
            event_id = str(event_id_obj.get("#text") or "")
        else:
            event_id = str(event_id_obj or "")

        provider_name = ""
        provider_obj = system_info.get("Provider", {})
        if isinstance(provider_obj, dict):
            provider_name = provider_obj.get("@Name", "")

        time_info = system_info.get("TimeCreated", {})
        time_created = time_info.get("@SystemTime") if isinstance(time_info, dict) else datetime.utcnow().isoformat()
        computer = system_info.get("Computer", "unknown")

        event_type = f"windows_event_{event_id}"
        action = "unknown"
        subject = {"type": "user", "name": "unknown", "pid": None, "user": "unknown"}
        obj = None
        network = None

        # ====================================================
        # 一、Windows Security Event Log (安全日志)
        # ====================================================

        # 1. 进程创建 (4688)
        if event_id == "4688":
            event_type = "process_create"
            action = "create_process"
            subject_user = event_data.get("SubjectUserName", "-")
            parent_proc = event_data.get("ParentProcessName", "")
            subject = {
                "type": "process",
                "name": parent_proc.split("\\")[-1] if parent_proc else "unknown",
                "pid": int(event_data.get("ProcessId", "0"), 16) if event_data.get("ProcessId") else None,
                "user": subject_user,
            }
            new_proc = event_data.get("NewProcessName", "")
            cmd_line = event_data.get("CommandLine", "")
            obj = {
                "type": "process",
                "name": new_proc.split("\\")[-1] if new_proc else "unknown",
                "path": new_proc,
                "command_line": cmd_line,
            }

        # 2. 登录/会话 (4624)
        elif event_id == "4624":
            target_user = event_data.get("TargetUserName", "")
            logon_type = str(event_data.get("LogonType", ""))

            if target_user.upper() in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"] or logon_type in ["0", "5"]:
                event_type = "system_session_start"
                action = "system_login"
            else:
                event_type = "user_login"
                action = "login"

            subject = {"type": "user", "name": target_user, "pid": None, "user": target_user}
            ip = event_data.get("IpAddress")
            if ip and ip not in ["-", "127.0.0.1", "::1"]:
                network = {
                    "src_ip": ip,
                    "src_port": event_data.get("IpPort"),
                    "protocol": "tcp",
                }

        # 3. 凭据读取 (5379)
        elif event_id == "5379":
            event_type = "credential_read"
            action = "read_credential"
            subject_user = event_data.get("SubjectUserName", "unknown")
            subject = {"type": "user", "name": subject_user, "pid": None, "user": subject_user}
            target_name = event_data.get("TargetName")
            if target_name:
                obj = {"type": "credential", "name": target_name}

        # 4. 权限赋予 (4672)
        elif event_id == "4672":
            event_type = "privilege_assigned"
            action = "assign_privilege"
            subject_user = event_data.get("SubjectUserName", "SYSTEM")
            subject = {"type": "user", "name": subject_user, "pid": None, "user": subject_user}

        # 5. 组枚举 (4798)
        elif event_id == "4798":
            event_type = "group_enumeration"
            action = "enumerate_group"
            subject_user = event_data.get("SubjectUserName", "unknown")
            subject = {"type": "user", "name": subject_user, "pid": None, "user": subject_user}

        # 6. 用户账号管理 (4720: 创建, 4726: 删除)
        elif event_id in ["4720", "4726"]:
            event_type = "account_management"
            action = "create_user" if event_id == "4720" else "delete_user"
            subject_user = event_data.get("SubjectUserName", "unknown")
            target_user = event_data.get("TargetUserName", "unknown")
            subject = {"type": "user", "name": subject_user, "pid": None, "user": subject_user}
            obj = {"type": "user", "name": target_user}

        # 7. 用户组变更 (4732: 加入本地组, 4728: 加入全局组)
        elif event_id in ["4732", "4728"]:
            event_type = "group_management"
            action = "add_member_to_group"
            subject_user = event_data.get("SubjectUserName", "unknown")
            group_name = event_data.get("TargetGroupName", "unknown")
            member_name = event_data.get("MemberName", "unknown")
            subject = {"type": "user", "name": subject_user, "pid": None, "user": subject_user}
            obj = {"type": "group", "name": group_name, "member": member_name}

        # 8. 服务安装 (7045)
        elif event_id == "7045":
            event_type = "service_installation"
            action = "install_service"
            service_name = event_data.get("ServiceName", "")
            image_path = event_data.get("ImagePath", "")
            subject = {"type": "system", "name": "SYSTEM", "pid": None, "user": "SYSTEM"}
            obj = {"type": "service", "name": service_name, "path": image_path}

        # 9. 计划任务创建 (4698)
        elif event_id == "4698":
            event_type = "scheduled_task_creation"
            action = "create_task"
            subject_user = event_data.get("SubjectUserName", "unknown")
            task_name = event_data.get("TaskName", "")
            subject = {"type": "user", "name": subject_user, "pid": None, "user": subject_user}
            obj = {"type": "scheduled_task", "name": task_name}

        # ====================================================
        # 二、Sysmon Event Log (微件事件)
        # ====================================================
        elif "Sysmon" in provider_name or "Sysmon" in str(system_info):
            # Sysmon ID 1: 进程创建
            if event_id == "1":
                event_type = "process_create"
                action = "create_process"
                user = event_data.get("User", "unknown")
                parent_proc = event_data.get("ParentImage", "")
                subject = {
                    "type": "process",
                    "name": parent_proc.split("\\")[-1] if parent_proc else "unknown",
                    "pid": int(event_data.get("ParentProcessId", 0)) if event_data.get("ParentProcessId") else None,
                    "user": user,
                }
                image = event_data.get("Image", "")
                cmd = event_data.get("CommandLine", "")
                obj = {
                    "type": "process",
                    "name": image.split("\\")[-1] if image else "unknown",
                    "path": image,
                    "command_line": cmd,
                }

            # Sysmon ID 11: 文件创建
            elif event_id == "11":
                event_type = "file_create"
                action = "create_file"
                proc = event_data.get("Image", "")
                user = event_data.get("User", "unknown")
                subject = {
                    "type": "process",
                    "name": proc.split("\\")[-1] if proc else "unknown",
                    "pid": int(event_data.get("ProcessId", 0)) if event_data.get("ProcessId") else None,
                    "user": user,
                }
                target_filename = event_data.get("TargetFilename", "")
                obj = {"type": "file", "path": target_filename, "name": target_filename.split("\\")[-1] if target_filename else ""}

            # Sysmon ID 12/13/14: 注册表项修改
            elif event_id in ["12", "13", "14"]:
                event_type = "registry_event"
                action = "modify_registry"
                proc = event_data.get("Image", "")
                user = event_data.get("User", "unknown")
                subject = {
                    "type": "process",
                    "name": proc.split("\\")[-1] if proc else "unknown",
                    "pid": int(event_data.get("ProcessId", 0)) if event_data.get("ProcessId") else None,
                    "user": user,
                }
                target_object = event_data.get("TargetObject", "")
                obj = {"type": "registry", "path": target_object}

            # Sysmon ID 3: 网络连接
            elif event_id == "3":
                event_type = "network_connection"
                action = "connect_network"
                proc = event_data.get("Image", "")
                user = event_data.get("User", "unknown")
                subject = {
                    "type": "process",
                    "name": proc.split("\\")[-1] if proc else "unknown",
                    "pid": int(event_data.get("ProcessId", 0)) if event_data.get("ProcessId") else None,
                    "user": user,
                }
                network = {
                    "src_ip": event_data.get("SourceIp"),
                    "src_port": event_data.get("SourcePort"),
                    "dest_ip": event_data.get("DestinationIp"),
                    "dest_port": event_data.get("DestinationPort"),
                    "protocol": event_data.get("Protocol", "tcp"),
                }

        # 封装兼容字典及点号属性访问的对象
        return EventResult({
            "event_id": f"evt-{event_id}-{system_info.get('EventRecordID', '')}",
            "timestamp": time_created,
            "source_type": "host_log",
            "source": "windows_security",
            "host": {"hostname": computer, "ip": None, "os": None},
            "event_type": event_type,
            "subject": subject,
            "object": obj,
            "network": network,
            "action": action,
            "raw_data": {"xml_snippet": str(event_raw)},
            "severity": "info",
            "attack": None,
            "tags": [],
        })


class EventResult(dict):
    """同时支持 dict['key'] 和 dict.key 两种访问模式的包装字典类"""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'EventResult' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        self[name] = value

    def model_dump(self, mode="json"):
        return dict(self)