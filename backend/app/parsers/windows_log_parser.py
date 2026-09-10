"""
Windows 日志统一解析器
支持 Security.evtx 和 Sysmon.evtx
"""

from pathlib import Path
from typing import List, Optional, Dict, Any
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

from ..core.parser import BaseParser
from ..schemas.event import NormalizedEvent


def clean_str(value: Optional[str]) -> Optional[str]:
    """清理字符串，移除无效 Unicode 替换字符，去除首尾空格"""
    if not value:
        return None
    value = str(value).replace('\ufffd', '').strip()
    return value if value else None


def safe_int(value) -> int:
    """
    安全转换为整数，支持：
    - 十六进制字符串（如 '0x1234' 或 '0x00000000000001b4'）
    - 十进制字符串（如 '1234'）
    - None 或空字符串返回 0
    """
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    value = str(value).strip()
    if not value:
        return 0
    try:
        if value.lower().startswith('0x'):
            return int(value, 16)
        else:
            return int(value, 10)
    except (ValueError, TypeError):
        try:
            return int(value, 16)
        except:
            return 0


def get_nested_value(data: Dict[str, Any], *keys) -> Optional[str]:
    """从字典中按优先级顺序获取第一个存在的值"""
    for key in keys:
        if key in data:
            val = data.get(key)
            if val is not None and str(val).strip():
                return val
    return None


class WindowsLogParser(BaseParser):
    """Windows 日志解析器（兼容 Security 和 Sysmon）"""

    @property
    def name(self) -> str:
        return "windows_log_parser"

    @property
    def source_type(self) -> str:
        return "host_log"

    def parse(self, source: Path) -> List[NormalizedEvent]:
        """解析单个 .evtx 文件，返回 NormalizedEvent 列表"""
        # 只处理 Security 和 Sysmon 日志，跳过 Application 和 System
        if "Security" not in source.name and "Sysmon" not in source.name:
            print(f"⏭️ 跳过非 Security/Sysmon 文件: {source.name}")
            return []

        print(f"🔍 正在解析: {source.name}")
        events = []

        if not source.exists():
            print(f"⚠️ 文件不存在: {source}")
            return events

        try:
            with Evtx(str(source)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)

                        # ----- 提取 EventData 中的所有键值对 -----
                        event_data = {}
                        for data in root.iter():
                            if data.tag.endswith('Data'):
                                name = data.attrib.get('Name')
                                if name:
                                    event_data[name] = clean_str(data.text)

                        # 如果上面的方法没取到，尝试通过 XPath 直接取
                        if not event_data:
                            for data in root.findall('.//{*}Data'):
                                name = data.attrib.get('Name')
                                if name:
                                    event_data[name] = clean_str(data.text)

                        # ----- 提取事件 ID -----
                        event_id_node = root.find('.//{*}EventID')
                        if event_id_node is None:
                            event_id_node = root.find('.//EventID')
                        event_id = int(event_id_node.text) if event_id_node is not None else 0

                        # ----- 提取时间戳 -----
                        time_created = root.find('.//{*}TimeCreated')
                        if time_created is None:
                            time_created = root.find('.//TimeCreated')
                        timestamp = time_created.attrib.get('SystemTime') if time_created is not None else None

                        # ----- 提取主机名 -----
                        computer = root.find('.//{*}Computer')
                        if computer is None:
                            computer = root.find('.//Computer')
                        hostname = computer.text if computer is not None else "Unknown"

                        # 根据事件 ID 构造 NormalizedEvent
                        parsed = self._parse_event(event_id, event_data, timestamp, hostname)
                        if parsed:
                            events.append(parsed)

                    except Exception as e:
                        # 单条事件解析失败，继续下一条
                        continue

        except Exception as e:
            print(f"解析 {source.name} 时出错: {e}")
            import traceback
            traceback.print_exc()

        return events

    def _parse_event(self, event_id: int, data: Dict[str, Any], timestamp: str, hostname: str):
        """根据事件 ID 构造具体的 NormalizedEvent"""
        
        # 公共 host 信息
        host = {
            "hostname": hostname,
            "ip": None,
            "os": "windows"
        }

        # ---------------- Sysmon 事件 ----------------
        if event_id in (1, 3, 11, 13, 22):
            source = "windows_sysmon"

            # Sysmon 1: 进程创建
            if event_id == 1:
                return NormalizedEvent(
                    event_id=f"evt-{hostname}-{timestamp}-{event_id}",
                    timestamp=timestamp,
                    source_type="host_log",
                    source=source,
                    host=host,
                    event_type="process_create",
                    subject={
                        "type": "process",
                        "name": clean_str(data.get("Image")),
                        "pid": safe_int(data.get("ProcessId")),
                        "user": clean_str(data.get("User"))
                    },
                    object={
                        "type": "process",
                        "name": clean_str(data.get("ParentImage")),
                        "pid": safe_int(data.get("ParentProcessId"))
                    },
                    network=None,
                    action="create_process",
                    raw_data={"command_line": clean_str(data.get("CommandLine"))},
                    severity="medium",
                    attack=None,
                    tags=["sysmon", "process"]
                )

            # Sysmon 3: 网络连接
            if event_id == 3:
                return NormalizedEvent(
                    event_id=f"evt-{hostname}-{timestamp}-{event_id}",
                    timestamp=timestamp,
                    source_type="host_log",
                    source=source,
                    host=host,
                    event_type="network_connection",
                    subject={
                        "type": "process",
                        "name": clean_str(data.get("Image")),
                        "pid": safe_int(data.get("ProcessId")),
                        "user": clean_str(data.get("User")),
                    },
                    object=None,
                    network={
                        "src_ip": clean_str(data.get("SourceIp")),
                        "src_port": safe_int(data.get("SourcePort")),
                        "dst_ip": clean_str(data.get("DestinationIp")),
                        "dst_port": safe_int(data.get("DestinationPort")),
                        "protocol": clean_str(data.get("Protocol")),
                    },
                    action="connect",
                    raw_data={
                        "source_hostname": clean_str(
                            data.get("SourceHostname")
                        ),
                        "destination_hostname": clean_str(
                            data.get("DestinationHostname")
                        ),
                        "initiated": clean_str(
                            data.get("Initiated")
                        ),
                    },
                    severity="medium",
                    attack=None,
                    tags=["sysmon", "network"],
                )
            # Sysmon 11: 文件创建
            if event_id == 11:
                return NormalizedEvent(
                    event_id=f"evt-{hostname}-{timestamp}-{event_id}",
                    timestamp=timestamp,
                    source_type="host_log",
                    source=source,
                    host=host,
                    event_type="file_create",
                    subject={
                        "type": "process",
                        "name": clean_str(data.get("Image")),
                        "pid": safe_int(data.get("ProcessId")),
                        "user": clean_str(data.get("User"))
                    },
                    object={
                        "type": "file",
                        "path": clean_str(data.get("TargetFilename"))
                    },
                    network=None,
                    action="create_file",
                    raw_data={},
                    severity="low",
                    attack=None,
                    tags=["sysmon", "file"]
                )

            # Sysmon 13: 注册表值修改
            if event_id == 13:
                return NormalizedEvent(
                    event_id=f"evt-{hostname}-{timestamp}-{event_id}",
                    timestamp=timestamp,
                    source_type="host_log",
                    source=source,
                    host=host,
                    event_type="registry_modify",
                    subject={
                        "type": "process",
                        "name": clean_str(data.get("Image")),
                        "pid": safe_int(data.get("ProcessId")),
                        "user": clean_str(data.get("User")),
                    },
                    object={
                        "type": "registry",
                        "name": clean_str(data.get("TargetObject")),
                        "path": clean_str(data.get("TargetObject")),
                    },
                    network=None,
                    action="modify_registry",
                    raw_data={
                        "details": clean_str(data.get("Details")),
                        "event_type": clean_str(data.get("EventType")),
                    },
                    severity="medium",
                    attack=None,
                    tags=["sysmon", "registry"],
                )

            # Sysmon 22: DNS 查询
            if event_id == 22:
                return NormalizedEvent(
                    event_id=f"evt-{hostname}-{timestamp}-{event_id}",
                    timestamp=timestamp,
                    source_type="host_log",
                    source=source,
                    host=host,
                    event_type="dns_query",
                    subject={
                        "type": "process",
                        "name": clean_str(data.get("Image")),
                        "pid": safe_int(data.get("ProcessId")),
                        "user": clean_str(data.get("User")),
                    },
                    object={
                        "type": "domain",
                        "name": clean_str(data.get("QueryName")),
                    },
                    network={
                        "protocol": "dns",
                    },
                    action="dns_query",
                    raw_data={
                        "query": clean_str(data.get("QueryName")),
                        "query_status": clean_str(data.get("QueryStatus")),
                        "query_results": clean_str(data.get("QueryResults")),
                    },
                    severity="medium",
                    attack=None,
                    tags=["sysmon", "dns"],
                )

        # ---------------- Security 事件 ----------------
        elif event_id in (4624, 4688):
            source = "windows_security"

            # Security 4624: 登录
            if event_id == 4624:
                return NormalizedEvent(
                    event_id=f"evt-{hostname}-{timestamp}-{event_id}",
                    timestamp=timestamp,
                    source_type="host_log",
                    source=source,
                    host=host,
                    event_type="user_login",
                    subject={
                        "type": "user",
                        "name": clean_str(data.get("TargetUserName"))
                    },
                    object=None,
                    network={
                        "src_ip": clean_str(data.get("IpAddress")),
                        "src_port": safe_int(data.get("IpPort")),
                    },
                    action="login",
                    raw_data={},
                    severity="info",
                    attack=None,
                    tags=["security", "login"]
                )

            # Security 4688: 进程创建
            # 字段含义（重要！）：
            # - ProcessId = 父进程 PID (subject.pid)
            # - NewProcessId = 新进程 PID (object.pid)  
            # - NewProcessName = 新进程路径 (object.name/path)
            # - SubjectUserName = 执行用户 (subject.user)
            if event_id == 4688:
                # ---- 提取原始字段（兼容多种字段名） ----
                # 父进程 PID
                process_id = get_nested_value(
                    data,
                    "ProcessId",
                    "Process ID",
                    "SubjectProcessId"
                )
                # 新进程 PID
                new_process_id = get_nested_value(
                    data,
                    "NewProcessId",
                    "New Process ID",
                    "TargetProcessId"
                )
                # 新进程名称（这是最重要的字段！）
                new_process_name = get_nested_value(
                    data,
                    "NewProcessName",
                    "New Process Name",
                    "TargetProcessName",
                    "ProcessName"
                )
                # 命令行（可能为 None，取决于系统配置）
                command_line = get_nested_value(
                    data,
                    "CommandLine",
                    "Command Line",
                    "ProcessCommandLine"
                )
                # 执行用户
                subject_user = get_nested_value(
                    data,
                    "SubjectUserName",
                    "Subject User Name",
                    "User"
                )
                # 登录会话 ID
                logon_id = get_nested_value(
                    data,
                    "SubjectLogonId",
                    "Subject Logon ID",
                    "LogonId"
                )

                # ---- 转换 PID ----
                pid_int = safe_int(process_id)
                new_pid_int = safe_int(new_process_id)

                # ---- 调试打印（关键！用于验证字段提取） ----
                # print(f"  📌 4688: "
                #       f"ProcessId={process_id} -> {pid_int}, "
                #       f"NewProcessId={new_process_id} -> {new_pid_int}, "
                #       f"NewProcessName={new_process_name[:60] if new_process_name else 'None'}, "
                #       f"SubjectUser={subject_user}, "
                #       f"CommandLine={command_line[:40] if command_line else 'None'}")

                # ---- 构造 NormalizedEvent ----
                return NormalizedEvent(
                    event_id=f"evt-{hostname}-{timestamp}-{event_id}",
                    timestamp=timestamp,
                    source_type="host_log",
                    source=source,
                    host=host,
                    event_type="process_create",
                    subject={
                        "type": "process",
                        "name": None,  # Security 4688 不提供父进程路径
                        "pid": pid_int,           # 父进程 PID
                        "user": clean_str(subject_user)
                    },
                    object={
                        "type": "process",
                        "name": clean_str(new_process_name),
                        "path": clean_str(new_process_name),
                        "pid": new_pid_int         # 新进程 PID
                    },
                    network=None,
                    action="create_process",
                    raw_data={
                        "command_line": clean_str(command_line),
                        "logon_id": clean_str(logon_id),
                    },
                    severity="low",
                    attack=None,
                    tags=["security", "process"]
                )

        return None