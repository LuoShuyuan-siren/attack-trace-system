import sys
import time
import json
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend.app.parsers.windows_log_parser import WindowsLogParser

def main():
    print("="*40)
    print("成员2 最终交付版测试启动...")
    
    data_dir = Path("datasets/botsv1_csv")
    sysmon_files = list(data_dir.glob("*Sysmon*"))
    target = sysmon_files[0] if sysmon_files else data_dir
    
    parser = WindowsLogParser()
    start_time = time.perf_counter()
    
    print("开始全量解析 Sysmon 日志，寻找真实的进程创建事件...")
    events = parser.parse(target, max_events=100000)
    
    # 筛选真实的进程创建事件 (EventCode 1)
    real_process_samples = []
    for e in events:
        e_dict = e.model_dump()
        if e_dict.get('event_type') == 'process_create':
            real_process_samples.append(e_dict)
            
    print(f"共找到 {len(real_process_samples)} 条真实进程创建事件。")
    
    # 挑选 10 条，优先挑选有 command_line 的
    final_samples = []
    for e in real_process_samples:
        attrs = e.get("raw_data", {}).get("extracted_attributes", {})
        if attrs.get("command_line") and len(final_samples) < 10:
            final_samples.append(e)
            
    if len(final_samples) < 10:
        for e in real_process_samples:
            if e not in final_samples:
                final_samples.append(e)
            if len(final_samples) >= 10:
                break

    print(f"最终提取到 {len(final_samples)} 条真实进程事件供成员4联调。")
    
    output_dir = Path("backend/tests/fixtures/output")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 保存真实数据
    real_file = output_dir / "member4_real_sysmon_samples.json"
    with open(real_file, 'w', encoding='utf-8') as f:
        json.dump(final_samples, f, ensure_ascii=False, indent=2, default=str)
    print(f"✅ 真实数据已保存至: {real_file.absolute()}")
    
    # ================= 核心修改区域：补齐成员4要求的 Mock 数据 =================
    mock_file_events = [
        {
            "event_id": "evt-mock-file-001",
            "timestamp": "2016-08-24T12:28:00Z",
            "source_type": "host_log",
            "source": "windows_sysmon",
            "host": {"hostname": "we8105desk", "ip": None, "os": "windows"},
            "event_type": "file_create",
            "action": "create",  # 补齐 action
            "subject": {"type": "process", "name": "C:\\Windows\\System32\\cmd.exe", "pid": 1234, "user": "waynecorp\\bob.smith"},
            "object": {"type": "file", "name": "payload.exe", "path": "C:\\Users\\bob.smith\\payload.exe"},
            "raw_data": {"extracted_attributes": {"real_event_id": "999", "parent_pid": "592", "parent_process_name": "explorer.exe", "command_line": "cmd.exe /c copy payload.exe", "file_path": "C:\\Users\\bob.smith\\payload.exe", "registry_key": None}},
            "tags": ["windows", "mock", "simulated"]  # 补齐 simulated 标签
        },
        {
            "event_id": "evt-mock-reg-001",
            "timestamp": "2016-08-24T12:29:00Z",
            "source_type": "host_log",
            "source": "windows_sysmon",
            "host": {"hostname": "we8105desk", "ip": None, "os": "windows"},
            "event_type": "registry_set",
            "action": "set",  # 补齐 action
            "subject": {"type": "process", "name": "C:\\Windows\\System32\\reg.exe", "pid": 5678, "user": "waynecorp\\bob.smith"},
            "object": {"type": "registry", "name": "Run", "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            "raw_data": {"extracted_attributes": {"real_event_id": "1000", "parent_pid": "1234", "parent_process_name": "cmd.exe", "command_line": "reg add HKLM\\...", "file_path": None, "registry_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}},
            "tags": ["windows", "mock", "simulated"]  # 补齐 simulated 标签
        },
        {
            # 新增 process_access 事件
            "event_id": "evt-mock-access-001",
            "timestamp": "2016-08-24T12:30:00Z",
            "source_type": "host_log",
            "source": "windows_sysmon",
            "host": {"hostname": "we8105desk", "ip": None, "os": "windows"},
            "event_type": "process_access",
            "action": "access",  # 补齐 action
            "subject": {"type": "process", "name": "C:\\Windows\\System32\\lsass.exe", "pid": 789, "user": "NT AUTHORITY\\SYSTEM"},
            "object": {"type": "process", "name": "C:\\Windows\\System32\\cmd.exe", "path": None},
            "raw_data": {"extracted_attributes": {"real_event_id": "1001", "parent_pid": "456", "parent_process_name": "svchost.exe", "command_line": "lsass.exe", "file_path": None, "registry_key": None}},
            "tags": ["windows", "mock", "simulated"]  # 补齐 simulated 标签
        }
    ]
    # =========================================================================
    
    mock_file = output_dir / "member4_mock_sysmon_samples.json"
    with open(mock_file, 'w', encoding='utf-8') as f:
        json.dump(mock_file_events, f, ensure_ascii=False, indent=2, default=str)
    print(f"⚠️ Mock补齐数据（已标注 simulated，含 action 与 process_access）已保存至: {mock_file.absolute()}")
    print("="*40)

if __name__ == "__main__":
    main()