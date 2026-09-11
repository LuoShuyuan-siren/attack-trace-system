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
    # 读取10万条，足够找到767条进程事件中的6~10条
    events = parser.parse(target, max_events=100000)
    
    # 筛选真实的进程创建事件 (EventCode 1)
    real_process_samples = []
    for e in events:
        e_dict = e.model_dump()
        if e_dict.get('event_type') == 'process_create':
            real_process_samples.append(e_dict)
            
    print(f"共找到 {len(real_process_samples)} 条真实进程创建事件。")
    
    # 挑选 6~10 条，优先挑选有 command_line 的
    final_samples = []
    for e in real_process_samples:
        attrs = e.get("raw_data", {}).get("extracted_attributes", {})
        if attrs.get("command_line") and len(final_samples) < 10:
            final_samples.append(e)
            
    # 如果不够6条，用普通的进程事件补齐
    if len(final_samples) < 6:
        for e in real_process_samples:
            if e not in final_samples:
                final_samples.append(e)
            if len(final_samples) >= 6:
                break

    print(f"最终提取到 {len(final_samples)} 条真实进程事件供成员4联调。")
    
    output_dir = Path("backend/tests/fixtures/output")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 保存真实数据
    real_file = output_dir / "member4_real_sysmon_samples.json"
    with open(real_file, 'w', encoding='utf-8') as f:
        json.dump(final_samples, f, ensure_ascii=False, indent=2, default=str)
    print(f"✅ 真实数据已保存至: {real_file.absolute()}")
    
    # 保存一份 Mock 补齐数据 (单独存放，不混淆)
    mock_file = output_dir / "member4_mock_sysmon_samples.json"
    mock_data = [
        {
            "event_id": "evt-mock-file-001",
            "timestamp": "2016-08-24T12:28:00Z",
            "source_type": "host_log",
            "source": "windows_sysmon",
            "host": {"hostname": "we8105desk", "os": "windows"},
            "event_type": "file_create",
            "subject": {"type": "process", "name": "C:\\Windows\\System32\\cmd.exe", "pid": 1234, "user": "waynecorp\\bob.smith"},
            "object": {"type": "file", "name": "payload.exe", "path": "C:\\Users\\bob.smith\\payload.exe"},
            "raw_data": {"extracted_attributes": {"real_event_id": "999", "parent_pid": "592", "parent_process_name": "explorer.exe", "command_line": "cmd.exe /c copy payload.exe", "file_path": "C:\\Users\\bob.smith\\payload.exe", "registry_key": None}}
        },
        {
            "event_id": "evt-mock-reg-001",
            "timestamp": "2016-08-24T12:29:00Z",
            "source_type": "host_log",
            "source": "windows_sysmon",
            "host": {"hostname": "we8105desk", "os": "windows"},
            "event_type": "registry_set",
            "subject": {"type": "process", "name": "C:\\Windows\\System32\\reg.exe", "pid": 5678, "user": "waynecorp\\bob.smith"},
            "object": {"type": "registry", "name": "Run", "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            "raw_data": {"extracted_attributes": {"real_event_id": "1000", "parent_pid": "1234", "parent_process_name": "cmd.exe", "command_line": "reg add HKLM\\...", "file_path": None, "registry_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}}
        }
    ]
    with open(mock_file, 'w', encoding='utf-8') as f:
        json.dump(mock_data, f, ensure_ascii=False, indent=2, default=str)
    print(f"⚠️ Mock补齐数据（明确标注）已保存至: {mock_file.absolute()}")
    print("="*40)

if __name__ == "__main__":
    main()