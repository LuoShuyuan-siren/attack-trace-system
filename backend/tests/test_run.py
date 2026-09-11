import sys
import time
import json
from pathlib import Path

# 修复路径
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.parsers.windows_log_parser import WindowsLogParser

def main():
    print("="*40)
    print("成员2 Windows 日志解析测试启动...")
    
    data_dir = Path("datasets/botsv1_csv")
    if not data_dir.exists():
        print(f"[Error] 数据目录不存在: {data_dir.absolute()}")
        return

    parser = WindowsLogParser()
    start_time = time.perf_counter()
    
    # 优先找 Sysmon 数据
    sysmon_files = list(data_dir.glob("*Sysmon*"))
    target = sysmon_files[0] if sysmon_files else data_dir
    
    # 关键修改：扩大预读范围，因为 EventCode 1 是零星的
    print("开始解析，预读 300000 条以便筛选不同类型的事件...")
    events = parser.parse(target, max_events=300000)
    
    # 打印所有提取到的事件类型分布，让你看清数据到底有哪些
    from collections import Counter
    event_types = Counter([e.model_dump().get('event_type') for e in events])
    print(f"提取到的事件类型分布: {event_types}")
    
    # 按类型筛选
    process_samples, file_samples, registry_samples = [], [], []
    for e in events:
        e_dict = e.model_dump()
        etype = e_dict.get('event_type', '')
        
        # 如果有很多网络事件，也可以抓一些
        if etype in ['process_create', 'process_access'] and len(process_samples) < 10:
            process_samples.append(e_dict)
        elif 'file' in etype and len(file_samples) < 10:
            file_samples.append(e_dict)
        elif 'registry' in etype and len(registry_samples) < 10:
            registry_samples.append(e_dict)
            
    member4_samples = process_samples + file_samples + registry_samples
    print(f"筛选完成：进程 {len(process_samples)} 条，文件 {len(file_samples)} 条，注册表 {len(registry_samples)} 条")
    
    output_dir = Path("backend/tests/fixtures/output")
    output_dir.mkdir(parents=True, exist_ok=True)
    member4_file = output_dir / "member4_sysmon_samples.json"
    
    with open(member4_file, 'w', encoding='utf-8') as f:
        json.dump(member4_samples, f, ensure_ascii=False, indent=2, default=str)
    
    print(f"成员4联调样例数据（{len(member4_samples)}条）已保存至: {member4_file.absolute()}")
    if member4_samples:
        e_dict = member4_samples[0]
        print("\n[检查] 第一条数据 raw_data 顶层平铺字段:")
        print(f"command_line: {e_dict.get('raw_data', {}).get('command_line')}")
        print(f"parent_pid: {e_dict.get('raw_data', {}).get('parent_pid')}")
    print("="*40)

if __name__ == "__main__":
    main()