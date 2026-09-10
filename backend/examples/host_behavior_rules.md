# Host Behavior Analyzer

## Responsibility

HostBehaviorAnalyzer consumes NormalizedEvent objects and returns
DetectionResult objects. It does not parse EVTX, auditd logs, PCAP files or
other original data, and it does not build ATT&CK mappings or attack graphs.

## Preliminary event contract

The shared schemas are not modified. Parser-specific details are read from
raw_data through a compatibility adapter.

Process creation events should provide:

- event_type: process_create
- subject.name and subject.pid: the newly created process
- raw_data.parent_pid
- raw_data.parent_process_name
- raw_data.command_line

File events should use file_create, file_modify, file_delete or file_read and
place the target path in object.path.

System call events should use event_type system_call and provide
raw_data.syscall, raw_data.arguments and raw_data.result.

The adapter currently accepts common aliases such as ParentProcessId,
ParentImage, CommandLine, ppid and syscall_name. Once Windows and Linux parser
owners finalize their output, aliases can be adjusted in adapters.py without
rewriting detection rules.

When a process event contains parent_pid but no parent process name, the
analyzer resolves the name from earlier events on the same host. Events are
sorted by timestamp before this process context is built.

## Implemented rule IDs

| Rule ID | Behavior |
| --- | --- |
| HB-PROC-001 | Document application spawns a shell or script interpreter |
| HB-PROC-002 | Web service spawns a shell or script interpreter |
| HB-PROC-003 | Suspicious encoded or dynamic-execution command line |
| HB-PROC-004 | Executable or script launched from a temporary directory |
| HB-FILE-001 | Sensitive credential file read |
| HB-FILE-002 | Persistence-related file modification |
| HB-FILE-003 | Security log file deletion |
| HB-FILE-004 | Executable or script written to a temporary directory |
| HB-FILE-005 | High-volume file changes by one process |
| HB-SYSCALL-001 | High-risk system call |
| HB-SYSCALL-002 | memfd_create followed by execve or execveat |
| HB-MEM-001 | Explicit process injection or remote-memory event |

ATT&CK technique IDs are intentionally left empty for the ATT&CK mapping
module. Every result includes a stable rule ID, related event IDs, related
entity IDs and evidence.

## Attack tracing entity direction

The first two related_entity_ids are ordered as source and target:

- Parent-child execution: parent process to child process
- Other process execution: user or host to process
- File behavior: process to file
- Cross-process memory behavior: source process to target process
- Host-local system call without a target PID: host to process

Every detection contains at least one real related_event_id. Evidence uses
structured keys such as rule_id, pid, ppid, process_name, parent_process,
command_line, file_path, operation, matched_conditions, event_count and
time_delta_seconds when applicable.

## Shareable fixtures

The examples directory contains 20 NormalizedEvent records: 7 normal events
and 13 attack events across Windows and Linux. The current analyzer produces
13 DetectionResult records from this fixture. Run the following command from
the repository root to regenerate both JSON files:

    python scripts/generate_host_behavior_fixtures.py

Detection IDs in the fixture are normalized to deterministic det-UUID values
so regeneration does not create unrelated Git changes.

## Run tests

From the backend directory:

    python -m unittest discover -s tests -v

The example input is available in examples/host_behavior_events.json.
