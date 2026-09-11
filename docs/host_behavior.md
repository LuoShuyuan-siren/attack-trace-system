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
- Either subject as the new process with parent details in raw_data
- Or subject as the parent process and object as the new process
- The new process name and PID
- The parent process name and PID when available
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
| HB-PROC-005 | Command references a local password or credential database |
| HB-PROC-006 | Command searches for SSH keys or other credential material |
| HB-FILE-001 | Sensitive credential file read |
| HB-FILE-002 | Persistence-related file modification |
| HB-FILE-003 | Security log file deletion |
| HB-FILE-004 | Executable or script written to a temporary directory |
| HB-FILE-005 | High-volume file changes by one process |
| HB-SYSCALL-001 | High-risk system call |
| HB-SYSCALL-002 | memfd_create followed by execve or execveat |
| HB-SYSCALL-003 | Successful exec transition from a non-root identity to root |
| HB-MEM-001 | Explicit process injection or remote-memory event |

ATT&CK technique IDs are intentionally left empty for the ATT&CK mapping
module. Every result includes a stable rule ID, related event IDs, related
entity IDs and evidence.

## Attack tracing entity direction

The first two related_entity_ids are ordered as source and target:

- Parent-child execution: parent process to child process
- Other process execution: user or host to process
- File behavior: process to file
- Credential command without a PID: host to referenced or inferred file
- Cross-process memory behavior: source process to target process
- Host-local system call without a target PID: host to process
- Privileged execution: process to the elevated user identity

Every detection contains at least one real related_event_id. Evidence uses
structured keys such as rule_id, pid, ppid, process_name, parent_process,
command_line, file_path, operation, matched_conditions, event_count and
time_delta_seconds when applicable.

## Shareable fixtures

The backend/examples directory contains 20 NormalizedEvent records: 7 normal events
and 13 attack events across Windows and Linux. The current analyzer produces
13 DetectionResult records from this fixture. Run the following command from
the repository root to regenerate both JSON files:

    python scripts/generate_host_behavior_fixtures.py

Detection IDs in the fixture are normalized to deterministic det-UUID values
so regeneration does not create unrelated Git changes.

## Real Linux attack-data handoff

The files prefixed with member4_host_behavior_real in backend/examples are a
compact handoff generated from 41 real Linux parser-output events supplied by
the Linux parser owner. The committed subset contains 20 unique
NormalizedEvent records across T1003.008, T1068, T1548.003 and T1552.004. It
produces 12 DetectionResult records: four password-database command alerts,
five credential-material search alerts and three privileged-execution alerts.

The source technique labels are recorded as provenance in the summary only.
The analyzer intentionally leaves attack_technique_id empty because member 6
owns the unified ATT&CK mapping stage. Every DetectionResult references an
event in the committed subset and follows the source-to-target entity order.

Regenerate the handoff with the four parser-output files:

    python scripts/generate_real_host_behavior_handoff.py --t1003-008 T1003.008.json --t1068 T1068.json --t1548-003 T1548.003.json --t1552-004 T1552.004.json

## Parser handoff validation

Use validate_parser_handoff.py when Windows or Linux parser owners provide
new JSON output. The tool validates NormalizedEvent, runs the current analyzer
and reports missing process, file or syscall context without parsing original
EVTX, XML or audit logs inside the Analyzer.

    python scripts/validate_parser_handoff.py --output examples/parser_handoff_report.json parser-output-1.json parser-output-2.json

When an input is known to be simulated, add simulated-input so the generated
report preserves provenance and does not present it as real testbed evidence:

    python scripts/validate_parser_handoff.py --simulated-input simulated.json --output examples/parser_handoff_report.json simulated.json

## Run tests

From the backend directory:

    python -m unittest discover -s tests -v

The example input is available in
backend/examples/member4_host_behavior_events.json.
