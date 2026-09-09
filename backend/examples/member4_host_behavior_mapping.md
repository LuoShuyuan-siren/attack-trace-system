# Member 4 Host Behavior Rule Mapping

The table below combines Member 4 rule descriptions with the ATT&CK mapping
used by Member 6.

| Rule ID | Member 4 rule description | Technique ID | Technique | Tactic ID | Tactic |
| --- | --- | --- | --- | --- | --- |
| HB-PROC-001 | Document application spawns a shell or script interpreter | T1059.001 | PowerShell | TA0002 | Execution |
| HB-PROC-002 | Web service spawns a shell or script interpreter | T1190 | Exploit Public-Facing Application | TA0001 | Initial Access |
| HB-PROC-003 | Suspicious encoded or dynamic-execution command line | T1059.001 | PowerShell | TA0002 | Execution |
| HB-PROC-004 | Executable or script launched from a temporary directory | T1059.004 | Unix Shell | TA0002 | Execution |
| HB-FILE-001 | Sensitive credential file read | T1003 | OS Credential Dumping | TA0006 | Credential Access |
| HB-FILE-002 | Persistence-related file modification | T1547 | Boot or Logon Autostart Execution | TA0003 | Persistence |
| HB-FILE-003 | Security log file deletion | T1070 | Indicator Removal | TA0005 | Defense Evasion |
| HB-FILE-004 | Executable or script written to a temporary directory | T1105 | Ingress Tool Transfer | TA0011 | Command and Control |
| HB-SYSCALL-001 | High-risk system call | T1055 | Process Injection | TA0004 | Privilege Escalation |
| HB-SYSCALL-001 | High-risk system call | T1055 | Process Injection | TA0005 | Defense Evasion |
| HB-SYSCALL-002 | memfd_create followed by execve or execveat | T1620 | Reflective Code Loading | TA0005 | Defense Evasion |
| HB-MEM-001 | Explicit process injection or remote-memory event | T1055 | Process Injection | TA0004 | Privilege Escalation |
| HB-MEM-001 | Explicit process injection or remote-memory event | T1055 | Process Injection | TA0005 | Defense Evasion |

The original `related_entity_ids` order and `related_event_ids` are preserved.
