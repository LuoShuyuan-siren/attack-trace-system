# Real tracing integration fixtures

Place sanitized JSON arrays in the matching source directory:

- `windows/events.json`
- `linux/events.json`
- `host_behavior/events.json`
- `network/events.json`
- `attack_mapping/detections.json`

Event files contain `NormalizedEvent[]`; detection files contain
`DetectionResult[]`. Do not commit credentials, raw logs, PCAP/EVTX files,
personal data, or large datasets.
