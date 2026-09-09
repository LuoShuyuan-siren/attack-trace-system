import type { EventItem } from '../types/event';

export const mockEvents: EventItem[] = [
  {
    event_id: 'evt-001',
    timestamp: '2026-09-08T10:20:00Z',
    source_type: 'host_log',
    source: 'windows_sysmon',
    host: {
      hostname: 'WIN-PC01',
      ip: '192.168.1.20',
      os: 'windows',
    },
    event_type: 'process_create',
    severity: 'high',
    action: 'create_process',
    tags: ['powershell', 'process'],
    raw_data: {
      process_name: 'powershell.exe',
      command_line: 'powershell.exe -enc ...',
    },
  },
  {
    event_id: 'evt-002',
    timestamp: '2026-09-08T10:22:10Z',
    source_type: 'host_behavior',
    source: 'ebpf',
    host: {
      hostname: 'WEB01',
      ip: '10.0.0.15',
      os: 'linux',
    },
    event_type: 'network_connection',
    severity: 'critical',
    action: 'connect',
    tags: ['c2', 'network'],
    raw_data: {
      destination_ip: '203.0.113.9',
      port: 443,
    },
  },
  {
    event_id: 'evt-003',
    timestamp: '2026-09-08T10:35:00Z',
    source_type: 'network_traffic',
    source: 'zeek',
    host: {
      hostname: 'CORE-SRV',
      ip: '10.0.0.50',
      os: 'linux',
    },
    event_type: 'dns_query',
    severity: 'medium',
    action: 'resolve',
    tags: ['dns', 'tunnel'],
    raw_data: {
      query: 'cdn.evil.example.com',
    },
  },
];
