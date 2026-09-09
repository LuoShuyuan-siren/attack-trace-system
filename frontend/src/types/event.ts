export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type SourceType = 'host_log' | 'host_behavior' | 'network_traffic';

export interface HostInfo {
  hostname: string;
  ip?: string;
  os?: string;
}

export interface EventItem {
  event_id: string;
  timestamp: string;
  source_type: SourceType;
  source: string;
  host: HostInfo;
  event_type: string;
  severity: Severity;
  action?: string;
  tags?: string[];
  raw_data?: Record<string, any>;
}
