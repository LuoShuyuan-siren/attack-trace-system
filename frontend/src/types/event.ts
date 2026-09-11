export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type SourceType = 'host_log' | 'host_behavior' | 'network_traffic';

export interface HostInfo {
  hostname?: string | null;
  ip?: string;
  os?: string;
}

export interface SubjectInfo {
  type?: string | null;
  name?: string | null;
  pid?: number | null;
  user?: string | null;
}

export interface ObjectInfo {
  type?: string | null;
  name?: string | null;
  path?: string | null;
  pid?: number | null;
}

export interface NetworkInfo {
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  protocol?: string | null;
}

export interface AttackInfo {
  technique_id?: string | null;
  technique_name?: string | null;
  tactic?: string | null;
}

export interface EventItem {
  event_id: string;
  timestamp: string;
  source_type: SourceType;
  source: string;
  host: HostInfo;
  event_type: string;
  subject?: SubjectInfo | null;
  object?: ObjectInfo | null;
  network?: NetworkInfo | null;
  severity: Severity;
  action?: string;
  tags?: string[];
  raw_data?: Record<string, any>;
  attack?: AttackInfo | null;
}
