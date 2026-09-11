import { requestJson } from './client';

export interface LoginSession {
  session_id: string;
  hostname: string;
  user: string;
  src_ip?: string | null;
  login_at: string;
  logout_at?: string | null;
  duration_seconds: number;
  processes?: string[];
}

export interface NetworkSession {
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  protocol?: string | null;
  start_time: string;
  end_time: string;
  event_count: number;
  bytes: number;
  state?: string;
  tls_sni?: string[];
  reassembled_payloads?: Array<Record<string, unknown>>;
}

export function getLoginSessions(): Promise<{ sessions: LoginSession[] }> {
  return requestJson('/api/v1/sessions/sessions');
}

export function getNetworkSessions(): Promise<{ sessions: NetworkSession[] }> {
  return requestJson('/api/v1/network/sessions');
}