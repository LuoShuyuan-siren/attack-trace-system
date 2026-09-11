import { requestJson } from './client';
import { API_BASE_URL } from '../config';

export interface ForensicsReport {
  event_count: number;
  detection_count: number;
  timeline: Array<Record<string, unknown>>;
  paths: Array<Record<string, unknown>>;
  apt_matches: Array<Record<string, unknown>>;
  attacker_fingerprint: Record<string, unknown>;
  c2_infrastructure: { endpoints?: Array<Record<string, unknown>> };
  process_tree: { nodes?: Array<Record<string, unknown>>; edges?: Array<Record<string, unknown>> };
  limitations: string[];
}

export interface CovertChannelSummary {
  count: number;
  suspicious_domains?: Array<Record<string, unknown>>;
}

export interface AgentAnalysis {
  agent_status: { enabled: boolean; degraded: boolean; errors?: string[] };
  agent_analysis?: {
    evidence?: Record<string, unknown>;
    chain_review?: Record<string, unknown>;
    attribution?: Record<string, unknown>;
    report?: Record<string, unknown>;
  };
}

export function getForensicsReport(): Promise<ForensicsReport> {
  return requestJson<ForensicsReport>('/api/v1/forensics/report');
}

export function getCovertChannels(): Promise<CovertChannelSummary> {
  return requestJson<CovertChannelSummary>('/api/v1/network/covert-channels');
}

export function getAgentAnalysis(): Promise<AgentAnalysis> {
  return requestJson<AgentAnalysis>('/api/v1/forensics/agent-analysis');
}

export async function downloadMarkdownReport(): Promise<Blob> {
  const response = await fetch(`${API_BASE_URL}/api/v1/forensics/report/markdown`, {
    credentials: 'include',
    headers: { Accept: 'text/markdown' },
  });
  if (!response.ok) {
    throw new Error(`报告下载失败：${response.status}`);
  }
  return response.blob();
}