import type { Severity } from './event';

export interface AttackNode {
  node_id: string;
  node_type: string;
  name: string;
  severity: Severity;
  attributes: Record<string, any>;
  tags: string[];
}

export interface AttackEdge {
  edge_id: string;
  source: string;
  target: string;
  relation: string;
  timestamp?: string;
  confidence?: number;
  related_event_ids?: string[];
  related_detection_ids?: string[];
  attack_technique_id?: string;
  attributes?: Record<string, any>;
}

export interface AttackGraph {
  graph_id?: string;
  nodes: AttackNode[];
  edges: AttackEdge[];
  start_time?: string | null;
  end_time?: string | null;
  description?: string | null;
}

export interface AttackStage {
  stage: string;
  source?: string;
  target?: string;
  host?: string;
  technique_id?: string | null;
  tactic_id?: string;
  tactic_name?: string;
  timestamp?: string;
  confidence?: number;
  related_event_ids?: string[];
  related_detection_ids?: string[];
}

export interface AttackChain {
  stages: AttackStage[];
  paths: AttackPath[];
  candidate_path_count?: number;
  top_path_score?: number | null;
}

export interface AttackPath {
  nodes: string[];
  edges: string[];
  relations: string[];
  start_time?: string | null;
  end_time?: string | null;
  confidence: number;
  score: number;
  score_breakdown?: Record<string, number>;
  related_event_ids: string[];
  related_detection_ids: string[];
}
