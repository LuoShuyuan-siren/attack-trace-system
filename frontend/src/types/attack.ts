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
  nodes: AttackNode[];
  edges: AttackEdge[];
}

export interface AttackStage {
  stage: string;
  host: string;
  technique_id: string;
}

export interface AttackChain {
  stages: AttackStage[];
}
