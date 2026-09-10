import type { Severity } from './event';

export type DetectionType = 'anomaly' | 'suspicious_behavior' | 'malicious_behavior' | 'policy_violation';

export interface DetectionItem {
  detection_id: string;
  timestamp: string;
  analyzer: string;
  detection_type: DetectionType;
  title: string;
  description?: string | null;
  severity: Severity;
  confidence: number;
  related_event_ids?: string[];
  related_entity_ids?: string[];
  evidence?: Record<string, unknown>;
  attack_technique_id?: string | null;
  tags?: string[];
}