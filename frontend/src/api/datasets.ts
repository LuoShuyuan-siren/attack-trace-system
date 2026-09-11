import { requestJson } from './client';

export interface AdfaLabelSummary {
  samples: number;
  detected: number;
}

export interface AdfaEvaluation {
  dataset: string;
  normal_samples: number;
  attack_samples: number;
  syscall_vocabulary_size: number;
  normal_score_max: number;
  threshold: number;
  normal_alert_count: number;
  false_positive_rate: number;
  detected_attack_samples: number;
  detection_rate: number;
  mapped_detection_count: number;
  attack_techniques: string[];
  by_attack_label: Record<string, AdfaLabelSummary>;
  detection_count: number;
  attack_graph: { nodes: number; edges: number; stages: number; paths: number };
  note: string;
}

export function getAdfaEvaluation(): Promise<AdfaEvaluation> {
  return requestJson<AdfaEvaluation>('/api/v1/datasets/adfa-ld');
}