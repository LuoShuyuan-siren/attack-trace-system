import { requestMethod } from './client';

export interface AdfaLoadResult {
  task_id: string;
  status: string;
  message: string;
  event_count: number;
  detection_count: number;
  attack_mapping_count: number;
}

export function loadAdfaIntoWorkspace(): Promise<AdfaLoadResult> {
  return requestMethod<AdfaLoadResult>('/api/v1/datasets/adfa-ld', 'POST');
}