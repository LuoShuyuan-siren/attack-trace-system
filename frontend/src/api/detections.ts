import { requestJson } from './client';
import type { DetectionItem } from '../types/detection';

export async function getDetections(): Promise<DetectionItem[]> {
  const data = await requestJson<DetectionItem[] | { items?: DetectionItem[]; detections?: DetectionItem[] }>('/api/v1/detections/');
  return Array.isArray(data) ? data : data.items ?? data.detections ?? [];
}