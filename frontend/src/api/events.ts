import { requestJson } from './client';
import type { EventItem } from '../types/event';

export async function getEvents(): Promise<EventItem[]> {
  const data = await requestJson<EventItem[] | { items?: EventItem[]; events?: EventItem[] }>('/api/v1/events/');
  return Array.isArray(data) ? data : data.items ?? data.events ?? [];
}
