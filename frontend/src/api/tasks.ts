import { requestJson } from './client';
import type { TaskItem } from '../types/task';

export async function getTasks(): Promise<TaskItem[]> {
  const data = await requestJson<TaskItem[] | { items: TaskItem[] }>('/api/v1/tasks/');
  return Array.isArray(data) ? data : data.items;
}
