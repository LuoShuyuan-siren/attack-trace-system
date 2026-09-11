import { requestJson, requestMethod } from './client';
import type { TaskItem } from '../types/task';

export async function getTasks(): Promise<TaskItem[]> {
  const data = await requestJson<TaskItem[] | { items?: TaskItem[]; tasks?: TaskItem[] }>('/api/v1/tasks/');
  return Array.isArray(data) ? data : data.items ?? data.tasks ?? [];
}

export function getTask(taskId: string): Promise<TaskItem> {
  return requestJson<TaskItem>(`/api/v1/tasks/${encodeURIComponent(taskId)}`);
}

export function cancelTask(taskId: string): Promise<TaskItem> {
  return requestMethod<TaskItem>(`/api/v1/tasks/${encodeURIComponent(taskId)}/cancel`, 'POST');
}

export function retryTask(taskId: string): Promise<TaskItem> {
  return requestMethod<TaskItem>(`/api/v1/tasks/${encodeURIComponent(taskId)}/retry`, 'POST');
}

export function removeTask(taskId: string): Promise<TaskItem> {
  return requestMethod<TaskItem>(`/api/v1/tasks/${encodeURIComponent(taskId)}/remove`, 'POST');
}
