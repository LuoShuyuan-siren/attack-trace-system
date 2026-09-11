export type TaskStatus = 'pending' | 'running' | 'success' | 'failed' | 'removed';

export interface TaskItem {
  task_id: string;
  name: string;
  status: TaskStatus;
  progress: number;
  created_at: string;
  updated_at?: string;
}
