import type { TaskItem } from '../types/task';

export const mockTasks: TaskItem[] = [
  {
    task_id: 'task-001',
    name: '主机日志关联',
    status: 'success',
    progress: 100,
    created_at: '2026-09-08T09:30:00Z',
    updated_at: '2026-09-08T09:45:00Z',
  },
  {
    task_id: 'task-002',
    name: '网络异常检测',
    status: 'running',
    progress: 72,
    created_at: '2026-09-08T10:00:00Z',
    updated_at: '2026-09-08T10:12:00Z',
  },
  {
    task_id: 'task-003',
    name: '攻击链重建',
    status: 'pending',
    progress: 30,
    created_at: '2026-09-08T10:15:00Z',
    updated_at: '2026-09-08T10:15:00Z',
  },
];
