export type UploadSourceType = 'host_log' | 'host_behavior' | 'network_traffic';

export interface UploadTaskResponse {
  task_id: string;
  status?: 'pending' | 'running' | 'success' | 'failed';
  progress?: number;
  message?: string;
}