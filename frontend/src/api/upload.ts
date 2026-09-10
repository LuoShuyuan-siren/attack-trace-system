import { API_BASE_URL } from '../config';
import type { UploadSourceType, UploadTaskResponse } from '../types/upload';

export async function uploadDataFile(file: File, sourceType: UploadSourceType): Promise<UploadTaskResponse> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('source_type', sourceType);

  const response = await fetch(`${API_BASE_URL}/api/v1/data/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('当前分析入口尚未启用');
    }

    throw new Error(`数据提交失败（${response.status}）`);
  }

  return response.json() as Promise<UploadTaskResponse>;
}