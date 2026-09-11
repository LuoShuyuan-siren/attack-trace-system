import { requestMethod } from './client';
import type { UploadSourceType, UploadTaskResponse } from '../types/upload';

export async function uploadDataFile(file: File, sourceType: UploadSourceType): Promise<UploadTaskResponse> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('source_type', sourceType);

  try {
    return await requestMethod<UploadTaskResponse>('/api/v1/data/upload', 'POST', {
      body: formData,
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('404')) {
      throw new Error('当前分析入口尚未启用');
    }

    throw new Error(
      error instanceof Error ? `数据提交失败：${error.message}` : '数据提交失败，请稍后重试',
    );
  }
}