import { API_BASE_URL } from '../config';

export async function requestJson<T>(path: string): Promise<T> {
  return requestMethod<T>(path);
}

export async function requestMethod<T>(path: string, method = 'GET'): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, { method });

  if (!response.ok) {
    throw new Error(`请求失败：${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<T>;
}