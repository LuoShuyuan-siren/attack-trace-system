import { API_BASE_URL } from '../config';

async function parseJsonSafely<T>(response: Response): Promise<T> {
  const text = await response.text();

  if (!text) {
    return {} as T;
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error('服务返回了非 JSON 响应');
  }
}

export async function requestJson<T>(path: string): Promise<T> {
  return requestMethod<T>(path);
}

export async function requestMethod<T>(
  path: string,
  method = 'GET',
  init?: RequestInit,
): Promise<T> {
  let response: Response;

  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      credentials: 'include',
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.headers ?? {}),
      },
    });
  } catch (error) {
    throw new Error(
      error instanceof Error ? `网络请求失败：${error.message}` : '网络请求失败：未知错误',
    );
  }

  if (!response.ok) {
    let detail = response.statusText || '请求失败';

    try {
      const payload = await parseJsonSafely<{ detail?: string; message?: string }>(response);
      detail = payload.detail || payload.message || detail;
    } catch {
      // ignore parse fallback failure and keep the status text
    }

    throw new Error(`请求失败：${response.status} ${detail}`);
  }

  return parseJsonSafely<T>(response);
}