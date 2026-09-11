import { requestJson } from './client';

export async function getSourceTypes(): Promise<{ source_types?: string[] }> {
  const data = await requestJson<{ source_types?: string[] } | { items?: string[] }>('/api/v1/data/sources');
  if (Array.isArray((data as { source_types?: string[] }).source_types)) {
    return data as { source_types: string[] };
  }

  return { source_types: Array.isArray((data as { items?: string[] }).items) ? (data as { items: string[] }).items : [] };
}
