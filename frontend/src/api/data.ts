import { API_BASE_URL } from '../config';

export async function getSourceTypes() {
  const res = await fetch(`${API_BASE_URL}/api/v1/data/sources`);
  return res.json();
}
