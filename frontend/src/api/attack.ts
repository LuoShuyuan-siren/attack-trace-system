import { requestJson } from './client';
import type { AttackChain, AttackGraph } from '../types/attack';

export function getAttackGraph(): Promise<AttackGraph> {
  return requestJson<AttackGraph>('/api/v1/attack/graph').then((data) => ({
    ...data,
    nodes: data.nodes ?? [],
    edges: data.edges ?? [],
  }));
}

export function getAttackChain(): Promise<AttackChain> {
  return requestJson<AttackChain>('/api/v1/attack/chain').then((data) => ({
    ...data,
    stages: data.stages ?? [],
    paths: data.paths ?? [],
    candidate_path_count: data.candidate_path_count ?? data.paths?.length ?? 0,
    top_path_score: data.top_path_score ?? data.paths?.[0]?.score ?? null,
  }));
}
