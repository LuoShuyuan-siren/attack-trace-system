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
  return requestJson<AttackChain>('/api/v1/attack/chain');
}
