import type { AttackChain } from '../types/attack';

export const mockAttackChain: AttackChain = {
  stages: [
    { stage: 'initial_access', host: 'WEB01', technique_id: 'T1190' },
    { stage: 'execution', host: 'WEB01', technique_id: 'T1059' },
    { stage: 'lateral_movement', host: 'PC01', technique_id: 'T1021' },
    { stage: 'privilege_escalation', host: 'PC01', technique_id: 'T1068' },
    { stage: 'command_and_control', host: 'CORE-SRV', technique_id: 'T1071' },
    { stage: 'exfiltration', host: 'CORE-SRV', technique_id: 'T1041' },
  ],
};
