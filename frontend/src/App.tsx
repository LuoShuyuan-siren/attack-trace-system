import { useEffect, useMemo, useRef, useState } from 'react';
import { getEvents } from './api/events';
import { getDetections } from './api/detections';
import { getAttackChain, getAttackGraph } from './api/attack';
import { cancelTask, getTask, getTasks, removeTask, retryTask } from './api/tasks';
import { uploadDataFile } from './api/upload';
import { downloadMarkdownReport, getAgentAnalysis, getCovertChannels, getForensicsReport } from './api/forensics';
import { getLoginSessions, getNetworkSessions } from './api/sessions';
import { loadAdfaIntoWorkspace } from './api/adfa';
import type { EventItem } from './types/event';
import type { AttackChain, AttackGraph } from './types/attack';
import type { TaskItem } from './types/task';
import type { UploadSourceType } from './types/upload';
import type { DetectionItem } from './types/detection';

const tabs = ['仪表盘', '事件', '告警', 'ATT&CK', '攻击图谱', '攻击链', '会话', '取证', '任务'] as const;

type TabName = (typeof tabs)[number];
type AlertRecord = {
  id: string;
  title: string;
  severity: string;
  status: 'new' | 'prioritized' | 'correlated';
  host: string;
  source: string;
  evidence: string;
  technique: string;
  updated: string;
  description?: string;
  confidence?: number;
  tags?: string[];
  relatedEventIds?: string[];
  relatedEntityIds?: string[];
  evidenceDetails?: Record<string, unknown>;
};

const severityLabels: Record<string, string> = {
  info: '信息',
  low: '低危',
  medium: '中等',
  high: '高危',
  critical: '严重',
};

const eventTypeLabels: Record<string, string> = {
  process_create: '进程创建',
  network_connection: '网络连接',
  dns_query: 'DNS 查询',
};

const sourceTypeLabels: Record<string, string> = {
  host_log: '主机日志',
  host_behavior: '主机行为',
  network_traffic: '网络流量',
};

const tagLabels: Record<string, string> = {
  powershell: 'PowerShell',
  process: '进程',
  c2: 'C2',
  network: '网络',
  dns: 'DNS',
  tunnel: '隧道',
  web: 'Web',
  server: '服务器',
  workstation: '工作站',
  initial_access: '初始访问',
  exfiltration: '数据窃取',
  lateral_movement: '横向移动',
  privilege_escalation: '权限提升',
  command_and_control: '命令与控制',
};

const formatSeverity = (severity: string) => severityLabels[severity] ?? severity;
const formatEventType = (eventType: string) => eventTypeLabels[eventType] ?? eventType;
const formatSourceType = (sourceType: string) => sourceTypeLabels[sourceType] ?? sourceType;
const formatTags = (tags?: string[]) => (tags ?? []).map((tag) => tagLabels[tag] ?? tag).join(', ') || '无';
const formatStageName = (stage: string) => {
  const stageMap: Record<string, string> = {
    initial_access: '初始访问',
    execution: '执行',
    lateral_movement: '横向移动',
    privilege_escalation: '权限提升',
    command_and_control: '命令与控制',
    exfiltration: '数据窃取',
  };

  return stageMap[stage] ?? stage;
};

type GraphLayoutMode = 'tree' | 'ring' | 'free';
type GraphViewMode = 'core' | 'full';

const DEFAULT_NODE_POSITIONS: Record<string, { left: string; top: string }> = {};

const GRAPH_LAYOUT_STORAGE_KEY = 'attack-trace-graph-layout';

const relationLabels: Record<string, string> = {
  anomaly: '异常行为',
  initial_access: '初始访问',
  execute: '执行',
  connect: '网络连接',
  resolve: 'DNS 解析',
  spawn: '进程创建',
  authenticate: '认证',
  login: '登录',
  lateral_movement: '横向移动',
  privilege_escalation: '权限提升',
  c2_communication: 'C2 通信',
};

const relationColors: Record<string, string> = {
  anomaly: '#fb7185',
  initial_access: '#f97316',
  execute: '#34d399',
  connect: '#38bdf8',
  resolve: '#a78bfa',
  spawn: '#34d399',
  authenticate: '#f97316',
  login: '#22d3ee',
  lateral_movement: '#60a5fa',
  privilege_escalation: '#fbbf24',
  c2_communication: '#f87171',
};

const alertStatusLabels: Record<string, string> = {
  new: '待研判',
  prioritized: '重点关注',
  correlated: '已关联',
};

const getDetectionAlertStatus = (severity: string, confidence: number): AlertRecord['status'] => {
  if (severity === 'critical' || (severity === 'high' && confidence >= 0.8)) {
    return 'prioritized';
  }
  return 'new';
};
const getLayoutPositions = (mode: GraphLayoutMode, graph: AttackGraph): Record<string, { left: string; top: string }> => {
  const nodeIds = graph.nodes.map((node) => node.node_id);

  if (mode === 'ring') {
    if (nodeIds.length === 0) {
      return {};
    }
    return nodeIds.reduce<Record<string, { left: string; top: string }>>((result, nodeId, index) => {
      const angle = (index / nodeIds.length) * Math.PI * 2 - Math.PI / 2;
      const radius = 28;
      const x = 50 + Math.cos(angle) * radius;
      const y = 50 + Math.sin(angle) * radius;

      result[nodeId] = {
        left: `${x}%`,
        top: `${y}%`,
      };

      return result;
    }, {});
  }

  if (mode === 'tree') {
    const incoming = new Map(nodeIds.map((nodeId) => [nodeId, 0]));
    const adjacency = new Map<string, string[]>();
    graph.edges.forEach((edge) => {
      if (!incoming.has(edge.source) || !incoming.has(edge.target)) {
        return;
      }
      adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge.target]);
      incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1);
    });

    const depth = new Map<string, number>();
    const queue = nodeIds.filter((nodeId) => incoming.get(nodeId) === 0);
    const visited = new Set<string>();
    queue.forEach((nodeId) => depth.set(nodeId, 0));
    for (let index = 0; index < queue.length; index += 1) {
      const nodeId = queue[index];
      if (visited.has(nodeId)) {
        continue;
      }
      visited.add(nodeId);
      (adjacency.get(nodeId) ?? []).forEach((target) => {
        if (!visited.has(target)) {
          const nextDepth = Math.max(depth.get(target) ?? 0, (depth.get(nodeId) ?? 0) + 1);
          depth.set(target, nextDepth);
          queue.push(target);
        }
      });
    }
    nodeIds.forEach((nodeId) => {
      if (!depth.has(nodeId)) {
        depth.set(nodeId, 0);
      }
    });

    const levels = new Map<number, string[]>();
    nodeIds.forEach((nodeId) => {
      const level = depth.get(nodeId) ?? 0;
      levels.set(level, [...(levels.get(level) ?? []), nodeId]);
    });
    const maxLevel = Math.max(...levels.keys(), 0);
    return nodeIds.reduce<Record<string, { left: string; top: string }>>((result, nodeId) => {
      const level = depth.get(nodeId) ?? 0;
      const levelNodes = levels.get(level) ?? [nodeId];
      const column = levelNodes.indexOf(nodeId);
      result[nodeId] = {
        left: `${levelNodes.length === 1 ? 50 : 8 + (column / (levelNodes.length - 1)) * 84}%`,
        top: `${maxLevel === 0 ? 50 : 8 + (level / maxLevel) * 84}%`,
      };
      return result;
    }, {});
  }

  return DEFAULT_NODE_POSITIONS;
};

function App() {
  const [activeTab, setActiveTab] = useState<TabName>('仪表盘');
  const [events, setEvents] = useState<EventItem[]>([]);
  const [attackGraph, setAttackGraph] = useState<AttackGraph>({ nodes: [], edges: [] });
  const [attackChain, setAttackChain] = useState<AttackChain>({ stages: [], paths: [] });
  const [tasks, setTasks] = useState<TaskItem[]>([]);
  const [detections, setDetections] = useState<DetectionItem[]>([]);
  const [forensicsReport, setForensicsReport] = useState<Awaited<ReturnType<typeof getForensicsReport>> | null>(null);
  const [covertChannels, setCovertChannels] = useState<Awaited<ReturnType<typeof getCovertChannels>> | null>(null);
  const [agentAnalysis, setAgentAnalysis] = useState<Awaited<ReturnType<typeof getAgentAnalysis>> | null>(null);
  const [loginSessions, setLoginSessions] = useState<Awaited<ReturnType<typeof getLoginSessions>>['sessions']>([]);
  const [networkSessions, setNetworkSessions] = useState<Awaited<ReturnType<typeof getNetworkSessions>>['sessions']>([]);
  const [adfaLoadMessage, setAdfaLoadMessage] = useState('');
  const [detectionStatus, setDetectionStatus] = useState<'loading' | 'ready' | 'unavailable'>('loading');
  const [dataMode, setDataMode] = useState<'loading' | 'live' | 'unavailable'>('loading');
  const [dataError, setDataError] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadSourceType, setUploadSourceType] = useState<UploadSourceType>('host_log');
  const [uploadState, setUploadState] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [uploadMessage, setUploadMessage] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [hostFilter, setHostFilter] = useState('all');
  const [sourceTypeFilter, setSourceTypeFilter] = useState('all');
  const [eventTypeFilter, setEventTypeFilter] = useState('all');
  const [eventSearch, setEventSearch] = useState('');
  const [alertStatusFilter, setAlertStatusFilter] = useState('all');
  const [alertSeverityFilter, setAlertSeverityFilter] = useState('all');
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [graphZoom, setGraphZoom] = useState(1);
  const [selectedTask, setSelectedTask] = useState<TaskItem | null>(null);
  const [taskActionMessage, setTaskActionMessage] = useState('');
  const [selectedEventId, setSelectedEventId] = useState('');
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState('');
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [graphLayoutMode, setGraphLayoutMode] = useState<GraphLayoutMode>('tree');
  const [graphViewMode, setGraphViewMode] = useState<GraphViewMode>('core');
  const [graphSearch, setGraphSearch] = useState('');
  const [graphNodeTypeFilter, setGraphNodeTypeFilter] = useState('all');
  const [graphSeverityFilter, setGraphSeverityFilter] = useState('all');
  const [selectedStageIndex, setSelectedStageIndex] = useState<number | null>(null);
  const workflowRef = useRef<HTMLDivElement>(null);
  const eventFiltersRef = useRef<HTMLDivElement>(null);
  const eventTableRef = useRef<HTMLDivElement>(null);
  const labTopologyRef = useRef<HTMLDivElement>(null);
  const attackChainRef = useRef<HTMLDivElement>(null);
  const recentEventsRef = useRef<HTMLDivElement>(null);
  const [nodePositions, setNodePositions] = useState<Record<string, { left: string; top: string }>>(() => {
    const savedPositions = localStorage.getItem(GRAPH_LAYOUT_STORAGE_KEY);

    if (!savedPositions) {
      return {};
    }

    try {
      return { ...JSON.parse(savedPositions) };
    } catch {
      return {};
    }
  });

  const displayGraph = useMemo<AttackGraph>(() => {
    const topPath = attackChain.paths?.[0];
    const coreNodeIds = new Set(topPath?.nodes ?? []);
    const coreEdgeIds = new Set(topPath?.edges ?? []);
    const scopedNodes = graphViewMode === 'core' && topPath
      ? attackGraph.nodes.filter((node) => coreNodeIds.has(node.node_id))
      : attackGraph.nodes;
    const scopedNodeIds = new Set(scopedNodes.map((node) => node.node_id));
    const scopedEdges = attackGraph.edges.filter((edge) => (
      graphViewMode === 'core' && topPath
        ? coreEdgeIds.has(edge.edge_id)
        : scopedNodeIds.has(edge.source) && scopedNodeIds.has(edge.target)
    ));
    const filteredNodes = scopedNodes
      .filter((node) => graphNodeTypeFilter === 'all' || node.node_type === graphNodeTypeFilter)
      .filter((node) => graphSeverityFilter === 'all' || node.severity === graphSeverityFilter)
      .filter((node) => !graphSearch.trim() || `${node.name} ${node.node_id} ${node.tags.join(' ')}`.toLowerCase().includes(graphSearch.trim().toLowerCase()));
    const filteredNodeIds = new Set(filteredNodes.map((node) => node.node_id));

    return {
      ...attackGraph,
      nodes: filteredNodes,
      edges: scopedEdges.filter((edge) => filteredNodeIds.has(edge.source) && filteredNodeIds.has(edge.target)),
    };
  }, [attackChain.paths, attackGraph, graphNodeTypeFilter, graphSearch, graphSeverityFilter, graphViewMode]);

  const loadData = (isActive: () => boolean = () => true) => {
    setIsRefreshing(true);
    setDataMode('loading');
    setDataError('');

    const detectionRequest = getDetections()
      .then((items) => {
        setDetections(items);
        setDetectionStatus('ready');
      })
      .catch(() => {
        setDetectionStatus('unavailable');
      });

    const forensicsRequest = Promise.all([
      getForensicsReport(),
      getCovertChannels(),
      getAgentAnalysis(),
      getLoginSessions(),
      getNetworkSessions(),
    ])
      .then(([report, covert, agents, login, network]) => {
        setForensicsReport(report);
        setCovertChannels(covert);
        setAgentAnalysis(agents);
        setLoginSessions(login.sessions ?? []);
        setNetworkSessions(network.sessions ?? []);
      });

    return Promise.allSettled([getEvents(), getAttackGraph(), getAttackChain(), getTasks(), detectionRequest, forensicsRequest]).then((results) => {
      if (!isActive()) {
        return;
      }

      const [eventsResult, graphResult, chainResult, tasksResult] = results;
      if (eventsResult.status === 'fulfilled') {
        setEvents(eventsResult.value);
      }
      if (graphResult.status === 'fulfilled') {
        setAttackGraph(graphResult.value);
        if (graphResult.value.nodes.length > 0) {
          setSelectedGraphNodeId(graphResult.value.nodes[0].node_id);
          setNodePositions(getLayoutPositions('tree', graphResult.value));
        }
      }
      if (chainResult.status === 'fulfilled') {
        setAttackChain(chainResult.value);
      }
      if (tasksResult.status === 'fulfilled') {
        setTasks(tasksResult.value);
      }

      const rejectedCount = results.slice(0, 4).filter((result) => result.status === 'rejected').length;
      setDataMode(rejectedCount === 0 ? 'live' : 'unavailable');
      setDataError(rejectedCount > 0 ? `${rejectedCount} 项数据加载失败，当前仅展示已获得的数据。` : '');
      setIsRefreshing(false);
    });
  };

  useEffect(() => {
    let active = true;
    loadData(() => active);

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (graphLayoutMode !== 'free') {
      setNodePositions(getLayoutPositions(graphLayoutMode, displayGraph));
    }
  }, [displayGraph, graphLayoutMode]);

  useEffect(() => {
    localStorage.setItem(GRAPH_LAYOUT_STORAGE_KEY, JSON.stringify(nodePositions));
  }, [nodePositions]);

  const handleNodePointerDown = (event: React.PointerEvent<HTMLButtonElement>, nodeId: string) => {
    if (graphLayoutMode !== 'free') {
      setSelectedGraphNodeId(nodeId);
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    setSelectedGraphNodeId(nodeId);
    setDraggingNodeId(nodeId);
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const handleNodePointerMove = (event: React.PointerEvent<HTMLButtonElement>, nodeId: string) => {
    if (draggingNodeId !== nodeId || !event.currentTarget.parentElement) {
      return;
    }

    const container = event.currentTarget.parentElement;
    const rect = container.getBoundingClientRect();

    const rawLeft = ((event.clientX - rect.left) / rect.width) * 100;
    const rawTop = ((event.clientY - rect.top) / rect.height) * 100;

    const nextLeft = Math.min(Math.max(rawLeft, 8), 92);
    const nextTop = Math.min(Math.max(rawTop, 12), 88);

    setNodePositions((prev) => ({
      ...prev,
      [nodeId]: {
        left: `${nextLeft}%`,
        top: `${nextTop}%`,
      },
    }));
  };

  const handleNodePointerUp = (event: React.PointerEvent<HTMLButtonElement>, nodeId: string) => {
    if (draggingNodeId === nodeId) {
      setDraggingNodeId(null);
      if (event.currentTarget.hasPointerCapture(event.pointerId)) {
        event.currentTarget.releasePointerCapture(event.pointerId);
      }
    }
  };

  const resetGraphLayout = () => {
    setNodePositions(getLayoutPositions(graphLayoutMode === 'free' ? 'tree' : graphLayoutMode, displayGraph));
  };

  const scrollWorkflow = (direction: 'left' | 'right') => {
    workflowRef.current?.scrollBy({
      left: direction === 'left' ? -280 : 280,
      behavior: 'smooth',
    });
  };

  const scrollEventFilters = (direction: 'left' | 'right') => {
    eventFiltersRef.current?.scrollBy({
      left: direction === 'left' ? -260 : 260,
      behavior: 'smooth',
    });
  };

  const scrollEventTable = (direction: 'left' | 'right') => {
    eventTableRef.current?.scrollBy({
      left: direction === 'left' ? -320 : 320,
      behavior: 'smooth',
    });
  };

  const scrollDashboardList = (direction: 'up' | 'down', ref: React.RefObject<HTMLDivElement | null>) => {
    ref.current?.scrollBy({
      top: direction === 'up' ? -180 : 180,
      behavior: 'smooth',
    });
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setUploadState('error');
      setUploadMessage('请先选择数据文件');
      return;
    }

    const acceptedExtensions = [
      '.txt',
      '.log',
      '.json',
      '.evtx',
      '.pcap',
      '.pcapng',
      '.cap',
    ];
    const fileExtension = selectedFile.name.slice(selectedFile.name.lastIndexOf('.')).toLowerCase();
    const maxFileSize = 500 * 1024 * 1024;

    if (!acceptedExtensions.includes(fileExtension)) {
      setUploadState('error');
      setUploadMessage('暂不支持该文件格式，请选择 TXT、LOG、JSON、EVTX、PCAP、PCAPNG 或 CAP 文件');
      return;
    }

    if (selectedFile.size > maxFileSize) {
      setUploadState('error');
      setUploadMessage('文件大小不能超过 500 MB');
      return;
    }

    setUploadState('uploading');
    setUploadMessage('正在提交数据分析任务...');

    try {
      const result = await uploadDataFile(selectedFile, uploadSourceType);
      setUploadState('success');
      setUploadMessage(result.task_id ? `分析任务已创建：${result.task_id}` : '分析任务已创建');
      setSelectedFile(null);
      if (result.task_id) {
        await waitForTask(result.task_id);
      }
      await loadData();
    } catch (error) {
      setUploadState('error');
      setUploadMessage(error instanceof Error ? error.message : '数据提交失败，请稍后重试');
    }
  };

  const handleLoadAdfa = async () => {
    setAdfaLoadMessage('正在将 ADFA-LD 加载到统一分析工作区...');
    try {
      const result = await loadAdfaIntoWorkspace();
      setAdfaLoadMessage(`${result.message}：${result.event_count} 条事件，${result.detection_count} 条告警，${result.attack_mapping_count} 条 ATT&CK 映射`);
      await loadData();
    } catch (error) {
      setAdfaLoadMessage(error instanceof Error ? error.message : 'ADFA-LD 加载失败');
    }
  };

  const runTaskAction = async (task: TaskItem, action: 'cancel' | 'retry') => {
    setTaskActionMessage(`${action === 'cancel' ? '正在取消' : '正在重试'}任务...`);

    try {
      const updatedTask = action === 'cancel' ? await cancelTask(task.task_id) : await retryTask(task.task_id);
      setTasks((current) => current.map((item) => item.task_id === updatedTask.task_id ? updatedTask : item));
      setSelectedTask(updatedTask);
      setTaskActionMessage(action === 'cancel' ? '任务已取消' : '任务已重新提交');
    } catch (error) {
      setTaskActionMessage(error instanceof Error && error.message.includes('404') ? '当前任务操作尚未启用' : '任务操作失败，请稍后重试');
    }
  };

  const handleRemoveTask = async (task: TaskItem) => {
    setTaskActionMessage('正在撤销任务并移除工作区数据...');
    try {
      await removeTask(task.task_id);
      setTasks((current) => current.filter((item) => item.task_id !== task.task_id));
      setSelectedTask(null);
      setTaskActionMessage('任务及其产生的数据已从工作区移除');
      await loadData();
    } catch (error) {
      setTaskActionMessage(error instanceof Error ? error.message : '撤销任务失败，请稍后重试');
    }
  };

  const waitForTask = async (taskId: string) => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 1000));
      const task = await getTask(taskId);

      if (task.status === 'success') {
        setUploadMessage('分析完成，数据已更新');
        return;
      }

      if (task.status === 'failed') {
        throw new Error('分析任务执行失败');
      }

      setUploadMessage(`分析进行中：${task.progress}%`);
    }

    throw new Error('分析任务仍在执行，请稍后刷新查看结果');
  };

  const exportReport = async () => {
    try {
      const blob = await downloadMarkdownReport();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `attack-trace-report-${new Date().toISOString().replace(/[:.]/g, '-')}.md`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setDataError(error instanceof Error ? error.message : '报告下载失败');
    }
  };

  const stats = useMemo(() => {
    const completedTasks = tasks.filter((task) => task.status === 'success').length;
    const completionRate = tasks.length > 0 ? Math.round((completedTasks / tasks.length) * 100) : 0;

    return [
      { label: '事件总量', value: events.length.toLocaleString(), detail: '当前数据范围' },
      { label: '高危事件', value: events.filter((event) => event.severity === 'high' || event.severity === 'critical').length.toString(), detail: '按风险等级统计' },
      { label: '攻击链阶段', value: attackChain.stages.length.toString(), detail: '当前关联结果' },
      { label: '任务完成率', value: `${completionRate}%`, detail: `${tasks.length} 个分析任务` },
    ];
  }, [attackChain.stages.length, events, tasks]);

  const hostOptions = useMemo(
    () => [...new Set(events.map((event) => event.host.hostname).filter((hostname): hostname is string => Boolean(hostname)))]
      .sort((left, right) => left.localeCompare(right)),
    [events],
  );

  const sourceTypeOptions = useMemo(
    () => [...new Set(events.map((event) => event.source_type))].sort(),
    [events],
  );

  const eventTypeOptions = useMemo(
    () => [...new Set(events.map((event) => event.event_type))].sort(),
    [events],
  );

  const graphConfidence = attackGraph.edges.reduce(
    (highest, edge) => Math.max(highest, edge.confidence ?? 0),
    0,
  );
  const affectedHostCount = new Set(
    attackGraph.nodes.filter((node) => node.node_type === 'host').map((node) => node.node_id),
  ).size;
  const latestEvent = [...events].sort((left, right) => right.timestamp.localeCompare(left.timestamp))[0];
  const sourceSummary = [...new Set(events.map((event) => event.source))].join('、') || '暂无';

  const graphNodeTypes = [...new Set(attackGraph.nodes.map((node) => node.node_type))].sort();
  const exportGraph = () => {
    const graphExport = JSON.stringify({ graph: attackGraph, exported_at: new Date().toISOString() }, null, 2);
    const blob = new Blob([graphExport], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `attack-graph-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const traceDimensions = useMemo(
    () => [
      { title: '主机日志', detail: '时间对齐 / 统一范式 / 登录重建 / 关键实体提取' },
      { title: '主机行为', detail: '系统调用 / 进程树 / 文件操作 / 内存行为分析' },
      { title: '网络流量', detail: '会话重建 / 协议建模 / 隐蔽信道 / DNS/HTTP/ICMP 分析' },
      { title: '攻击链', detail: 'ATT&CK 映射 / 技术关联 / 攻击路径识别 / 权限提升链路' },
      { title: '身份溯源', detail: 'C2 基础设施 / 攻击者指纹 / TTP 组织特征匹配' },
    ],
    [],
  );

  const labNodes = useMemo(
    () => attackGraph.nodes.map((node) => ({ name: node.name, role: node.node_type })),
    [attackGraph.nodes],
  );

  const analysisWorkflow = useMemo(
    () => [
      { title: '数据采集', description: '整合主机日志、系统行为、网络流量与身份访问记录，形成统一事件时序。' },
      { title: '关联分析', description: '基于实体关联和 ATT&CK 技术映射，重建横向移动、提权和 C2 链路。' },
      { title: '响应决策', description: '依据风险评分和证据链，输出隔离建议、处置动作和后续取证优先级。' },
    ],
    [],
  );

  const experimentResults = useMemo(
    () => {
      const averageProgress = tasks.length > 0
        ? Math.round(tasks.reduce((total, task) => total + task.progress, 0) / tasks.length)
        : 0;

      return [
        { label: '事件数', value: events.length.toString() },
        { label: '图谱关系数', value: attackGraph.edges.length.toString() },
        { label: '任务平均进度', value: `${averageProgress}%` },
      ];
    },
    [attackGraph.edges.length, events.length, tasks],
  );

  const technologyHighlights = useMemo(
    () => [
      '采用统一事件时序与多源证据融合方案，提升威胁链路还原能力。',
      '结合 ATT&CK 技术映射与权限提升、横向移动、C2 通信关联逻辑。',
      '支持视图化展示、风险优先级排序与处置建议输出，便于运营快速决策。',
    ],
    [],
  );

  const finalRecommendations = useMemo(
    () => [
      '持续加强内网横向移动与凭据滥用检测能力，重点覆盖 Web 与核心服务器。',
      '将实时事件关联与告警闭环机制扩展到更大规模网络环境，提升自动化响应效率。',
      '以结果导向方式开展后续实验验证，持续提高链路重建准确率和处置命中率。',
    ],
    [],
  );

  const filteredEvents = events.filter((event) => {
    const severityMatch = severityFilter === 'all' || event.severity === severityFilter;
    const hostMatch = hostFilter === 'all' || event.host.hostname === hostFilter;
    const sourceTypeMatch = sourceTypeFilter === 'all' || event.source_type === sourceTypeFilter;
    const eventTypeMatch = eventTypeFilter === 'all' || event.event_type === eventTypeFilter;
    const searchValue = eventSearch.trim().toLowerCase();
    const searchMatch = !searchValue || [
      event.event_id,
      event.host.hostname,
      event.host.ip,
      event.source,
      event.event_type,
      event.action,
      ...(event.tags ?? []),
    ].some((value) => value?.toLowerCase().includes(searchValue));

    return severityMatch && hostMatch && sourceTypeMatch && eventTypeMatch && searchMatch;
  });

  const timelineEvents = [...filteredEvents].sort((left, right) => left.timestamp.localeCompare(right.timestamp));

  const graphAlertRecords = useMemo<AlertRecord[]>(() => attackGraph.edges.map((edge) => {
    const sourceNode = attackGraph.nodes.find((node) => node.node_id === edge.source);
    const targetNode = attackGraph.nodes.find((node) => node.node_id === edge.target);
    const relatedEvent = events.find((event) => edge.related_event_ids?.includes(event.event_id));
    const host = targetNode?.name ?? sourceNode?.name ?? '未知实体';

    return {
      id: edge.edge_id,
      title: relationLabels[edge.relation] ?? edge.relation,
      severity: relatedEvent?.severity ?? targetNode?.severity ?? 'medium',
      status: 'correlated',
      host,
      source: relatedEvent?.source ?? '攻击图谱',
      evidence: relatedEvent?.event_type ?? edge.related_event_ids?.join(', ') ?? '攻击边',
      technique: edge.attack_technique_id ?? '未映射',
      updated: edge.timestamp ?? '未提供',
    };
  }), [attackGraph, events]);

  const alertRecords = useMemo<AlertRecord[]>(() => {
    if (detections.length === 0) {
      return graphAlertRecords;
    }

    return detections.map((detection) => {
      const relatedEvent = events.find((event) => detection.related_event_ids?.includes(event.event_id));
      return {
        id: detection.detection_id,
        title: detection.title,
        severity: detection.severity,
        status: getDetectionAlertStatus(detection.severity, detection.confidence),
        host: relatedEvent?.host.hostname ?? detection.related_entity_ids?.[0] ?? '关联实体',
        source: relatedEvent?.source ?? detection.analyzer,
        evidence: detection.description ?? detection.tags?.join(', ') ?? '检测结果',
        technique: detection.attack_technique_id ?? '未映射',
        updated: detection.timestamp,
        description: detection.description ?? undefined,
        confidence: detection.confidence,
        tags: detection.tags,
          relatedEventIds: detection.related_event_ids,
          relatedEntityIds: detection.related_entity_ids,
          evidenceDetails: detection.evidence,
      };
    });
  }, [detections, events, graphAlertRecords]);

  const attackTechniqueRows = useMemo(() => {
    const tacticByTechnique = new Map<string, string[]>();
    attackChain.stages.forEach((stage) => {
      if (!stage.technique_id) {
        return;
      }
      const tactic = stage.tactic_name ?? formatStageName(stage.stage);
      const tactics = tacticByTechnique.get(stage.technique_id) ?? [];
      if (!tactics.includes(tactic)) {
        tactics.push(tactic);
      }
      tacticByTechnique.set(stage.technique_id, tactics);
    });
    const rows = new Map<string, {
      id: string;
      name: string;
      tactic: string;
      hosts: string;
      confidence: number | null;
      evidence: string;
    }>();

    attackGraph.edges.forEach((edge) => {
      if (!edge.attack_technique_id) {
        return;
      }

      const source = attackGraph.nodes.find((node) => node.node_id === edge.source)?.name ?? edge.source;
      const target = attackGraph.nodes.find((node) => node.node_id === edge.target)?.name ?? edge.target;
      rows.set(edge.attack_technique_id, {
        id: edge.attack_technique_id,
        name: relationLabels[edge.relation] ?? edge.relation,
        tactic: tacticByTechnique.get(edge.attack_technique_id)?.join('、')
          ?? relationLabels[edge.relation]
          ?? edge.relation,
        hosts: `${source} → ${target}`,
        confidence: edge.confidence ?? null,
        evidence: edge.related_event_ids?.join(', ') ?? '攻击图谱',
      });
    });

    detections.forEach((detection) => {
      if (!detection.attack_technique_id) {
        return;
      }

      const relatedEvent = events.find((event) => detection.related_event_ids?.includes(event.event_id));
      rows.set(detection.attack_technique_id, {
        id: detection.attack_technique_id,
        name: detection.title,
        tactic: tacticByTechnique.get(detection.attack_technique_id)?.join('、') ?? '未映射',
        hosts: relatedEvent?.host.hostname ?? detection.related_entity_ids?.join(', ') ?? '关联实体',
        confidence: detection.confidence,
        evidence: detection.description ?? detection.tags?.join(', ') ?? detection.analyzer,
      });
    });

    attackChain.stages.forEach((stage) => {
      if (!stage.technique_id) {
        return;
      }
      if (!rows.has(stage.technique_id)) {
        rows.set(stage.technique_id, {
          id: stage.technique_id,
          name: stage.stage,
          tactic: formatStageName(stage.stage),
          hosts: stage.host ?? '未知',
          confidence: null,
          evidence: '攻击链结果',
        });
      }
    });

    return [...rows.values()];
  }, [attackChain.stages, attackGraph, detections, events]);

  const filteredAlerts = alertRecords.filter(
    (alert) => (alertStatusFilter === 'all' || alert.status === alertStatusFilter)
      && (alertSeverityFilter === 'all' || alert.severity === alertSeverityFilter),
  );

  const selectedEvent =
    filteredEvents.find((event) => event.event_id === selectedEventId) ?? filteredEvents[0];

  const selectedGraphNode =
    displayGraph.nodes.find((node) => node.node_id === selectedGraphNodeId) ?? displayGraph.nodes[0];

  const relatedGraphEdges = displayGraph.edges.filter(
    (edge) => selectedGraphNode && (edge.source === selectedGraphNode.node_id || edge.target === selectedGraphNode.node_id),
  );

  const relatedGraphNodeIds = new Set(
    relatedGraphEdges.flatMap((edge) => [edge.source, edge.target]).filter((id) => id !== selectedGraphNode?.node_id),
  );

  const graphRelationContext = relatedGraphEdges.map((edge) => {
    const neighborId = edge.source === selectedGraphNode?.node_id ? edge.target : edge.source;
    const neighbor = displayGraph.nodes.find((node) => node.node_id === neighborId);

    return {
      ...edge,
      neighborName: neighbor?.name ?? neighborId,
      relationLabel: relationLabels[edge.relation] ?? edge.relation,
      color: relationColors[edge.relation] ?? '#94a3b8',
    };
  });

  const visibleGraphEdges = displayGraph.edges;

  const graphEdgePaths = visibleGraphEdges.map((edge) => {
    const sourcePosition = nodePositions[edge.source] ?? DEFAULT_NODE_POSITIONS[edge.source] ?? { left: '50%', top: '50%' };
    const targetPosition = nodePositions[edge.target] ?? DEFAULT_NODE_POSITIONS[edge.target] ?? { left: '50%', top: '50%' };
    const x1 = Number.parseFloat(sourcePosition.left);
    const y1 = Number.parseFloat(sourcePosition.top);
    const x2 = Number.parseFloat(targetPosition.left);
    const y2 = Number.parseFloat(targetPosition.top);
    const ctrlX = (x1 + x2) / 2;
    const ctrlY = Math.min(y1, y2) - 12;
    const d = `M ${x1} ${y1} Q ${ctrlX} ${ctrlY} ${x2} ${y2}`;
    const isActive = selectedGraphNode !== undefined && (edge.source === selectedGraphNode.node_id || edge.target === selectedGraphNode.node_id);
    const labelX = (x1 + x2) / 2;
    const labelY = (y1 + y2) / 2 - 6;

    return {
      ...edge,
      d,
      active: isActive,
      color: relationColors[edge.relation] ?? '#94a3b8',
      label: relationLabels[edge.relation] ?? edge.relation,
      labelX,
      labelY,
    };
  });

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">攻击溯源</div>
        <nav className="nav">
          {tabs.map((tab) => (
            <button
              key={tab}
              type="button"
              className={`nav-item ${activeTab === tab ? 'active' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab}
            </button>
          ))}
        </nav>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <div className="eyebrow">安全运营</div>
            <h1>威胁分析监控台</h1>
            <div className="topbar-meta">
              <span className={`status-pill ${dataMode === 'unavailable' ? 'demo' : ''}`}>
                {dataMode === 'loading' ? '正在加载数据' : dataMode === 'live' ? '实时数据' : '数据暂不可用'}
              </span>
              <span className="status-note">{dataError || '数据已同步'}</span>
            </div>
          </div>
          <div className="header-actions">
            <div className="chip-row">
              <span className="chip active">威胁狩猎</span>
              <span className="chip">安全分析员</span>
            </div>
            <button type="button" className="primary-btn" onClick={() => loadData()} disabled={isRefreshing}>
              {isRefreshing ? '刷新中...' : '刷新数据'}
            </button>
            <button type="button" className="primary-btn" onClick={exportReport}>导出报告</button>
          </div>
        </header>

        {activeTab === '仪表盘' && (
          <>
            <section className="overview-banner">
              <div className="overview-copy">
                <span className="tag">重点事件</span>
                <h2>{attackChain.stages.length > 0 ? '已形成攻击链关联结果' : '暂未形成攻击链'}</h2>
                <p>
                  当前加载 {events.length} 条事件、{attackGraph.edges.length} 条图谱关系，数据来源：{sourceSummary}。
                </p>
              </div>
              <div className="overview-metrics">
                <div className="mini-metric">
                  <span>最高关联置信度</span>
                  <strong>{Math.round(graphConfidence * 100)}%</strong>
                </div>
                <div className="mini-metric">
                  <span>任务平均进度</span>
                  <strong>{tasks.length > 0 ? `${Math.round(tasks.reduce((total, task) => total + task.progress, 0) / tasks.length)}%` : '暂无'}</strong>
                </div>
                <div className="mini-metric">
                  <span>图谱主机数</span>
                  <strong>{affectedHostCount} 台</strong>
                </div>
              </div>
            </section>

            <section className="stats-grid">
              {stats.map((item) => (
                <div className="stat-card" key={item.label}>
                  <div className="stat-label">{item.label}</div>
                  <div className="stat-value">{item.value}</div>
                  <div className="stat-detail">{item.detail}</div>
                </div>
              ))}
            </section>

            <section className="insight-grid">
              <div className="panel insight-panel">
                <div className="panel-header">
                  <h2>风险分布</h2>
                </div>
                <div className="bar-stack">
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => {
                    const count = events.filter((event) => event.severity === severity).length;
                    const percentage = events.length > 0 ? Math.round((count / events.length) * 100) : 0;

                    return (
                      <div className="bar-row" key={severity}>
                        <span>{formatSeverity(severity)}</span>
                        <div className="bar-track"><i style={{ width: `${percentage}%` }} /></div>
                        <strong>{percentage}%</strong>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="panel insight-panel">
                <div className="panel-header">
                  <h2>处置状态</h2>
                </div>
                <ul className="status-list">
                  <li>
                    <span className="bullet good" />
                    {tasks.filter((task) => task.status === 'success').length} 个分析任务已完成
                  </li>
                  <li>
                    <span className="bullet warn" />
                    {tasks.filter((task) => task.status === 'running').length} 个分析任务运行中
                  </li>
                  <li>
                    <span className="bullet neutral" />
                    {tasks.filter((task) => task.status === 'pending').length} 个分析任务待处理
                  </li>
                </ul>
              </div>

              <div className="panel insight-panel">
                <div className="panel-header">
                  <h2>调查说明</h2>
                </div>
                <div className="note-box">
                  {latestEvent ? `最近事件：${latestEvent.event_id}，类型为${formatEventType(latestEvent.event_type)}，来源为${latestEvent.source}。` : '暂未获取到事件数据。'}
                </div>
              </div>
            </section>

            <section className="summary-strip">
              <div className="summary-card accent">
                <span className="summary-kicker">建议动作</span>
                <strong>审查高风险事件</strong>
                <small>当前高危及严重事件共 {events.filter((event) => event.severity === 'high' || event.severity === 'critical').length} 条。</small>
              </div>
              <div className="summary-card">
                <span className="summary-kicker">关键证据</span>
                <strong>{sourceSummary}</strong>
                <small>当前数据中的采集器集合。</small>
              </div>
              <div className="summary-card">
                <span className="summary-kicker">分析说明</span>
                <strong>{attackGraph.nodes.length} 个图谱节点</strong>
                <small>当前分析范围内的攻击关系。</small>
              </div>
            </section>

            <section className="coverage-shell">
              <div className="panel coverage-panel">
                <div className="panel-header">
                  <h2>分析能力覆盖</h2>
                  <p className="panel-subtitle">面向主机日志、主机行为和网络流量的统一溯源能力。</p>
                </div>
                <div className="coverage-grid">
                  {traceDimensions.map((item) => (
                    <div key={item.title} className="coverage-card">
                      <div className="coverage-title">{item.title}</div>
                      <p>{item.detail}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel lab-panel">
                <div className="panel-header row-header">
                  <div>
                    <h2>靶场拓扑</h2>
                    <p className="panel-subtitle">当前分析范围包含 {labNodes.length} 个关系节点。</p>
                  </div>
                  <div className="vertical-scroll-controls" aria-label="靶场拓扑上下滚动控制">
                    <button type="button" onClick={() => scrollDashboardList('up', labTopologyRef)} aria-label="向上查看靶场拓扑">↑</button>
                    <button type="button" onClick={() => scrollDashboardList('down', labTopologyRef)} aria-label="向下查看靶场拓扑">↓</button>
                  </div>
                </div>
                <div className="scrollable-vertical-list" ref={labTopologyRef}>
                  <div className="lab-node-list">
                    {labNodes.length > 0 ? labNodes.map((node, index) => (
                      <div key={node.name} className="lab-node-item">
                        <span className="lab-node-index">{index + 1}</span>
                        <span className="lab-node-copy">
                          <strong>{node.name}</strong>
                          <small>{node.role}</small>
                        </span>
                      </div>
                    )) : <div className="empty-state">暂无关系节点数据。</div>}
                  </div>
                </div>
              </div>
            </section>

            <section className="workflow-shell">
              <div className="panel workflow-panel">
                <div className="panel-header row-header">
                  <div>
                    <h2>检测流程</h2>
                    <p className="panel-subtitle">展示从数据采集到关联研判的完整处理流程。</p>
                  </div>
                  <div className="workflow-scroll-controls" aria-label="检测流程横向滚动控制">
                    <button type="button" onClick={() => scrollWorkflow('left')} aria-label="向左查看检测流程">←</button>
                    <button type="button" onClick={() => scrollWorkflow('right')} aria-label="向右查看检测流程">→</button>
                  </div>
                </div>
                <div className="workflow-grid" ref={workflowRef}>
                  {analysisWorkflow.map((item) => (
                    <div key={item.title} className="workflow-card">
                      <div className="workflow-step">{item.title}</div>
                      <p>{item.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel result-panel">
                <div className="panel-header">
                  <h2>分析统计指标</h2>
                  <p className="panel-subtitle">指标根据当前分析范围动态计算。</p>
                </div>
                <div className="result-list">
                  {experimentResults.map((item) => (
                    <div key={item.label} className="result-item">
                      <span>{item.label}</span>
                      <strong>{item.value}</strong>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="conclusion-shell">
              <div className="panel highlight-panel">
                <div className="panel-header">
                  <h2>技术亮点</h2>
                </div>
                <ul className="bullet-list">
                  {technologyHighlights.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>

              <div className="panel recommendation-panel">
                <div className="panel-header">
                  <h2>结论与建议</h2>
                </div>
                <ul className="bullet-list">
                  {finalRecommendations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </section>

            <section className="content-grid">
              <div className="panel">
                <div className="panel-header">
                  <h2>攻击图谱</h2>
                </div>
                <div className="graph-box">
                  <svg className="graph-svg" viewBox="0 0 100 100" preserveAspectRatio="none">
                    <defs>
                      {Object.entries(relationColors).map(([relation, color]) => (
                        <marker key={relation} id={`dashboard-arrow-${relation}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
                          <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
                        </marker>
                      ))}
                    </defs>
                    {graphEdgePaths.map((edge) => (
                      <g key={`${edge.source}-${edge.target}`}>
                        <path
                          d={edge.d}
                          className={`graph-connection-line ${edge.active ? 'active' : ''}`}
                          markerEnd={`url(#dashboard-arrow-${edge.relation})`}
                          style={{ stroke: edge.color, opacity: edge.active ? 1 : 0.72 }}
                        />
                        <g transform={`translate(${edge.labelX} ${edge.labelY})`}>
                          <text
                            x="0"
                            y="-0.4"
                            textAnchor="middle"
                            fontSize="2.7"
                            fontWeight="700"
                            fill={edge.color}
                            paintOrder="stroke"
                            stroke="rgba(5, 10, 20, 0.15)"
                            strokeWidth="0.25"
                            style={{ letterSpacing: '0.08em' }}
                          >
                            {edge.label}
                          </text>
                        </g>
                      </g>
                    ))}
                  </svg>
                  {attackGraph.nodes.map((node) => {
                    const pos = nodePositions[node.node_id] ?? DEFAULT_NODE_POSITIONS[node.node_id] ?? { left: '20%', top: '28%' };
                    const isSelected = selectedGraphNodeId === node.node_id;
                    const isConnected = relatedGraphNodeIds.has(node.node_id) && !isSelected;

                    return (
                      <button
                        key={node.node_id}
                        type="button"
                        className={`node ${node.severity} ${isSelected ? 'selected' : ''} ${isConnected ? 'connected' : ''} ${draggingNodeId === node.node_id ? 'dragging' : ''}`}
                        style={{ left: pos.left, top: pos.top }}
                        onClick={() => setSelectedGraphNodeId(node.node_id)}
                        onPointerDown={(event) => handleNodePointerDown(event, node.node_id)}
                        onPointerMove={(event) => handleNodePointerMove(event, node.node_id)}
                        onPointerUp={(event) => handleNodePointerUp(event, node.node_id)}
                        onPointerLeave={(event) => {
                          if (draggingNodeId === node.node_id) {
                            setDraggingNodeId(null);
                            if (event.currentTarget.hasPointerCapture(event.pointerId)) {
                              event.currentTarget.releasePointerCapture(event.pointerId);
                            }
                          }
                        }}
                      >
                        {node.name}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="panel">
                <div className="panel-header row-header">
                  <h2>攻击链</h2>
                  <div className="vertical-scroll-controls" aria-label="攻击链上下滚动控制">
                    <button type="button" onClick={() => scrollDashboardList('up', attackChainRef)} aria-label="向上查看攻击链">↑</button>
                    <button type="button" onClick={() => scrollDashboardList('down', attackChainRef)} aria-label="向下查看攻击链">↓</button>
                  </div>
                </div>
                <div className="scrollable-vertical-list attack-chain-scroll" ref={attackChainRef}>
                  <div className="timeline">
                    {attackChain.stages.map((stage, index) => (
                      <div className={`timeline-item stage-${stage.stage}`} key={`${stage.stage}-${index}`}>
                        <span className="timeline-marker">{index + 1}</span>
                        <div>
                          <strong>{formatStageName(stage.stage)}</strong>
                          <div className="timeline-host">{stage.host} · {stage.stage}</div>
                          <small>{stage.technique_id} · 攻击链关联结果</small>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            <section className="bottom-grid">
              <div className="panel">
                <div className="panel-header row-header">
                  <h2>最近事件</h2>
                  <div className="vertical-scroll-controls" aria-label="最近事件上下滚动控制">
                    <button type="button" onClick={() => scrollDashboardList('up', recentEventsRef)} aria-label="向上查看最近事件">↑</button>
                    <button type="button" onClick={() => scrollDashboardList('down', recentEventsRef)} aria-label="向下查看最近事件">↓</button>
                  </div>
                </div>
                <div className="recent-events-scroll-area" ref={recentEventsRef}>
                  <table className="event-table">
                    <thead>
                      <tr>
                        <th>时间</th>
                        <th>主机</th>
                        <th>类型</th>
                        <th>严重级别</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.length > 0 ? events.map((event) => (
                        <tr key={event.event_id} onClick={() => setSelectedEventId(event.event_id)} className="clickable-row">
                          <td>{event.timestamp}</td>
                          <td>{event.host.hostname}</td>
                          <td>{formatEventType(event.event_type)}</td>
                          <td>
                            <span className={`severity-badge ${event.severity}`}>{formatSeverity(event.severity)}</span>
                          </td>
                        </tr>
                      )) : <tr><td colSpan={4}>暂无事件数据。</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="panel">
                <div className="panel-header">
                  <h2>选中事件</h2>
                </div>
                <div className="detail-card">
                  <div className="detail-label">事件 ID</div>
                  <div className="detail-value">{selectedEvent?.event_id ?? '暂无事件数据'}</div>

                  <div className="detail-label">严重级别</div>
                  <div className="detail-value">
                    <span className={`severity-badge ${selectedEvent?.severity ?? 'info'}`}>{selectedEvent ? formatSeverity(selectedEvent.severity) : '暂无数据'}</span>
                  </div>

                  <div className="detail-label">主机</div>
                  <div className="detail-value">{selectedEvent?.host.hostname ?? '暂无事件数据'}</div>

                  <div className="detail-label">来源</div>
                  <div className="detail-value">{selectedEvent?.source ?? '暂无事件数据'}</div>
                </div>
              </div>
            </section>
          </>
        )}

        {activeTab === '事件' && (
          <section className="events-layout">
            <div className="panel full-panel events-panel">
              <div className="panel-header row-header">
                <h2>安全事件</h2>
                <div className="filter-controls">
                  <button
                    type="button"
                    className="filter-scroll-button"
                    onClick={() => scrollEventFilters('left')}
                    aria-label="向左查看查询条件"
                    title="向左查看查询条件"
                  >
                    ←
                  </button>
                  <div className="filters filter-scroll-area" ref={eventFiltersRef}>
                  <input
                    type="search"
                    value={eventSearch}
                    onChange={(event) => setEventSearch(event.target.value)}
                    placeholder="搜索事件、主机、IP、标签"
                    aria-label="搜索事件、主机、IP、标签"
                  />
                  <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                    <option value="all">全部级别</option>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中等</option>
                    <option value="low">低危</option>
                    <option value="info">信息</option>
                  </select>
                  <select value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
                    <option value="all">全部主机</option>
                    {hostOptions.map((hostname) => (
                      <option value={hostname} key={hostname}>{hostname}</option>
                    ))}
                  </select>
                  <select value={sourceTypeFilter} onChange={(event) => setSourceTypeFilter(event.target.value)}>
                    <option value="all">全部数据源</option>
                    {sourceTypeOptions.map((sourceType) => (
                      <option value={sourceType} key={sourceType}>{formatSourceType(sourceType)}</option>
                    ))}
                  </select>
                  <select value={eventTypeFilter} onChange={(event) => setEventTypeFilter(event.target.value)}>
                    <option value="all">全部事件类型</option>
                    {eventTypeOptions.map((eventType) => (
                      <option value={eventType} key={eventType}>{formatEventType(eventType)}</option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="reset-layout-btn"
                    onClick={() => {
                      setEventSearch('');
                      setSeverityFilter('all');
                      setHostFilter('all');
                      setSourceTypeFilter('all');
                      setEventTypeFilter('all');
                    }}
                  >
                    清空筛选
                  </button>
                  </div>
                  <button
                    type="button"
                    className="filter-scroll-button"
                    onClick={() => scrollEventFilters('right')}
                    aria-label="向右查看查询条件"
                    title="向右查看查询条件"
                  >
                    →
                  </button>
                </div>
              </div>

              <div className="table-scroll-controls" aria-label="事件列表横向滚动控制">
                <button
                  type="button"
                  className="filter-scroll-button"
                  onClick={() => scrollEventTable('left')}
                  aria-label="向左查看事件列表"
                  title="向左查看事件列表"
                >
                  ←
                </button>
                <div className="event-table-scroll-area" ref={eventTableRef}>
                  <table className="event-table">
                    <thead>
                      <tr>
                        <th>事件 ID</th>
                        <th>时间</th>
                        <th>数据源</th>
                        <th>主机</th>
                        <th>类型</th>
                        <th>严重级别</th>
                        <th>标签</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredEvents.length > 0 ? filteredEvents.map((event) => (
                        <tr
                          key={event.event_id}
                          onClick={() => setSelectedEventId(event.event_id)}
                          className={`clickable-row ${selectedEvent?.event_id === event.event_id ? 'active-row' : ''}`}
                        >
                          <td>{event.event_id}</td>
                          <td>{event.timestamp}</td>
                          <td><span className="source-pill">{formatSourceType(event.source_type)}</span></td>
                          <td>{event.host.hostname}</td>
                          <td>{formatEventType(event.event_type)}</td>
                          <td>
                            <span className={`severity-badge ${event.severity}`}>{formatSeverity(event.severity)}</span>
                          </td>
                          <td>{formatTags(event.tags)}</td>
                        </tr>
                      )) : <tr><td colSpan={7}>没有符合当前筛选条件的事件。</td></tr>}
                    </tbody>
                  </table>
                </div>
                <button
                  type="button"
                  className="filter-scroll-button"
                  onClick={() => scrollEventTable('right')}
                  aria-label="向右查看事件列表"
                  title="向右查看事件列表"
                >
                  →
                </button>
              </div>
              <div className="event-timeline-panel">
                <div className="panel-header">
                  <h3>事件时间线</h3>
                  <p className="panel-subtitle">按当前筛选结果排列，辅助追踪多源行为顺序。</p>
                </div>
                <div className="event-timeline">
                  {timelineEvents.length > 0 ? timelineEvents.map((event) => (
                    <button
                      type="button"
                      className={`event-timeline-item ${selectedEvent?.event_id === event.event_id ? 'active' : ''}`}
                      key={`timeline-${event.event_id}`}
                      onClick={() => setSelectedEventId(event.event_id)}
                    >
                      <time>{event.timestamp}</time>
                      <strong>{formatEventType(event.event_type)}</strong>
                      <span>{event.host.hostname ?? '未知主机'} · {event.source}</span>
                    </button>
                  )) : <div className="empty-state">暂无符合条件的时间线事件。</div>}
                </div>
              </div>
            </div>

            <aside className="panel detail-panel">
              <div className="panel-header">
                <h2>事件详情</h2>
              </div>
              <div className="detail-card">
                <div className="detail-label">事件 ID</div>
                <div className="detail-value">{selectedEvent?.event_id ?? '暂无事件数据'}</div>

                <div className="detail-label">时间戳</div>
                <div className="detail-value">{selectedEvent?.timestamp ?? '暂无事件数据'}</div>

                <div className="detail-label">数据源类型</div>
                <div className="detail-value">{selectedEvent ? formatSourceType(selectedEvent.source_type) : '暂无事件数据'}</div>

                <div className="detail-label">采集器</div>
                <div className="detail-value">{selectedEvent?.source ?? '暂无事件数据'}</div>

                <div className="detail-label">主机</div>
                <div className="detail-value">{selectedEvent ? `${selectedEvent.host.hostname} / ${selectedEvent.host.ip ?? '-'}` : '暂无事件数据'}</div>

                <div className="detail-label">严重级别</div>
                <div className="detail-value">
                  <span className={`severity-badge ${selectedEvent?.severity ?? 'info'}`}>{selectedEvent ? formatSeverity(selectedEvent.severity) : '暂无数据'}</span>
                </div>

                <div className="detail-label">标签</div>
                <div className="detail-value">{formatTags(selectedEvent?.tags)}</div>

                <div className="detail-label">行为主体</div>
                <div className="detail-value">
                  {selectedEvent?.subject
                    ? `${selectedEvent.subject.type ?? '未知'} / ${selectedEvent.subject.name ?? '未知'}${selectedEvent.subject.pid ? ` / PID ${selectedEvent.subject.pid}` : ''}`
                    : '暂无数据'}
                </div>

                <div className="detail-label">行为对象</div>
                <div className="detail-value">
                  {selectedEvent?.object
                    ? `${selectedEvent.object.type ?? '未知'} / ${selectedEvent.object.name ?? selectedEvent.object.path ?? '未知'}`
                    : '暂无数据'}
                </div>

                <div className="detail-label">网络信息</div>
                <div className="detail-value">
                  {selectedEvent?.network
                    ? `${selectedEvent.network.src_ip ?? '-'}:${selectedEvent.network.src_port ?? '-'} -> ${selectedEvent.network.dst_ip ?? '-'}:${selectedEvent.network.dst_port ?? '-'} (${selectedEvent.network.protocol ?? '-'})`
                    : '暂无数据'}
                </div>

                <div className="detail-label">ATT&CK 映射</div>
                <div className="detail-value">
                  {selectedEvent?.attack
                    ? `${selectedEvent.attack.technique_id ?? '未提供'} / ${selectedEvent.attack.technique_name ?? '未提供'} / ${selectedEvent.attack.tactic ?? '未提供'}`
                    : '暂无数据'}
                </div>

                <div className="detail-label">原始数据</div>
                <pre className="detail-json">{JSON.stringify(selectedEvent?.raw_data ?? {}, null, 2)}</pre>
              </div>
            </aside>
          </section>
        )}

        {activeTab === '告警' && (
          <section className="alerts-layout">
            <div className="panel full-panel alerts-panel">
              <div className="panel-header row-header">
                <div>
                  <h2>告警列表</h2>
                  <p className="panel-subtitle">
                    {detectionStatus === 'ready' && detections.length > 0
                      ? `已加载 ${detections.length} 条检测结果。`
                      : '当前展示基于攻击关系整理的关联项，检测详情将在分析结果完善后呈现。'}
                  </p>
                </div>
                <div className="filters">
                  <select value={alertStatusFilter} onChange={(event) => setAlertStatusFilter(event.target.value)}>
                    <option value="all">全部状态</option>
                    <option value="new">待研判</option>
                    <option value="prioritized">重点关注</option>
                    <option value="correlated">已关联</option>
                  </select>
                  <select value={alertSeverityFilter} onChange={(event) => setAlertSeverityFilter(event.target.value)}>
                    <option value="all">全部级别</option>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中等</option>
                    <option value="low">低危</option>
                  </select>
                </div>
              </div>
              <div className="alert-summary-row">
                <div><strong>{alertRecords.length}</strong><span>图谱关系</span></div>
                <div><strong>{alertRecords.filter((alert) => alert.status === 'new').length}</strong><span>待研判关系</span></div>
                <div><strong>{alertRecords.filter((alert) => alert.severity === 'critical').length}</strong><span>严重关系</span></div>
              </div>
              <div className="alert-list">
                {filteredAlerts.length > 0 ? filteredAlerts.map((alert) => (
                  <article
                    className={`alert-item ${selectedAlertId === alert.id ? 'selected-alert' : ''}`}
                    key={alert.id}
                    onClick={() => setSelectedAlertId(selectedAlertId === alert.id ? null : alert.id)}
                  >
                    <div className="alert-main">
                      <div className="alert-title-row">
                        <span className={`severity-badge ${alert.severity}`}>{formatSeverity(alert.severity)}</span>
                        <h3>{alert.title}</h3>
                      </div>
                      <div className="alert-meta">{alert.id} · {alert.host} · 更新于 {alert.updated}</div>
                      <div className="alert-evidence">证据：{alert.evidence}</div>
                    </div>
                    <div className="alert-side">
                      <span className={`task-status ${alert.status}`}>{alertStatusLabels[alert.status]}</span>
                      <span className="source-pill">{alert.source}</span>
                      <strong>{alert.technique}</strong>
                      {alert.confidence !== undefined && <small>置信度 {Math.round(alert.confidence * 100)}%</small>}
                    </div>
                    {selectedAlertId === alert.id && (
                      <div className="alert-detail-expanded">
                        <span>详细说明</span>
                        <p>{alert.description ?? alert.evidence}</p>
                        <span>标签</span>
                        <p>{alert.tags?.join('、') || '暂无数据'}</p>
                        <span>关联事件</span>
                        <p>{alert.relatedEventIds?.join('、') || '暂无数据'}</p>
                        <span>关联实体</span>
                        <p>{alert.relatedEntityIds?.join('、') || '暂无数据'}</p>
                        <span>证据详情</span>
                        <pre>{alert.evidenceDetails ? JSON.stringify(alert.evidenceDetails, null, 2) : '暂无数据'}</pre>
                      </div>
                    )}
                  </article>
                )) : <div className="empty-state">暂无可展示的攻击关系。</div>}
              </div>
            </div>
          </section>
        )}

        {activeTab === 'ATT&CK' && (
          <section className="attack-knowledge-layout">
            <div className="panel full-panel attack-technique-panel">
              <div className="panel-header">
                <h2>ATT&CK 技术映射</h2>
                <p className="panel-subtitle">展示检测结果到战术、技术和攻击阶段的映射关系，支撑攻击链重建。</p>
              </div>
              <div className="tactic-strip">
                {['初始访问', '执行', '横向移动', '权限提升', '命令与控制', '数据窃取'].map((tactic) => (
                  <span key={tactic} className="tactic-chip">{tactic}</span>
                ))}
              </div>
              <div className="technique-table-wrap">
                <table className="event-table technique-table">
                  <thead>
                    <tr>
                      <th>技术 ID</th>
                      <th>技术名称</th>
                      <th>战术阶段</th>
                      <th>关联主机</th>
                      <th>证据来源</th>
                      <th>置信度</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attackTechniqueRows.map((technique) => (
                      <tr key={technique.id}>
                        <td><strong className="technique-id">{technique.id}</strong></td>
                        <td>{technique.name}</td>
                        <td><span className="tactic-chip compact">{technique.tactic}</span></td>
                        <td>{technique.hosts}</td>
                        <td>{technique.evidence}</td>
                        <td><strong className="confidence-value">{technique.confidence === null ? '暂无数据' : `${Math.round(technique.confidence * 100)}%`}</strong></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="attack-context-grid">
              <div className="panel context-panel">
                <div className="panel-header"><h2>攻击者指纹</h2></div>
                <div className="fingerprint-list">
                  <div><span>事件标签</span><strong>{[...new Set(events.flatMap((event) => event.tags ?? []))].join('、') || '暂无数据'}</strong></div>
                  <div><span>关联关系</span><strong>{[...new Set(attackGraph.edges.map((edge) => edge.relation))].join('、') || '暂无数据'}</strong></div>
                  <div><span>数据来源</span><strong>{sourceSummary}</strong></div>
                </div>
              </div>
              <div className="panel context-panel">
                <div className="panel-header"><h2>C2 基础设施关联</h2></div>
                <div className="infrastructure-list">
                  <div><span>地址</span><strong>{attackGraph.nodes.filter((node) => node.node_type === 'ip').map((node) => node.name).join('、') || '暂无数据'}</strong></div>
                  <div><span>关系</span><strong>{attackGraph.edges.filter((edge) => edge.relation === 'c2_communication').map((edge) => edge.relation).join('、') || '暂无数据'}</strong></div>
                  <div><span>最高置信度</span><strong className="match-positive">{graphConfidence > 0 ? `${Math.round(graphConfidence * 100)}%` : '暂无数据'}</strong></div>
                </div>
              </div>
            </div>
          </section>
        )}

        {activeTab === '攻击图谱' && (
          <section className="panel full-panel">
            <div className="panel-header row-header">
              <div>
                <h2>攻击关系图</h2>
                <p className="panel-subtitle">
                  {attackGraph.graph_id ?? '暂无图谱编号'} · {attackGraph.description ?? '暂无图谱描述'}
                  {' · '}
                  {attackGraph.start_time ?? '未提供开始时间'} - {attackGraph.end_time ?? '未提供结束时间'}
                </p>
              </div>
              <div className="graph-controls">
                <input
                  className="graph-search"
                  type="search"
                  value={graphSearch}
                  onChange={(event) => setGraphSearch(event.target.value)}
                  placeholder="搜索节点"
                  aria-label="搜索图谱节点"
                />
                <select value={graphNodeTypeFilter} onChange={(event) => setGraphNodeTypeFilter(event.target.value)} aria-label="按节点类型筛选">
                  <option value="all">全部节点</option>
                  {graphNodeTypes.map((nodeType) => <option value={nodeType} key={nodeType}>{nodeType}</option>)}
                </select>
                <select value={graphSeverityFilter} onChange={(event) => setGraphSeverityFilter(event.target.value)} aria-label="按节点风险筛选">
                  <option value="all">全部风险</option>
                  <option value="critical">严重</option>
                  <option value="high">高危</option>
                  <option value="medium">中等</option>
                  <option value="low">低危</option>
                  <option value="info">信息</option>
                </select>
                <button
                  type="button"
                  className={`layout-mode-btn ${graphViewMode === 'core' ? 'active' : ''}`}
                  onClick={() => setGraphViewMode('core')}
                >
                  核心路径
                </button>
                <button
                  type="button"
                  className={`layout-mode-btn ${graphViewMode === 'full' ? 'active' : ''}`}
                  onClick={() => setGraphViewMode('full')}
                >
                  全量图谱
                </button>
                <button
                  type="button"
                  className={`layout-mode-btn ${graphLayoutMode === 'tree' ? 'active' : ''}`}
                  onClick={() => setGraphLayoutMode('tree')}
                >
                  树状
                </button>
                <button
                  type="button"
                  className={`layout-mode-btn ${graphLayoutMode === 'ring' ? 'active' : ''}`}
                  onClick={() => setGraphLayoutMode('ring')}
                >
                  环状
                </button>
                <button
                  type="button"
                  className={`layout-mode-btn ${graphLayoutMode === 'free' ? 'active' : ''}`}
                  onClick={() => setGraphLayoutMode('free')}
                >
                  自由拖拽
                </button>
                <button type="button" className="reset-layout-btn" onClick={resetGraphLayout}>
                  重置布局
                </button>
                <button type="button" className="reset-layout-btn" onClick={exportGraph}>
                  导出图谱
                </button>
              </div>
            </div>
            <div className="graph-box large-box">
              <div className="graph-zoom-controls" aria-label="图谱缩放控制">
                <button type="button" onClick={() => setGraphZoom((value) => Math.min(value + 0.1, 1.8))} aria-label="放大图谱">+</button>
                <span>{Math.round(graphZoom * 100)}%</span>
                <button type="button" onClick={() => setGraphZoom((value) => Math.max(value - 0.1, 0.6))} aria-label="缩小图谱">−</button>
                <button type="button" onClick={() => setGraphZoom(1)} aria-label="重置图谱缩放">重置</button>
              </div>
              <div className="graph-zoom-layer" style={{ transform: `scale(${graphZoom})` }}>
              <svg className="graph-svg" viewBox="0 0 100 100" preserveAspectRatio="none">
                <defs>
                  {Object.entries(relationColors).map(([relation, color]) => (
                    <marker key={relation} id={`graph-arrow-${relation}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
                      <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
                    </marker>
                  ))}
                </defs>
                {graphEdgePaths.map((edge) => (
                  <g key={`${edge.source}-${edge.target}`}>
                    <path
                      d={edge.d}
                      className={`graph-connection-line ${edge.active ? 'active' : ''}`}
                      markerEnd={`url(#graph-arrow-${edge.relation})`}
                      style={{ stroke: edge.color, opacity: edge.active ? 1 : 0.72 }}
                    />
                    <g transform={`translate(${edge.labelX} ${edge.labelY})`}>
                      <text
                        x="0"
                        y="-0.4"
                        textAnchor="middle"
                        fontSize="2.7"
                        fontWeight="700"
                        fill={edge.color}
                        paintOrder="stroke"
                        stroke="rgba(5, 10, 20, 0.15)"
                        strokeWidth="0.25"
                        style={{ letterSpacing: '0.08em' }}
                      >
                        {edge.label}
                      </text>
                    </g>
                  </g>
                ))}
              </svg>
              {displayGraph.nodes.map((node) => {
                const pos = nodePositions[node.node_id] ?? DEFAULT_NODE_POSITIONS[node.node_id] ?? { left: '18%', top: '25%' };
                const isSelected = selectedGraphNodeId === node.node_id;
                const isConnected = relatedGraphNodeIds.has(node.node_id) && !isSelected;

                return (
                  <button
                    key={node.node_id}
                    type="button"
                    className={`node ${node.severity} ${isSelected ? 'selected' : ''} ${isConnected ? 'connected' : ''} ${draggingNodeId === node.node_id ? 'dragging' : ''}`}
                    style={{ left: pos.left, top: pos.top }}
                    onClick={() => setSelectedGraphNodeId(node.node_id)}
                    onPointerDown={(event) => handleNodePointerDown(event, node.node_id)}
                    onPointerMove={(event) => handleNodePointerMove(event, node.node_id)}
                    onPointerUp={(event) => handleNodePointerUp(event, node.node_id)}
                    onPointerLeave={(event) => {
                      if (draggingNodeId === node.node_id) {
                        setDraggingNodeId(null);
                        if (event.currentTarget.hasPointerCapture(event.pointerId)) {
                          event.currentTarget.releasePointerCapture(event.pointerId);
                        }
                      }
                    }}
                  >
                    {node.name}
                  </button>
                );
              })}
              </div>
            </div>

            <div className="graph-legend" aria-label="关系图例">
              <span className="graph-legend-title">关系图例</span>
              {Object.entries(relationLabels).map(([relation, label]) => (
                <span className="graph-legend-item" key={relation}>
                  <i style={{ background: relationColors[relation] }} />
                  {label}
                </span>
              ))}
              <span className="graph-legend-note">箭头表示攻击方向 · 点击节点查看上下文</span>
            </div>
            <div className="graph-view-summary">
              当前展示 {displayGraph.nodes.length} 个节点、{displayGraph.edges.length} 条边
              {graphViewMode === 'core' && attackChain.paths[0] ? ` · Top 1 路径评分 ${attackChain.paths[0].score.toFixed(4)}` : ' · 已按筛选条件重新布局'}
            </div>

            <div className="graph-detail-card">
              <div className="graph-detail-header">
                <span className="graph-tag">已选节点</span>
                <strong>{selectedGraphNode?.name ?? '暂无图谱数据'}</strong>
              </div>
              <div className="graph-detail-grid">
                <div>
                  <span className="detail-label">类型</span>
                  <div className="detail-value">{selectedGraphNode?.node_type ?? '暂无数据'}</div>
                </div>
                <div>
                  <span className="detail-label">严重级别</span>
                  <div className="detail-value"><span className={`severity-badge ${selectedGraphNode?.severity ?? 'info'}`}>{selectedGraphNode ? formatSeverity(selectedGraphNode.severity) : '暂无数据'}</span></div>
                </div>
                <div>
                  <span className="detail-label">标签</span>
                  <div className="detail-value">{formatTags(selectedGraphNode?.tags)}</div>
                </div>
                <div>
                  <span className="detail-label">关联事件</span>
                  <div className="detail-value">{relatedGraphEdges.length}</div>
                </div>
              </div>

              <div className="detail-context-block">
                <div className="detail-label">关系上下文</div>
                <div className="context-list">
                  {graphRelationContext.length > 0 ? (
                    graphRelationContext.map((edge) => (
                      <div key={edge.edge_id} className="context-item">
                        <span className="context-badge" style={{ background: `${edge.color}20`, color: edge.color }}>
                          {edge.relationLabel}
                        </span>
                        <span className="context-relation">
                          {selectedGraphNode?.node_id === edge.source ? `${selectedGraphNode.name} → ${edge.neighborName}` : `${edge.neighborName} → ${selectedGraphNode?.name ?? ''}`}
                          <small>{edge.attack_technique_id ?? '未映射'} · 置信度 {edge.confidence === undefined ? '暂无数据' : `${Math.round(edge.confidence * 100)}%`}</small>
                        </span>
                      </div>
                    ))
                  ) : (
                    <div className="context-item muted">当前节点暂无关联关系</div>
                  )}
                </div>
              </div>
            </div>
          </section>
        )}

        {activeTab === '攻击链' && (
          <section className="panel full-panel">
            <div className="panel-header">
              <h2>攻击链重建</h2>
            </div>
            <div className="chain-summary-grid">
              <div className="chain-summary-item">
                <span>候选路径</span>
                <strong>{attackChain.candidate_path_count ?? attackChain.paths.length}</strong>
              </div>
              <div className="chain-summary-item">
                <span>Top 1 路径评分</span>
                <strong>{attackChain.top_path_score == null ? '暂无' : attackChain.top_path_score.toFixed(4)}</strong>
              </div>
              <div className="chain-summary-item">
                <span>重建阶段</span>
                <strong>{attackChain.stages.length}</strong>
              </div>
            </div>
            <div className="chain-grid">
              {attackChain.stages.length > 0 ? attackChain.stages.map((stage, index) => (
                <button
                  type="button"
                  className={`chain-card ${selectedStageIndex === index ? 'selected-chain-card' : ''}`}
                  key={`${stage.stage}-${index}`}
                  onClick={() => setSelectedStageIndex(selectedStageIndex === index ? null : index)}
                >
                  <div className="chain-step">步骤 {index + 1}</div>
                  <h3>
                    {formatStageName(stage.stage)}
                  </h3>
                  <p>主机：{stage.host ?? '未知'}</p>
                  <p>技术：{stage.technique_id ?? '未映射'}</p>
                  <div className="chain-evidence">阶段：{stage.stage}</div>
                  <small className="chain-source">来源：攻击链关联结果</small>
                  {selectedStageIndex === index && (
                    <div className="chain-detail-expanded">
                      <span>关联事件</span>
                      <strong>{stage.related_event_ids?.length ?? 0} 条</strong>
                      <span>相关检测</span>
                      <strong>{stage.related_detection_ids?.length ?? 0} 条</strong>
                      <span>置信度</span>
                      <strong>{stage.confidence === undefined ? '暂无' : `${Math.round(stage.confidence * 100)}%`}</strong>
                    </div>
                  )}
                </button>
              )) : <div className="empty-state">暂无攻击链阶段。</div>}
            </div>
            <div className="chain-paths">
              <div className="panel-header"><h2>候选路径</h2></div>
              {attackChain.paths.length > 0 ? attackChain.paths.map((path, index) => (
                <div className="chain-path-card" key={`${path.edges.join('-')}-${index}`}>
                  <div>
                    <strong>路径 {index + 1}</strong>
                    <span>{path.nodes.length} 个节点 · {path.edges.length} 条边</span>
                  </div>
                  <div className="chain-path-metrics">
                    <span>评分 {path.score.toFixed(4)}</span>
                    <span>置信度 {Math.round(path.confidence * 100)}%</span>
                    <span>事件 {path.related_event_ids.length}</span>
                    <span>检测 {path.related_detection_ids.length}</span>
                  </div>
                </div>
              )) : <div className="empty-state">暂无候选路径。</div>}
            </div>
          </section>
        )}

        {activeTab === '会话' && (
          <section className="panel full-panel">
            <div className="panel-header">
              <h2>登录与网络会话</h2>
              <p className="panel-subtitle">将登录源 IP、用户进程和网络五元组放在同一调查视图中。</p>
            </div>
            <div className="insight-grid session-grid">
              <div className="panel insight-panel session-panel">
                <div className="panel-header"><h2>登录会话</h2></div>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>主机</th><th>用户</th><th>源 IP</th><th>登录时间</th><th>状态</th><th>进程</th></tr></thead>
                    <tbody>
                      {loginSessions.map((session) => (
                        <tr key={session.session_id}>
                          <td>{session.hostname}</td>
                          <td>{session.user}</td>
                          <td>{session.src_ip ?? '未知'}</td>
                          <td>{session.login_at}</td>
                          <td>{session.logout_at ? '已注销' : '活动中'}</td>
                          <td>{session.processes?.slice(0, 3).join(', ') || '暂无'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {loginSessions.length === 0 && <div className="empty-state">暂无登录会话</div>}
                </div>
              </div>
              <div className="panel insight-panel session-panel">
                <div className="panel-header"><h2>网络会话</h2></div>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>通信双方</th><th>协议</th><th>时间范围</th><th>事件</th><th>字节</th><th>状态</th></tr></thead>
                    <tbody>
                      {networkSessions.slice(0, 50).map((session, index) => (
                        <tr key={`${session.src_ip}-${session.dst_ip}-${session.start_time}-${index}`}>
                          <td>{session.src_ip}:{session.src_port ?? '-'} → {session.dst_ip}:{session.dst_port ?? '-'}</td>
                          <td>{session.protocol ?? '未知'}</td>
                          <td>{session.start_time} 至 {session.end_time}</td>
                          <td>{session.event_count}</td>
                          <td>{session.bytes}</td>
                          <td>{session.state ?? '未知'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {networkSessions.length === 0 && <div className="empty-state">暂无网络会话</div>}
                </div>
              </div>
            </div>
          </section>
        )}

        {activeTab === '取证' && (
          <section className="panel full-panel">
            <div className="panel-header">
              <h2>取证与归因</h2>
              <p className="panel-subtitle">汇总会话、隐蔽信道、攻击者指纹、C2 基础设施与多智能体复核结果。</p>
            </div>
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-label">进程树节点</div>
                <div className="stat-value">{forensicsReport?.process_tree.nodes?.length ?? 0}</div>
                <div className="stat-detail">主机进程证据</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">可疑隐蔽信道</div>
                <div className="stat-value">{covertChannels?.count ?? 0}</div>
                <div className="stat-detail">DNS / HTTP 线索</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">C2 端点</div>
                <div className="stat-value">{forensicsReport?.c2_infrastructure.endpoints?.length ?? 0}</div>
                <div className="stat-detail">IP 与域名关联</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Agent 状态</div>
                <div className="stat-value">{agentAnalysis?.agent_status.degraded ? '降级' : agentAnalysis?.agent_status.enabled ? '已启用' : '关闭'}</div>
                <div className="stat-detail">证据、攻击链、归因、报告复核</div>
              </div>
            </div>
            <div className="insight-grid">
              <div className="panel insight-panel">
                <div className="panel-header"><h2>APT/TTP 相似度</h2></div>
                <div className="context-list">
                  {(forensicsReport?.apt_matches ?? []).slice(0, 5).map((match, index) => (
                    <div className="context-item" key={`${String(match.profile)}-${index}`}>
                      <span className="context-badge">{String(match.profile ?? '未知画像')}</span>
                      <span className="context-relation">相似度 {String(match.similarity ?? 0)}<small>{Array.isArray(match.matched_techniques) ? match.matched_techniques.join(', ') : '暂无匹配技术'}</small></span>
                    </div>
                  ))}
                  {(forensicsReport?.apt_matches ?? []).length === 0 && <div className="empty-state">暂无归因画像结果</div>}
                </div>
              </div>
              <div className="panel insight-panel">
                <div className="panel-header"><h2>隐蔽信道证据</h2></div>
                <div className="context-list">
                  {(covertChannels?.suspicious_domains ?? []).slice(0, 5).map((item, index) => (
                    <div className="context-item" key={`${String(item.event_id)}-${index}`}>
                      <span className="context-badge">{String(item.src_ip ?? '未知源')}</span>
                      <span className="context-relation">{String(item.query ?? '未知查询')}<small>熵值 {String(item.entropy ?? '暂无')}</small></span>
                    </div>
                  ))}
                  {(covertChannels?.suspicious_domains ?? []).length === 0 && <div className="empty-state">暂无可疑信道证据</div>}
                </div>
              </div>
            </div>
            <div className="insight-grid">
              <div className="panel insight-panel">
                <div className="panel-header"><h2>进程父子关系</h2></div>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>父进程</th><th>子进程</th><th>主机</th><th>用户</th></tr></thead>
                    <tbody>
                      {(forensicsReport?.process_tree.edges ?? []).slice(0, 50).map((edge, index) => {
                        const nodes = forensicsReport?.process_tree.nodes ?? [];
                        const parent = nodes.find((node) => node.node_id === edge.source);
                        const child = nodes.find((node) => node.node_id === edge.target);
                        return (
                          <tr key={`${String(edge.source)}-${String(edge.target)}-${index}`}>
                            <td>{String(parent?.name ?? edge.source)}</td>
                            <td>{String(child?.name ?? edge.target)}</td>
                            <td>{String(child?.host ?? parent?.host ?? '未知')}</td>
                            <td>{String(child?.user ?? '未知')}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {(forensicsReport?.process_tree.edges ?? []).length === 0 && <div className="empty-state">暂无进程父子关系</div>}
                </div>
              </div>
              <div className="panel insight-panel">
                <div className="panel-header"><h2>C2 基础设施详情</h2></div>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>类型</th><th>地址</th><th>端口</th><th>证据数</th></tr></thead>
                    <tbody>
                      {(forensicsReport?.c2_infrastructure.endpoints ?? []).slice(0, 50).map((endpoint, index) => (
                        <tr key={`${String(endpoint.type)}-${String(endpoint.value)}-${index}`}>
                          <td>{String(endpoint.type ?? '未知')}</td>
                          <td>{String(endpoint.value ?? '未知')}</td>
                          <td>{Array.isArray(endpoint.ports) ? endpoint.ports.join(', ') || '未知' : '未知'}</td>
                          <td>{Array.isArray(endpoint.event_ids) ? endpoint.event_ids.length : 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {(forensicsReport?.c2_infrastructure.endpoints ?? []).length === 0 && <div className="empty-state">暂无 C2 端点</div>}
                </div>
              </div>
            </div>
            <div className="panel insight-panel">
              <div className="panel-header"><h2>多智能体复核</h2></div>
              <pre className="detail-value">{JSON.stringify(agentAnalysis?.agent_analysis?.report ?? { message: '暂无复核结果' }, null, 2)}</pre>
            </div>
          </section>
        )}

        {activeTab === '任务' && (
          <section className="panel full-panel">
            <div className="panel-header">
              <h2>分析任务队列</h2>
              <p className="panel-subtitle">提交主机日志、主机行为或网络流量数据，启动统一分析流程。</p>
            </div>
            <div className="upload-panel">
              <div className="upload-fields">
                <label className="field-label" htmlFor="upload-source-type">数据类型</label>
                <select
                  id="upload-source-type"
                  value={uploadSourceType}
                  onChange={(event) => setUploadSourceType(event.target.value as UploadSourceType)}
                  disabled={uploadState === 'uploading'}
                >
                  <option value="host_log">主机日志</option>
                  <option value="host_behavior">主机行为</option>
                  <option value="network_traffic">网络流量</option>
                </select>
              </div>
              <div className="upload-fields">
                <label className="field-label" htmlFor="data-file">数据文件</label>
                <input
                  id="data-file"
                  type="file"
                    accept=".txt,.log,.json,.jsonl,.ndjson,.evtx,.pcap,.pcapng,.cap"
                  onChange={(event) => {
                    setSelectedFile(event.target.files?.[0] ?? null);
                    setUploadState('idle');
                    setUploadMessage('');
                  }}
                  disabled={uploadState === 'uploading'}
                />
              </div>
              <button type="button" className="primary-btn" onClick={handleUpload} disabled={uploadState === 'uploading'}>
                {uploadState === 'uploading' ? '提交中...' : '提交分析'}
              </button>
              {selectedFile && <span className="upload-file-name">已选择：{selectedFile.name}</span>}
              {uploadMessage && <span className={`upload-message ${uploadState}`}>{uploadMessage}</span>}
            </div>
            <div className="dataset-load-panel">
              <div>
                <strong>ADFA-LD Linux 系统调用数据集</strong>
                <p>将数据集按统一主机行为事件加载，结果会同步到事件、告警、ATT&CK、攻击图和攻击链模块。</p>
              </div>
              <button type="button" className="primary-btn" onClick={handleLoadAdfa}>加载到统一工作区</button>
              {adfaLoadMessage && <span className="upload-message success">{adfaLoadMessage}</span>}
            </div>
            <div className="task-list big-list">
              {tasks.length > 0 ? tasks.map((task) => {
                const statusLabel = task.status === 'success'
                  ? '已完成'
                  : task.status === 'running'
                    ? '进行中'
                    : task.status === 'failed'
                      ? '失败'
                      : '待处理';

                return (
                  <div className="task-item" key={task.task_id}>
                    <div className="task-header">
                      <button type="button" className="task-name-button" onClick={() => setSelectedTask(task)}>{task.name}</button>
                      <div className="task-actions">
                        <span className={`task-status ${task.status}`}>{statusLabel}</span>
                        {task.status === 'running' && <button type="button" className="task-action-button" onClick={() => runTaskAction(task, 'cancel')}>取消</button>}
                        {task.status === 'failed' && <button type="button" className="task-action-button" onClick={() => runTaskAction(task, 'retry')}>重试</button>}
                        {task.status === 'success' && <button type="button" className="task-action-button" onClick={() => handleRemoveTask(task)}>撤销出工作区</button>}
                      </div>
                    </div>
                    <div className="progress-bar">
                      <span style={{ width: `${task.progress}%` }} />
                    </div>
                    <small>{task.progress}% 已完成</small>
                  </div>
                );
              }) : <div className="empty-state">暂无分析任务数据。</div>}
            </div>
            {selectedTask && (
              <div className="task-detail-card">
                <div className="panel-header row-header">
                  <h3>任务详情</h3>
                  <button type="button" className="task-action-button" onClick={() => setSelectedTask(null)}>关闭</button>
                </div>
                <div className="task-detail-grid">
                  <span>任务编号</span><strong>{selectedTask.task_id}</strong>
                  <span>状态</span><strong>{selectedTask.status}</strong>
                  <span>创建时间</span><strong>{selectedTask.created_at}</strong>
                  <span>更新时间</span><strong>{selectedTask.updated_at ?? '暂无数据'}</strong>
                </div>
                {taskActionMessage && <p className="task-action-message">{taskActionMessage}</p>}
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
