import { useEffect, useMemo, useRef, useState } from 'react';
import { mockEvents } from './mock/events';
import { mockAttackGraph } from './mock/attackGraph';
import { mockAttackChain } from './mock/attackChain';
import { mockTasks } from './mock/tasks';
import { getEvents } from './api/events';
import { getAttackChain, getAttackGraph } from './api/attack';
import { getTasks } from './api/tasks';
import type { EventItem } from './types/event';
import type { AttackChain, AttackGraph } from './types/attack';
import type { TaskItem } from './types/task';

const tabs = ['仪表盘', '事件', '告警', 'ATT&CK', '攻击图谱', '攻击链', '任务'] as const;

type TabName = (typeof tabs)[number];

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

const DEFAULT_NODE_POSITIONS: Record<string, { left: string; top: string }> = {
  'host:WEB01': { left: '18%', top: '25%' },
  'host:PC01': { left: '52%', top: '38%' },
  'host:CORE-SRV': { left: '76%', top: '62%' },
  'ip:203.0.113.9': { left: '38%', top: '72%' },
};

const GRAPH_LAYOUT_STORAGE_KEY = 'attack-trace-graph-layout';

const relationLabels: Record<string, string> = {
  lateral_movement: '横向移动',
  privilege_escalation: '权限提升',
  c2_communication: 'C2 通信',
};

const relationColors: Record<string, string> = {
  lateral_movement: '#60a5fa',
  privilege_escalation: '#fbbf24',
  c2_communication: '#f87171',
};

const relationDescriptions: Record<string, string> = {
  lateral_movement: '通过远程服务从 WEB01 向内网工作站移动',
  privilege_escalation: '利用异常权限令牌进入核心服务器',
  c2_communication: '核心服务器与外部 C2 建立周期性通信',
};

const stageDescriptions: Record<string, string> = {
  initial_access: '边界入口发现可疑 Web 请求',
  execution: '执行编码脚本并创建异常进程',
  lateral_movement: '通过认证与远程服务进入内网主机',
  privilege_escalation: '出现高权限令牌与异常进程行为',
  command_and_control: '建立周期性外联与 DNS/HTTPS 信道',
  exfiltration: '读取敏感文件并准备加密外传',
};

const stageSources: Record<string, string> = {
  initial_access: '边界设备日志',
  execution: 'Windows Sysmon',
  lateral_movement: '认证日志 / 网络流量',
  privilege_escalation: '主机行为监控',
  command_and_control: 'Zeek DNS / HTTP',
  exfiltration: '文件行为 / 网络流量',
};

const alertStatusLabels: Record<string, string> = {
  new: '待研判',
  investigating: '调查中',
  contained: '已遏制',
};

const alertRecords = [
  { id: 'ALT-20260908-001', title: 'WEB01 可疑权限提升链', severity: 'critical', status: 'investigating', host: 'WEB01', source: '主机行为 + 网络流量', evidence: '异常进程注入 / 外联 beaconing', technique: 'T1068', updated: '10:45' },
  { id: 'ALT-20260908-002', title: 'PowerShell 编码命令执行', severity: 'high', status: 'contained', host: 'WIN-PC01', source: 'Windows Sysmon', evidence: '编码命令行 / 异常父子进程', technique: 'T1059.001', updated: '10:22' },
  { id: 'ALT-20260908-003', title: 'DNS 隧道外传疑似行为', severity: 'medium', status: 'new', host: 'CORE-SRV', source: 'Zeek DNS', evidence: '高熵子域 / 周期性解析', technique: 'T1071.004', updated: '10:35' },
] as const;

const attackTechniqueRows = [
  { id: 'T1190', name: '利用面向公网的应用', tactic: '初始访问', stage: '初始访问', hosts: 'WEB01', confidence: 0.94, evidence: '边界访问日志 / Web 异常请求' },
  { id: 'T1059.001', name: 'PowerShell', tactic: '执行', stage: '执行', hosts: 'WIN-PC01', confidence: 0.91, evidence: 'Sysmon 进程创建 / 编码命令行' },
  { id: 'T1021', name: '远程服务', tactic: '横向移动', stage: '横向移动', hosts: 'WEB01 → PC01', confidence: 0.88, evidence: '认证日志 / SMB 连接' },
  { id: 'T1068', name: '利用提权漏洞', tactic: '权限提升', stage: '权限提升', hosts: 'PC01 → CORE-SRV', confidence: 0.81, evidence: '异常权限令牌 / 进程行为链' },
  { id: 'T1071.004', name: 'DNS', tactic: '命令与控制', stage: '命令与控制', hosts: 'CORE-SRV → 203.0.113.9', confidence: 0.92, evidence: 'Zeek DNS / 周期性 beaconing' },
  { id: 'T1041', name: '通过 C2 信道外传', tactic: '外传', stage: '数据窃取', hosts: 'CORE-SRV', confidence: 0.76, evidence: '文件读取 / 加密外联流量' },
] as const;

const getLayoutPositions = (mode: GraphLayoutMode, graph: AttackGraph = mockAttackGraph): Record<string, { left: string; top: string }> => {
  const nodeIds = graph.nodes.map((node) => node.node_id);

  if (mode === 'ring') {
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
    return {
      'host:WEB01': { left: '22%', top: '34%' },
      'host:PC01': { left: '50%', top: '50%' },
      'host:CORE-SRV': { left: '74%', top: '62%' },
      'ip:203.0.113.9': { left: '46%', top: '78%' },
    };
  }

  return DEFAULT_NODE_POSITIONS;
};

function App() {
  const [activeTab, setActiveTab] = useState<TabName>('仪表盘');
  const [events, setEvents] = useState<EventItem[]>(mockEvents);
  const [attackGraph, setAttackGraph] = useState<AttackGraph>(mockAttackGraph);
  const [attackChain, setAttackChain] = useState<AttackChain>(mockAttackChain);
  const [tasks, setTasks] = useState<TaskItem[]>(mockTasks);
  const [dataMode, setDataMode] = useState<'loading' | 'live' | 'mock'>('loading');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [hostFilter, setHostFilter] = useState('all');
  const [alertStatusFilter, setAlertStatusFilter] = useState('all');
  const [selectedEventId, setSelectedEventId] = useState<string>(mockEvents[0].event_id);
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState<string>(mockAttackGraph.nodes[0].node_id);
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [graphLayoutMode, setGraphLayoutMode] = useState<GraphLayoutMode>('tree');
  const workflowRef = useRef<HTMLDivElement>(null);
  const [nodePositions, setNodePositions] = useState<Record<string, { left: string; top: string }>>(() => {
    const savedPositions = localStorage.getItem(GRAPH_LAYOUT_STORAGE_KEY);

    if (!savedPositions) {
      return getLayoutPositions('tree');
    }

    try {
      return { ...getLayoutPositions('tree'), ...JSON.parse(savedPositions) };
    } catch {
      return getLayoutPositions('tree');
    }
  });

  useEffect(() => {
    let active = true;

    Promise.allSettled([getEvents(), getAttackGraph(), getAttackChain(), getTasks()]).then((results) => {
      if (!active) {
        return;
      }

      const [eventsResult, graphResult, chainResult, tasksResult] = results;
      let liveDataLoaded = false;

      if (eventsResult.status === 'fulfilled' && eventsResult.value.length > 0) {
        setEvents(eventsResult.value);
        liveDataLoaded = true;
      }
      if (graphResult.status === 'fulfilled' && graphResult.value.nodes.length > 0) {
        setAttackGraph(graphResult.value);
        setSelectedGraphNodeId(graphResult.value.nodes[0].node_id);
        setNodePositions(getLayoutPositions('tree', graphResult.value));
        liveDataLoaded = true;
      }
      if (chainResult.status === 'fulfilled' && chainResult.value.stages.length > 0) {
        setAttackChain(chainResult.value);
        liveDataLoaded = true;
      }
      if (tasksResult.status === 'fulfilled' && tasksResult.value.length > 0) {
        setTasks(tasksResult.value);
        liveDataLoaded = true;
      }

      setDataMode(liveDataLoaded ? 'live' : 'mock');
    });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (graphLayoutMode !== 'free') {
      setNodePositions(getLayoutPositions(graphLayoutMode, attackGraph));
    }
  }, [graphLayoutMode, attackGraph]);

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
    setNodePositions(getLayoutPositions(graphLayoutMode === 'free' ? 'tree' : graphLayoutMode));
  };

  const scrollWorkflow = (direction: 'left' | 'right') => {
    workflowRef.current?.scrollBy({
      left: direction === 'left' ? -280 : 280,
      behavior: 'smooth',
    });
  };

  const stats = useMemo(
    () => [
      { label: '事件总量', value: '3,284', detail: '较昨日 +12.4%' },
      { label: '高危告警', value: '18', detail: '4 台高风险主机' },
      { label: '攻击链数', value: '7', detail: '新增 2 个检测' },
      { label: '任务完成率', value: '93%', detail: '3 个运行 / 1 个待处理' },
    ],
    [],
  );

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
    () => [
      { name: '攻击节点', role: '外部攻击源' },
      { name: 'C2 服务器', role: '控制基础设施' },
      { name: '防火墙', role: '边界防护' },
      { name: 'Web 服务器', role: '初始入口' },
      { name: 'Email 服务器', role: '邮件入口' },
      { name: '内网交换机', role: '内部网络' },
      { name: '办公区域计算机', role: '用户终端' },
      { name: '核心服务器', role: '关键资产' },
    ],
    [],
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
    () => [
      { label: '链路重建准确率', value: '89.6%' },
      { label: '威胁定位覆盖率', value: '93.1%' },
      { label: '响应耗时下降', value: '41.2%' },
    ],
    [],
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
    return severityMatch && hostMatch;
  });

  const filteredAlerts = alertRecords.filter(
    (alert) => alertStatusFilter === 'all' || alert.status === alertStatusFilter,
  );

  const selectedEvent =
    filteredEvents.find((event) => event.event_id === selectedEventId) ?? filteredEvents[0] ?? events[0] ?? mockEvents[0];

  const selectedGraphNode =
    attackGraph.nodes.find((node) => node.node_id === selectedGraphNodeId) ?? attackGraph.nodes[0];

  const relatedGraphEdges = attackGraph.edges.filter(
    (edge) => edge.source === selectedGraphNode.node_id || edge.target === selectedGraphNode.node_id,
  );

  const relatedGraphNodeIds = new Set(
    relatedGraphEdges.flatMap((edge) => [edge.source, edge.target]).filter((id) => id !== selectedGraphNode.node_id),
  );

  const graphRelationContext = relatedGraphEdges.map((edge) => {
    const neighborId = edge.source === selectedGraphNode.node_id ? edge.target : edge.source;
    const neighbor = attackGraph.nodes.find((node) => node.node_id === neighborId);

    return {
      ...edge,
      neighborName: neighbor?.name ?? neighborId,
      relationLabel: relationLabels[edge.relation] ?? edge.relation,
      color: relationColors[edge.relation] ?? '#94a3b8',
    };
  });

  const graphEdgePaths = attackGraph.edges.map((edge) => {
    const sourcePosition = nodePositions[edge.source] ?? DEFAULT_NODE_POSITIONS[edge.source] ?? { left: '50%', top: '50%' };
    const targetPosition = nodePositions[edge.target] ?? DEFAULT_NODE_POSITIONS[edge.target] ?? { left: '50%', top: '50%' };
    const x1 = Number.parseFloat(sourcePosition.left);
    const y1 = Number.parseFloat(sourcePosition.top);
    const x2 = Number.parseFloat(targetPosition.left);
    const y2 = Number.parseFloat(targetPosition.top);
    const ctrlX = (x1 + x2) / 2;
    const ctrlY = Math.min(y1, y2) - 12;
    const d = `M ${x1} ${y1} Q ${ctrlX} ${ctrlY} ${x2} ${y2}`;
    const isActive = edge.source === selectedGraphNode.node_id || edge.target === selectedGraphNode.node_id;
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
              <span className={`status-pill ${dataMode === 'mock' ? 'demo' : ''}`}>
                {dataMode === 'loading' ? '正在连接接口' : dataMode === 'live' ? '接口数据' : '演示数据'}
              </span>
              <span className="status-note">最后同步 2 分钟前</span>
            </div>
          </div>
          <div className="header-actions">
            <div className="chip-row">
              <span className="chip active">威胁狩猎</span>
              <span className="chip">安全分析员</span>
            </div>
            <button className="primary-btn">导出报告</button>
          </div>
        </header>

        {activeTab === '仪表盘' && (
          <>
            <section className="overview-banner">
              <div className="overview-copy">
                <span className="tag">重点事件</span>
                <h2>检测到 WEB01 发生可疑权限提升攻击链</h2>
                <p>
                  已关联 3 台终端发生横向移动，且在过去 12 分钟内出现凭据滥用和 beaconing 行为。
                </p>
              </div>
              <div className="overview-metrics">
                <div className="mini-metric">
                  <span>风险评分</span>
                  <strong>92 / 100</strong>
                </div>
                <div className="mini-metric">
                  <span>处置进度</span>
                  <strong>63%</strong>
                </div>
                <div className="mini-metric">
                  <span>受影响主机</span>
                  <strong>7 台</strong>
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
                  <div className="bar-row">
                    <span>严重</span>
                    <div className="bar-track"><i style={{ width: '42%' }} /></div>
                    <strong>42%</strong>
                  </div>
                  <div className="bar-row">
                    <span>高危</span>
                    <div className="bar-track"><i style={{ width: '31%' }} /></div>
                    <strong>31%</strong>
                  </div>
                  <div className="bar-row">
                    <span>中等</span>
                    <div className="bar-track"><i style={{ width: '27%' }} /></div>
                    <strong>27%</strong>
                  </div>
                </div>
              </div>

              <div className="panel insight-panel">
                <div className="panel-header">
                  <h2>处置状态</h2>
                </div>
                <ul className="status-list">
                  <li>
                    <span className="bullet good" />
                    WEB01 已隔离出域认证
                  </li>
                  <li>
                    <span className="bullet warn" />
                    CORE-SRV 终端正在审查
                  </li>
                  <li>
                    <span className="bullet neutral" />
                    自动化狩猎流程正在运行
                  </li>
                </ul>
              </div>

              <div className="panel insight-panel">
                <div className="panel-header">
                  <h2>调查说明</h2>
                </div>
                <div className="note-box">
                  在钓鱼诱导后观察到可疑的 PowerShell 执行行为，随后出现权限滥用并向已知外部地址发送 beaconing 流量。
                </div>
              </div>
            </section>

            <section className="summary-strip">
              <div className="summary-card accent">
                <span className="summary-kicker">建议动作</span>
                <strong>隔离受影响主机</strong>
                <small>阻断外联 beaconing 并撤销高权限会话。</small>
              </div>
              <div className="summary-card">
                <span className="summary-kicker">关键证据</span>
                <strong>PowerShell + PsExec</strong>
                <small>与 WEB01 和 CORE-SRV 的凭据滥用事件相吻合。</small>
              </div>
              <div className="summary-card">
                <span className="summary-kicker">分析说明</span>
                <strong>攻击范围已受控</strong>
                <small>攻击链仍集中在已识别的子网段内。</small>
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
                <div className="panel-header">
                  <h2>靶场拓扑</h2>
                  <p className="panel-subtitle">8 节点演示环境，覆盖攻击入口、边界设备与内网核心区域。</p>
                </div>
                <div className="lab-node-list">
                  {labNodes.map((node, index) => (
                    <div key={node.name} className="lab-node-item">
                      <span className="lab-node-index">{index + 1}</span>
                      <span className="lab-node-copy">
                        <strong>{node.name}</strong>
                        <small>{node.role}</small>
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="workflow-shell">
              <div className="panel workflow-panel">
                <div className="panel-header row-header">
                  <div>
                    <h2>检测流程</h2>
                    <p className="panel-subtitle">当前为演示链路：数据采集 → 关联分析 → 响应决策</p>
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
                  <h2>演示评估指标</h2>
                  <p className="panel-subtitle">当前为前端演示数据，不代表真实实验测量结果。</p>
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
                <div className="panel-header">
                  <h2>攻击链</h2>
                </div>
                <div className="timeline">
                  {attackChain.stages.map((stage, index) => (
                    <div className={`timeline-item stage-${stage.stage}`} key={`${stage.stage}-${index}`}>
                      <span className="timeline-marker">{index + 1}</span>
                      <div>
                        <strong>{formatStageName(stage.stage)}</strong>
                        <div className="timeline-host">{stage.host} · {stageDescriptions[stage.stage]}</div>
                        <small>{stage.technique_id} · {stageSources[stage.stage]}</small>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="bottom-grid">
              <div className="panel">
                <div className="panel-header">
                  <h2>最近事件</h2>
                </div>
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
                    {events.map((event) => (
                      <tr key={event.event_id} onClick={() => setSelectedEventId(event.event_id)} className="clickable-row">
                        <td>{event.timestamp}</td>
                        <td>{event.host.hostname}</td>
                        <td>{formatEventType(event.event_type)}</td>
                        <td>
                          <span className={`severity-badge ${event.severity}`}>{formatSeverity(event.severity)}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="panel">
                <div className="panel-header">
                  <h2>选中事件</h2>
                </div>
                <div className="detail-card">
                  <div className="detail-label">事件 ID</div>
                  <div className="detail-value">{selectedEvent.event_id}</div>

                  <div className="detail-label">严重级别</div>
                  <div className="detail-value">
                    <span className={`severity-badge ${selectedEvent.severity}`}>{formatSeverity(selectedEvent.severity)}</span>
                  </div>

                  <div className="detail-label">主机</div>
                  <div className="detail-value">{selectedEvent.host.hostname}</div>

                  <div className="detail-label">来源</div>
                  <div className="detail-value">{selectedEvent.source}</div>
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
                <div className="filters">
                  <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                    <option value="all">全部级别</option>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中等</option>
                  </select>
                  <select value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
                    <option value="all">全部主机</option>
                    <option value="WEB01">WEB01</option>
                    <option value="WIN-PC01">WIN-PC01</option>
                    <option value="CORE-SRV">CORE-SRV</option>
                  </select>
                </div>
              </div>

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
                  {filteredEvents.map((event) => (
                    <tr
                      key={event.event_id}
                      onClick={() => setSelectedEventId(event.event_id)}
                      className={`clickable-row ${selectedEvent.event_id === event.event_id ? 'active-row' : ''}`}
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
                  ))}
                </tbody>
              </table>
            </div>

            <aside className="panel detail-panel">
              <div className="panel-header">
                <h2>事件详情</h2>
              </div>
              <div className="detail-card">
                <div className="detail-label">事件 ID</div>
                <div className="detail-value">{selectedEvent.event_id}</div>

                <div className="detail-label">时间戳</div>
                <div className="detail-value">{selectedEvent.timestamp}</div>

                <div className="detail-label">数据源类型</div>
                <div className="detail-value">{formatSourceType(selectedEvent.source_type)}</div>

                <div className="detail-label">采集器</div>
                <div className="detail-value">{selectedEvent.source}</div>

                <div className="detail-label">主机</div>
                <div className="detail-value">{selectedEvent.host.hostname} / {selectedEvent.host.ip}</div>

                <div className="detail-label">严重级别</div>
                <div className="detail-value">
                  <span className={`severity-badge ${selectedEvent.severity}`}>{formatSeverity(selectedEvent.severity)}</span>
                </div>

                <div className="detail-label">标签</div>
                <div className="detail-value">{formatTags(selectedEvent.tags)}</div>

                <div className="detail-label">原始数据</div>
                <pre className="detail-json">{JSON.stringify(selectedEvent.raw_data, null, 2)}</pre>
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
                  <p className="panel-subtitle">将多源检测结果聚合为可处置的攻击告警，并保留证据链上下文。</p>
                </div>
                <div className="filters">
                  <select value={alertStatusFilter} onChange={(event) => setAlertStatusFilter(event.target.value)}>
                    <option value="all">全部状态</option>
                    <option value="new">待研判</option>
                    <option value="investigating">调查中</option>
                    <option value="contained">已遏制</option>
                  </select>
                </div>
              </div>
              <div className="alert-summary-row">
                <div><strong>{alertRecords.length}</strong><span>关联告警</span></div>
                <div><strong>{alertRecords.filter((alert) => alert.status === 'investigating').length}</strong><span>调查中</span></div>
                <div><strong>{alertRecords.filter((alert) => alert.severity === 'critical').length}</strong><span>严重告警</span></div>
              </div>
              <div className="alert-list">
                {filteredAlerts.map((alert) => (
                  <article className="alert-item" key={alert.id}>
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
                    </div>
                  </article>
                ))}
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
                        <td><strong className="confidence-value">{Math.round(technique.confidence * 100)}%</strong></td>
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
                  <div><span>工具 / 脚本</span><strong>PowerShell · PsExec · 自定义 Loader</strong></div>
                  <div><span>C2 通信特征</span><strong>周期性 HTTPS / DNS 高熵子域</strong></div>
                  <div><span>配置特征</span><strong>固定 User-Agent · 加密配置段</strong></div>
                </div>
              </div>
              <div className="panel context-panel">
                <div className="panel-header"><h2>C2 基础设施关联</h2></div>
                <div className="infrastructure-list">
                  <div><span>地址</span><strong>203.0.113.9</strong></div>
                  <div><span>协议</span><strong>HTTPS / DNS</strong></div>
                  <div><span>匹配结果</span><strong className="match-positive">TTP 相似度 87%</strong></div>
                </div>
              </div>
            </div>
          </section>
        )}

        {activeTab === '攻击图谱' && (
          <section className="panel full-panel">
            <div className="panel-header row-header">
              <h2>攻击关系图</h2>
              <div className="graph-controls">
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
              </div>
            </div>
            <div className="graph-box large-box">
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
              {attackGraph.nodes.map((node) => {
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

            <div className="graph-detail-card">
              <div className="graph-detail-header">
                <span className="graph-tag">已选节点</span>
                <strong>{selectedGraphNode.name}</strong>
              </div>
              <div className="graph-detail-grid">
                <div>
                  <span className="detail-label">类型</span>
                  <div className="detail-value">{selectedGraphNode.node_type}</div>
                </div>
                <div>
                  <span className="detail-label">严重级别</span>
                  <div className="detail-value"><span className={`severity-badge ${selectedGraphNode.severity}`}>{formatSeverity(selectedGraphNode.severity)}</span></div>
                </div>
                <div>
                  <span className="detail-label">标签</span>
                  <div className="detail-value">{formatTags(selectedGraphNode.tags)}</div>
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
                          {selectedGraphNode.node_id === edge.source ? `${selectedGraphNode.name} → ${edge.neighborName}` : `${edge.neighborName} → ${selectedGraphNode.name}`}
                          <small>{edge.attack_technique_id} · 置信度 {Math.round((edge.confidence ?? 0) * 100)}%</small>
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
            <div className="chain-grid">
              {attackChain.stages.map((stage, index) => (
                <div className="chain-card" key={`${stage.stage}-${index}`}>
                  <div className="chain-step">步骤 {index + 1}</div>
                  <h3>
                    {stage.stage === 'initial_access' && '初始访问'}
                    {stage.stage === 'execution' && '执行'}
                    {stage.stage === 'lateral_movement' && '横向移动'}
                    {stage.stage === 'privilege_escalation' && '权限提升'}
                    {stage.stage === 'command_and_control' && '命令与控制'}
                    {stage.stage === 'exfiltration' && '数据窃取'}
                  </h3>
                  <p>主机：{stage.host}</p>
                  <p>技术：{stage.technique_id}</p>
                  <div className="chain-evidence">{stageDescriptions[stage.stage]}</div>
                  <small className="chain-source">证据：{stageSources[stage.stage]}</small>
                </div>
              ))}
            </div>
          </section>
        )}

        {activeTab === '任务' && (
          <section className="panel full-panel">
            <div className="panel-header">
              <h2>分析任务队列</h2>
            </div>
            <div className="task-list big-list">
              {tasks.map((task) => {
                const statusLabel = task.status === 'success' ? '已完成' : task.status === 'running' ? '进行中' : '待处理';

                return (
                  <div className="task-item" key={task.task_id}>
                    <div className="task-header">
                      <span>{task.name}</span>
                      <span className={`task-status ${task.status}`}>{statusLabel}</span>
                    </div>
                    <div className="progress-bar">
                      <span style={{ width: `${task.progress}%` }} />
                    </div>
                    <small>{task.progress}% 已完成</small>
                  </div>
                );
              })}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
