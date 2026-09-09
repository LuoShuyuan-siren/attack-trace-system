# Attack tracing

## Final integration status (2026-09-09)

The stable service entry point remains:

```python
from app.analyzers.tracing import AttackTraceService

service = AttackTraceService()
result = service.analyze(
    events=normalized_events,
    detections=detection_results,
    graph_id=graph_id,
)
graph = result["graph"]
stages = result["stages"]
paths = result["paths"]
```

`TraceAgentOrchestrator` remains the optional agent entry point. The integration
checker does not enable agents unless `--agents` is supplied, and a real LLM is
used only when its environment configuration is explicitly enabled. API keys
are never stored in this repository.

The final integration run using the updated member-5 network fixture produced
133 events, 52 detections, 121 nodes, 128 edges, 13 stages, and one candidate
path with score 0.9108. Correlation readiness is medium. Detailed provenance,
reference-integrity counts, historical fixture comparisons, and test results
are recorded in `backend/tests/fixtures/real_integration/INTEGRATION_STATUS.md`.

Important data limitations:

- Updated network detections use `process:<hostname>:<processname>`, while the
  shared entity convention requires `process:<hostname>:<numeric-pid>`.
- Member-6 `related_event_ids` do not match the current member-2 through
  member-5 event fixtures.
- The sole path (`host:PC01 -> host:DB01 -> ip:198.51.100.20`) is formed mainly
  by the internal entity chain in member-6 detections. It is not fully
  corroborated by member-2 through member-5 source events.

The public API layer is unchanged. A system integrator can map
`result["graph"]` to `GET /api/v1/attack/graph` and `result["stages"]` to
`GET /api/v1/attack/chain`; candidate paths remain an internal tracing result.

成员 7 的攻击关联模块，严格消费公共数据模型，不解析原始日志或流量。

## 使用方式

```python
from app.analyzers.tracing import AttackTraceService

service = AttackTraceService()
result = service.analyze(events, detections, graph_id="graph-task-001")
graph = result["graph"]
stages = result["stages"]
paths = result["paths"]

# 本次调用中被接收、跳过或跳过的数据统计（不进入公共 Schema）
diagnostics = service.last_diagnostics
```

服务入口会按 `event_id` / `detection_id` 去重，隔离时间、IP、PID 或对象结构损坏的输入。缺少 `subject`、`object`、`network` 等可选字段不会导致整批分析失败；无法支持对应规则的事件仍可贡献主机节点。`last_diagnostics` 仅用于运行日志和排错，不会改变 `analyze()` 的返回结构。

`AttackGraphBuilder` 完成以下工作：

- 从主机、用户、进程、文件、注册表、服务和网络端点生成稳定节点；
- 从主客体行为和网络连接生成基础关系边；
- 将检测结果中的多实体证据关联为语义攻击边；
- 根据检测标签和 ATT&CK 技术编号识别初始访问、横向移动、权限提升、C2 和外传关系；
- 在节点和边中保留事件、检测结果、技术编号、置信度及证据引用。

`AttackChainReconstructor` 从语义攻击边生成按时间排序的阶段列表。当前实现是确定性规则基线，后续可在不改变公共 Schema 的前提下增加会话窗口、跨主机因果评分和路径搜索。

`TemporalCorrelator` 在默认 5 分钟窗口内，将源主机的网络连接与目标主机的成功登录关联为横向移动边，并按远程服务端口映射 ATT&CK 子技术。

关联只支持具有完整证据闭环的远程服务：RDP `3389/T1021.001`、SSH `22/T1021.004`、SMB `445/T1021.002`、WinRM `5985/5986/T1021.006`。端口本身不会触发横向移动。

`SemanticCorrelator` 在默认 10 分钟窗口内关联：登录后执行、下载/写入/执行、敏感文件读取后外传、进程连接外部 C2。若相关 `DetectionResult` 已提供 ATT&CK Technique，会直接继承 Technique 和检测证据引用，不重复检测。

`AttackPathFinder` 只遍历攻击语义边，拒绝时间倒序和环路，输出按边数及路径置信度排序的候选攻击路径。

路径综合分数范围为 `0.0 ~ 1.0`：边置信度 25%、证据完整性 20%、时间连续性 15%、实体连续性 15%、ATT&CK 阶段顺序 15%、阶段覆盖率 10%。`score_breakdown` 保留各分项，`score` 保存加权总分。

## Multi-Agent 与真实模型

`TraceAgentOrchestrator` 在 `AttackTraceService` 之后运行，不替代规则分析。它把图裁剪为 Top-K 路径、最多 100 条边和 100 个节点，再依次调用 Evidence、ChainReview、Attribution、Report 四个 Agent。一次完整启用的分析通常产生 4 次模型调用；每次主要输入同一份裁剪后的 `TraceContext`，Report 还接收前三个 Agent 的结构化结论。

Agent 输出需经过 Pydantic 校验以及 evidence ID、Technique、IP/entity 白名单校验。任一 Agent 或真实模型失败时，仅该 Agent 使用 deterministic fallback，并在 `agent_status.degraded/errors` 中记录状态；`AttackTraceService` 始终可独立运行。真实 API smoke test 已验证四个 Agent 调用成功，结果为 `enabled=True`、`degraded=False`。API Key 只从环境变量读取，禁止写入仓库。

当前上下文保护已经限制 Top-K、节点数和边数，并优先保留路径边及高置信度边。四个 Agent 仍会重复发送部分相同 TraceContext，这是保持现有 Agent 接口的已知成本；后续可在 Provider 支持时评估 prompt caching，但不应删除本地验证。

## 误关联保护与测试

负样本覆盖：只有端口而无目标认证、认证源 IP/目标主机不匹配、超时、普通 HTTPS 外连、无文件读取证据的大流量上传、用户不一致的登录后执行、文件不一致的下载后执行、多主机并发隔离、重复 DetectionResult、乱序输入以及无关正常活动。路径鲁棒性测试覆盖环、重复阶段、多次横向移动、共享节点、相近分数、时间倒序、噪声边、不完整端点和阶段缺失。

## 性能基准

基准不属于默认 pytest：

```powershell
python -u scripts\benchmark_tracing.py
python -u scripts\benchmark_tracing.py --sizes 1000 5000 10000
```

脚本输出 `analyze()` 总耗时、节点/边/阶段/路径数量以及单独的 path finder 耗时。合成数据仅用于规模测试，不代表其他成员的真实联调数据。

当前构图使用字典索引和集合式去重，事件局部结果再合并，避免随图规模反复复制全图。仍需关注 temporal/semantic correlation 在候选密集数据上的成对扫描，以及 bounded DFS 在高分支攻击图上的路径组合增长。

## 真实联调 fixtures

将脱敏后的公共 Schema JSON 数组放入 `backend/tests/fixtures/real_integration/`：

- `windows/`、`linux/`：host_log 事件；
- `host_behavior/`：主机行为事件；
- `network/`：网络流量事件；
- `attack_mapping/`：DetectionResult。

事件文件顶层必须是 `NormalizedEvent[]`，检测文件必须是 `DetectionResult[]`。加载器 `backend/tests/fixtures/load_tracing_data.py` 使用现有 Pydantic Schema 验证，并在错误中指出文件和数组下标。不要放入原始 PCAP、EVTX、密钥、个人信息或大型数据集。

联调检查命令：

```powershell
python scripts\check_tracing_integration.py --events backend\tests\fixtures\real_integration\windows\events.json --events backend\tests\fixtures\real_integration\network\events.json --detections backend\tests\fixtures\real_integration\attack_mapping\detections.json
```

只有显式增加 `--agents` 才启用 Agent；该选项可能调用真实模型，取决于 LLM 环境配置。脚本只打印接收/跳过/重复计数、图规模、阶段、路径和分数等安全化统计。

## 当前限制

- 关联效果依赖其他模块提供稳定的 host/IP/user/process entity ID 和 evidence IDs；缺失字段会降低召回率。
- 规则采用有限时间窗口，长时间休眠、代理转发或 NAT 场景可能断链。
- TTP 归因仅输出行为画像，没有外部情报库时不做 APT 组织断言。
- 大规模高密度候选事件可能使 temporal/semantic 成对关联变慢；高分支图仍受 `max_depth/max_paths` 限制。
- 真实联调结论应等待成员 2～6 提供脱敏、Schema 合法的样例数据后再确认。
