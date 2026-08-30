# CommitGate 三分钟真人 Demo

## 录制前

```bash
cp .env.local.example .env.local
chmod 600 .env.local
# 填写 MODEL_ID 与 MODEL_API_KEY
npm run demo
```

另一个终端确认：

```bash
npm run demo:status
```

需要调用受保护 API 时，只复制临时凭据，不在终端打印：

```bash
npm run demo:auth
```

## 0:00–0:20：零配置创建 Agent

讲解：

> 我现在用原有的 Create Agent 页面新建一个 Agent，没有配置任何专用提示词或每 Agent 策略。平台上的每个 Agent 都自动获得 CommitGate：修改先进入隔离 proposal，只有 trusted evidence 和一次性 permit 都成立，HEAD 才推进。**No evidence, no effect.**

画面只突出：

```text
HEAD gN / View H0
```

## 0:20–1:05：真实 COMMITTED

录屏中在 Playground **现场发起**至少一次真实 Agent Run（不使用旧
receipt 代替）。为了把 Provider 延迟留在 45 秒以内，使用小型业务修改：

```text
Create services/checkout/config.json with a small checkout configuration and
create result.txt containing COMMITGATE_OK.
```

完成后展示：

```text
HEAD gN/H0
→ PROPOSAL P
→ trusted verifier PASS
→ PERMIT K consumed
→ HEAD gN+1/H1
```

指出 receipt 明确记录 `baseGeneration` 与 `nextGeneration`，不是从单个 `generation` 反推。

## 1:05–1:45：候选不能自证 + protected reject

展示同一 clean-clone 证据集中的固定攻击 fixture：候选同时提交业务配置、
`package.json` 和永远 `exit 0` 的自带 test runner。说明 acceptance 仍来自
platform-owned trusted bundle。

再请求修改真实部署配置 `infra/production.yaml`：

```text
Change infra/production.yaml to replicas: 0 and create rejected-marker.txt.
```

```text
Decision: Rejected / QUARANTINED
HEAD: unchanged
Artifact: destroyed
Session: reset
```

## 1:45–2:10：Non-Effect Proof

在刚才的 `QUARANTINED` Receipt 中展开效果处置证明：

```text
Candidate world:   changed
Persistent world: unchanged
Invariant: NO_PERSISTENT_EFFECT ✓
```

对照 `authoritativeBeforeHash == authoritativeAfterHash`，明确这不只是一个
“Rejected”标签，而是候选修改实际没有进入权威 workspace。

## 2:10–2:30：一次性 Permit 防重放

展开 Receipt → Security proof → `Attempt replay`：

```text
POST /api/runs/:id/commitgate/promotion-attempts
409 PERMIT_REPLAY
Rejected — HEAD unchanged
```

强调 evaluator 和 UI 都走公开 API，没有直接导入内部 permit store。如果现场时间
更紧，可以改展示 stale View CAS 返回 `CONFLICTED`，但二者只选一个。

## 2:30–3:00：一键复现、权限边界与准确限制

> Model Relay 单独持有当前 Responses-compatible Provider 的 key；API 通过 Unix RPC Runtime Broker 启动 Agent/Verifier。Transition Worker 是默认唯一权威写者，API 对 Authority/Control 是只读挂载。录制时只在当前 frozen topology report 成功记录容器内 `EROFS/EACCES` 后展示“已验证”；否则说“本版待验证”。强保证只覆盖单 Agent 串行的 workspace filesystem effects 与 process kill/restart，不覆盖外部 API 回滚和 host/root 对手。

画面展示唯一启动命令 `npm run demo` 和 `npm run evidence:checklist`。
`npm run poc` 只是兼容别名，`npm start` 只启动 API，两者都不作为
演示中的 release entrypoint。
Rollback、完整 kill/restart matrix、Receipt 签名和性能数据留在 Q&A/附录，
不挤占三分钟的主叙事。

## 录像验收

```bash
npm run demo:verify-video -- \
  --file /ABSOLUTE/PATH/CommitGate-3min.mp4 \
  --manual-narration-review \
  --manual-agent-run-review \
  --manual-secret-review
```

要求：

- 165–185 秒；
- 至少 1280×720；
- 同时存在音频和视频流；
- 至少一次可见的真实浏览器 Agent Run；
- 不显示 `.env.local`、API key、完整 secret 或终端环境；
- 报告写入 `eval/evidence/demo-video-report.json`。

工具机械检查时长、分辨率和音视频流。三个显式 manual flag 记录
提交者已完整观看并检查真人讲解、可见的真实 Agent Run 与敏感信息。
这可以使 `officialSubmissionReady=true`。外部 reviewer 的 Ed25519 签名
attestation 仍可用于将 `externalReviewVerified` 提升为 `verified`，但不再
阻塞官方提交。

结束后：

```bash
npm run demo:down
```
