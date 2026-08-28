# CommitGate 三分钟真人 Demo

## 录制前

```bash
cp .env.local.example .env.local
chmod 600 .env.local
# 填写 MODEL_ID 与 MODEL_API_KEY
PATH=/opt/homebrew/bin:$PATH npm run demo
```

另一个终端确认：

```bash
PATH=/opt/homebrew/bin:$PATH npm run demo:status
```

## 0:00–0:20：问题与 HEAD

讲解：

> Coding Agent 完成任务不代表它写出的文件可以直接成为下一轮事实。CommitGate 把修改先变成 proposal；只有 trusted evidence 和一次性 permit 都成立，HEAD 才推进。

画面只突出：

```text
HEAD gN / View H0
```

## 0:20–1:05：真实 COMMITTED

在 Playground 请求正常业务修改。展示：

```text
HEAD gN/H0
→ PROPOSAL P
→ trusted verifier PASS
→ PERMIT K consumed
→ HEAD gN+1/H1
```

指出 receipt 明确记录 `baseGeneration` 与 `nextGeneration`，不是从单个 `generation` 反推。

## 1:05–1:45：候选不能自证 + protected reject

先展示候选同时提交业务配置、`package.json` 和永远 `exit 0` 的自带 test runner。说明 acceptance 仍来自 platform-owned trusted bundle。

再请求修改 `protected.txt` 或演示 policy 中的 `release-notes.txt`：

```text
Decision: Rejected / QUARANTINED
HEAD: unchanged
Artifact: destroyed
Session: reset
```

## 1:45–2:15：公开 permit replay

展开 Receipt → Security proof → `Attempt replay`：

```text
POST /api/runs/:id/commitgate/promotion-attempts
409 PERMIT_REPLAY
Rejected — HEAD unchanged
```

强调 evaluator 和 UI 都走公开 API，没有直接导入内部 permit store。

## 2:15–2:40：fresh follow-up 与 rollback

在 reject/abort 后继续一次 follow-up，展示 fresh session 和 reconciliation。打开 Version History 回滚到旧版本：rollback 创建新的 version event 和新 generation，而不是改写旧历史。

## 2:40–3:00：权限边界与准确限制

> Model Relay 单独持有 Ark key；API 通过 Unix RPC Runtime Broker 启动 Agent/Verifier。Transition Worker 是默认唯一权威写者，API 的 Authority/Control 只读挂载已通过容器内 `EROFS/EACCES` 证据验证。强保证只覆盖单 Agent 串行的 workspace filesystem effects 与 process kill/restart，不覆盖外部 API 回滚和 host/root 对手。

## 录像验收

```bash
PATH=/opt/homebrew/bin:$PATH npm run demo:verify-video -- \
  --file /ABSOLUTE/PATH/CommitGate-CommitGate-3min.mp4 \
  --manual-secret-review
```

要求：

- 165–185 秒；
- 至少 1280×720；
- 同时存在音频和视频流；
- 不显示 `.env.local`、API key、完整 secret 或终端环境；
- 报告写入 `eval/evidence/demo-video-report.json`。

结束后：

```bash
PATH=/opt/homebrew/bin:$PATH npm run demo:down
```
