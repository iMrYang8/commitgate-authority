# CommitGate 部署与复现

## 1. 支持范围

比赛强保证路径：本地 Docker/Linux Runtime、单 server、单 Agent 串行、workspace filesystem effects、process kill/restart recovery。

## 2. 配置

```bash
cp .env.local.example .env.local
chmod 600 .env.local
```

```dotenv
MODEL_PROVIDER=ark
MODEL_BASE_URL=https://ark.cn-beijing.volces.com/api/v3
MODEL_ID=ENDPOINT_ID
MODEL_API_KEY=LOCAL_SECRET
MODEL_WIRE_API=responses
```

旧 `ARK_API_KEY/ARK_MODEL/ARK_BASE_URL` 只作为 launcher 输入兼容别名。应用内部和提交文档统一使用 `MODEL_*`。

## 3. 唯一产品入口

```bash
PATH=/opt/homebrew/bin:$PATH npm run demo
```

执行顺序：

```text
build Web/API/Runtime/Verifier/Relay/Worker/Broker
→ preflight
→ create internal Agent–Relay network
→ start Transition Worker, Model Relay and Runtime Broker
→ start production API with worker Authority and broker Runtime
→ health checks
→ seed Demo Agent
→ print browser URL
```

辅助命令：

```bash
npm run demo:status
npm run demo:logs
npm run demo:down
npm run demo:reset
```

## 4. 密钥边界

Launcher 把 Provider key 写入 `.demo-state/secrets/model_api_key`，权限为 `0600`，并以 readonly secret file 只挂载给 Relay。API、Runtime Broker、Agent 和 Verifier不获得上游 key。Relay 环境只记录 `MODEL_API_KEY_FILE` 名称，不记录 key 值。

## 5. 当前运行拓扑

```text
Browser
  → Launchpad API/UI
      → Unix RPC Transition Worker → candidate/seal/permit/promotion
      → Unix RPC Runtime Broker → Docker Engine → Agent/Verifier
  → Model Relay → Ark
```

Production config 强制：

```dotenv
RUNTIME_PROVIDER=broker
TRANSITION_AUTHORITY=worker
MODEL_ACCESS_MODE=relay
COMMITGATE_ENABLED=true
```

Runtime Broker 只接受 Worker 生成并绑定 `agentId/runId` 的 opaque volume ref；拒绝 persistent workspace、任意 raw host path 和错误 run subpath。API 对 Authority/Control 只读，Worker 是唯一 RW owner。

## 6. 验证

```bash
npm run check
npm run eval:protocol
npm run eval:adversarial
npm run eval:recovery
npm run eval:container
npm run eval:filesystem:linux
npm run eval:p1-product
npm run audit:topology
npm run demo:smoke
npm run check:secrets
npm run audit:clean-clone
```

真实 Ark 浏览器 E2E：

```bash
set -a; source .env.local; set +a
npm run eval:browser:clean-clone -- --provider ark
```

## 7. Authority V2 状态

默认产品已经接入 Transition Worker、Runtime Broker、append-only log、一次性 legacy adoption 和统一 Compose。`audit:topology` 在运行容器内实际写 Authority/Control 并要求 `EROFS/EACCES`。

当前准确实现状态是：

```text
Runtime Broker product path: verified
Transition Worker default authority: verified
API Authority/Control write denial: verified (EROFS/EACCES)
Ark clean-clone + Linux filesystem + recovery: verified
P1 hardened release label: waiting for narrated three-minute Demo
```

当前机器证据已绑定同一 source revision；在正式三分钟真人有声 Demo 完成前，不写“P1 hardened”。
