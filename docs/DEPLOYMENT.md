# CommitGate 部署与复现

## 1. 支持范围

正式强保证路径：本地 Docker/Linux Runtime、单 server、单 Agent 串行、workspace filesystem effects、已列明故障点的 process kill/restart recovery。

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
npm run demo:auth
```

`demo:auth` 只把临时 API 凭据复制到当前系统剪贴板，不在终端打印。
`demo:down` 和 `demo:reset` 会删除 runtime secret；仅当剪贴板仍是该
Demo 凭据时才会将其清除，不覆盖用户后续复制的其他内容。

`npm run poc` 只是 `npm run demo` 的兼容别名。`npm start` 仅启动 API
进程，用于 API 开发或单元调试；两者都不会定义第二套 release topology。
不要用 `npm start`、旧 split Relay/Worker Compose 或手工拼接的部分服务作为
正式复现入口。唯一 release/Demo 入口仍是 `npm run demo` 和根目录
`docker-compose.yml`。

## 4. 密钥边界

Launcher 把 Provider key 写入 `.demo-state/secrets/model_api_key`，权限为
`0600`，并以 readonly secret file 只挂载给 Relay。API、Runtime Broker、
Agent 和 Verifier 不获得上游 key。Relay 环境只记录
`MODEL_API_KEY_FILE` 名称，不记录 key 值。

Launcher 还为每次启动生成独立的 `broker_attestation_key`，同样以 `0600`
secret file 只挂载给 Runtime Broker 与 Transition Worker。Broker 用该 key
对 Runtime teardown/reconciliation 和 Verifier result 做 HMAC-SHA256；Worker
验签并逐字段核对 run/Agent/lease/session/scope、proposal/input/check results
以及 bundle/image/config/resource/source pins。API、Relay、Agent、Verifier
均拿不到该 key。该 MAC 证明消息来自持有本次 key 的 Broker，不证明 Broker
测量真实、抵抗 host/root，或构成第三方/硬件 attestation。

## 5. 当前运行拓扑

```text
Browser
  → Launchpad API/UI
      → Unix RPC Transition Worker → candidate/seal/permit/promotion
      → Unix RPC Runtime Broker → Docker Engine → Agent/Verifier
  → Model Relay → Responses-compatible Provider
```

产品只承诺两个可机械检查的 persistence 结果：

```text
COMMITTED:
sealedProposalHash == verifierInputHash == promotionSourceHash
                   == finalAuthoritativeHash

NON-COMMIT:
authoritativeAfterHash == authoritativeBeforeHash
```

receipt 返回由 Worker facts 派生的 `EffectDispositionProof`，包含
candidate observation、admission base、disposition-time before/after hash、四个
promotion hash 和 `PROMOTED_EXACT_PROPOSAL | NO_PERSISTENT_EFFECT`。
`invariantSatisfied` 不是 client 可以传入的授权布尔值。

Production config 强制：

```dotenv
RUNTIME_PROVIDER=broker
TRANSITION_AUTHORITY=worker
MODEL_ACCESS_MODE=relay
COMMITGATE_ENABLED=true
COMMITGATE_POLICY_PROFILE=deployment-protected
```

`COMMITGATE_POLICY_PROFILE` accepts only `workspace-default` or
`deployment-protected`. The production demo uses the latter and protects
`.github/workflows/deploy.yml`, `infra/production.yaml`, and
`config/payment-production.json`. The Transition Worker pins the selected
profile and its hashes in the Control volume; reuse with a different profile
fails closed. Use the versioned demo stack/volumes rather than rewriting the
old policy marker.

Runtime Broker 只接受 Worker 生成的 opaque exchange ref：
`candidate-${runId}` 和 `verify-${runId}`。Worker 将 candidate 写入时绑定
admitted Agent/run/lease/session，将 verifier export 额外绑定 sealed
Proposal。这些绑定 write-once：seal 消费并 tombstone candidate，
export 拒绝覆盖已有或其他 run 的目标。Broker 拒绝 persistent
workspace、任意 raw host path 和错误 run subpath。API 对
Authority/Control 只读，Worker 是唯一 RW owner。

Broker 在 Session volume 中保存 durable monotonic lifecycle ledger：

```text
AGENT_STARTED -> AGENT_CLOSED -> VERIFIER_STARTED -> ALL_CLOSED
```

ledger 按完整 `runId + agentId + runLeaseId + sessionEpoch` 绑定，拒绝
unknown/rebound run 和 stage 回退。关闭 tombstone 跨 Broker process restart
保留，因此已签名“容器与 mount 已关闭”的同一 binding 不能再启动
Agent 或 Verifier。

Transition Worker 与 Runtime Broker 使用两个独立的 Unix socket volume 和
两个独立的 Unix group。API 只读挂载两者用于客户端连接；Broker 不挂载
Worker socket，因此持有 Docker socket 的进程不能直接调用 promotion
authority。`audit:topology` 会在真实容器中验证 Broker 连接 Worker socket
得到 `ENOENT/EACCES`，并验证 API 仍能连接两个服务。

Worker、Broker 和 Runtime artifact 共用 UID `10001`，以便 Broker 读取 Worker
以 `0500/0600` 封存的 verifier export。这里不声称 Worker/Broker 为不同
UID；权限边界来自 Authority/Control 挂载独占和独立 socket group。

Worker health 必须同时报告：

```text
manifestSchemaVersion=2
filesystemProfile=linux-strong
signingKeyId=<24-hex public-key fingerprint>
```

浏览器 evaluator 在发起 Agent Run **之前**从 `/api/system` 记录
`authorityReceiptSigningKeyId`，并要求终态 proof 使用相同公钥指纹。这是
pre-run TOFU（trust on first use）锚点，不是外部 CA 或透明日志。

Candidate 与 Verifier export 共用的 exchange volume 在正式 Compose 中是
带 byte/inode 上限的 tmpfs；`audit:topology` 会在运行中的 Broker namespace
读取 `statfs`，确认其确实是 tmpfs 且容量未超过配置值。因为正式边界是
单 Agent 串行，这个 aggregate kernel cap 等价于当前 active run 的物理上限；
它不外推为多租户逐 run quota。

Manifest v2 的 streaming scan 还具有默认 30 秒的 monotonic wall-clock
budget；超时以 `CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED` fail closed。ignored
路径仍计入 entry、byte 与 scan-time budget。

启动脚本在 build 后、`compose up --no-build` 前从实际 Runtime/Verifier image、
trusted-check bundle 和 verifier/resource 配置派生四个 Worker pin。Worker
只有在 EvidenceContext 与这些 pin 完全一致时才签发 Permit。

该 profile 对 xattr、非平凡 ACL、hardlink、symlink、sparse file、casefold/NFC
冲突、异常 UID/GID/mode 和跨 filesystem swap fail closed。portable profile
只允许开发或测试，不能作为 production 证据。

下一代 `StateViewRef` 由 Worker 根据 authoritative bytes 和 append-only
parent event 计算；API/RPC caller 只提交 expected base View 与操作，不提交
caller-authored next View。

当前 recovery evaluator 实现了 Worker/API 进程故障和 Broker-owned Agent/Verifier
child container kill。`RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION`
还会启动独立 Broker Node 进程，对其发送 `SIGKILL`，确认原 Agent
container 仍在运行，再由重启后的 Broker 基于六个精确 label 完成
reconciliation 和空集合复查。这些只是 expected scenarios；必须等
frozen `eval/evidence/docker-recovery-report.json` 成功后才能称为本版证据。
该 evaluator 不会杀死 Docker daemon，也不扩展到
host/root 对手、daemon 损坏或掉电耐久。

## 6. 验证

证据冻结分两个 Git 提交：`SOURCE_REVISION` 冻结产品代码、评估器、
文档、trusted checks 和 `eval/fixtures`；后续 `EVIDENCE_REVISION`
只封装生成的报告。因此 evidence-only 提交后，provenance 显示
`sourceRevision=SOURCE_REVISION` 与 `headRevision=EVIDENCE_REVISION`，而
`sourceTreeHash` 不变。报告不声称包含自身的未来提交哈希，以避免
证据自引用。

```bash
npm run check
npm run eval:protocol
npm run eval:adversarial
npm run eval:recovery
npm run eval:recovery:docker
npm run eval:performance
npm run eval:container
npm run eval:filesystem:linux
npm run audit:authority
npm run audit:architecture
npm run demo:preflight
npm run demo:smoke
npm run eval:p1-product
npm run eval:provider -- --provider ark
npm run eval:browser:clean-clone -- --provider ark
npm run receipt:verify
npm run eval:invariants
npm run check:secrets
npm run audit:documentation
npm run audit:clean-clone
export COMMITGATE_DEMO_REVIEWER_ID=REVIEWER_ID
export COMMITGATE_DEMO_REVIEWER_KEY_ID=REVIEWER_ED25519_KEY_ID
npm run demo:verify-video -- \
  --file /ABSOLUTE/PATH/CommitGate-3min.mp4 \
  --review-attestation /ABSOLUTE/PATH/external-video-review.json
npm run audit:source-delivery -- --reviewer-login REVIEWER_GITHUB_LOGIN
npm run evidence:checklist
npm run audit:release
```

`demo:smoke` 会启动真实拓扑并在栈仍运行时刷新 `topology-report.json`；
`eval:p1-product` 必须紧随其后消费该报告。对已停止的栈单独运行
`audit:topology` 只会得到诊断性的 `unverified`。顺序是证据合同的一部分：浏览器先生成所有本次场景的 terminal proof set，
`receipt:verify` 再离线验证实际字节，随后 `eval:invariants` 才能派生 5/5
Receipt Validation Rate；checklist 与 release audit 必须最后执行。

`eval:invariants` 的 False Commit Rate 和 NON-COMMIT 持久化变异率
共享一个固定的 10 项 effect-capable 负例 registry，缺少任意
一项都是发布失败。其中 3 项浏览器负例直接记录 raw
before/after hash；3 项 CAS 和 4 项已接受取消负例仅标记为
`assertion-backed`，并绑定到明确 Vitest test name。后一类的 raw
hash 字段保持 `null`，不会用占位字符伪装成实测 hash。

`eval:performance` 只是 Linux 上的 Transition Worker 本地文件系统协议
microbenchmark。它对 4 KiB、256 KiB 和 1 MiB fixture 各运行 30 次，
统计 seal、export、manifest + fixed-file deterministic probe、permit 和
promotion 的 p50/p95。`deterministicProbeMs` **不包含** Broker RPC、
真实 Verifier container、trusted-check bundle 进程、模型推理或网络，
因此不得将该数字称为产品 Verifier latency 或端到端延迟。

`demo:verify-video` 的自动结论覆盖媒体封装：165–185 秒、最低分辨率、
视频流和音频流。真人讲解、画面内真实 Agent Run 以及全片敏感信息检查
必须由人完整观看；没有外部 reviewer 的 Ed25519 签名 attestation 时，内容项
保留为 `unverified`。attestation 必须绑定视频 SHA-256、reviewer id/method/time
和三个内容检查；预期公钥指纹通过独立环境变量提供。传入一个 manual flag
不会自证通过。

外部 reviewer 完整观看后，在其自己控制的 Ed25519 私钥环境中生成
attestation（私钥不复制进本仓库）：

```bash
npm run demo:sign-review -- \
  --file /ABSOLUTE/PATH/CommitGate-3min.mp4 \
  --reviewer-id REVIEWER_ID \
  --private-key /REVIEWER/PRIVATE/ed25519-private.pem \
  --public-key /REVIEWER/PUBLIC/ed25519-public.pem \
  --output /ABSOLUTE/PATH/external-video-review.json
```

reviewer 必须通过与 attestation 分离的渠道提供输出的 24-hex key id。
`audit:release` 会再次读取存档的 attestation 字节、核对视频 SHA-256、
reviewer id/key anchor 并重新验签；只手工改 `demo-video-report.json`
不会放行。

`audit:source-delivery` 不把“仓库存在”当成“评委可访问”。它会对比
冻结源码与脱敏 mirror 的产品字节，在临时 clone 中重跑敏感词和 secret
scan，然后要求二选一：用 `--reviewer-login` 机械查询指定 GitHub 账号
的 read permission；或者设置 `COMMITGATE_SOURCE_ARCHIVE` 并提供同名
`.sha256` companion。未给出确切评委账号且没有归档时，此门槛保持
`unverified`。

归档路径的固定命令（必须在 mirror 同步且工作区干净后执行）：

```bash
MIRROR='../commitgate-github'
ARCHIVE='/ABSOLUTE/PATH/commitgate-authority-source.tar.gz'
git -C "$MIRROR" archive --format=tar.gz --output "$ARCHIVE" HEAD
shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256"
COMMITGATE_SOURCE_ARCHIVE="$ARCHIVE" npm run audit:source-delivery
```

真实 Provider 浏览器 E2E（命令以 Ark 适配器为例，Provider 不是得分项）：

```bash
set -a; source .env.local; set +a
npm run eval:browser:clean-clone -- --provider ark
```

浏览器 evaluator 会保存本次有限场景的五个脱敏 terminal proof bundle。离线验证：

```bash
PATH=/opt/homebrew/bin:$PATH npm run receipt:verify
```

验证内容包括两次 commit、quarantine、abort 与 rollback 的 canonical receipt、terminal event sequence/digest、Ed25519
signature、source revision 以及 Proposal/Evidence/Permit digest 绑定。它证明
该 receipt 来自当前 Worker key 且未被修改，不证明 host/root 或被攻陷 Worker
的可信性。

## 7. Authority V2 状态

默认产品已经接入 Transition Worker、Runtime Broker、append-only log、
一次性 legacy adoption 和统一 Compose。`audit:topology` 的预期验收是在
运行容器内实际写 Authority/Control 并观察 `EROFS/EACCES`；只有
当本次 frozen report 成功时，它才是当前 release evidence。

当前准确实现与 evidence gate 应分开读取：

```text
Runtime Broker + Transition Worker product wiring: implemented
API Authority/Control RO mounts: configured; live EROFS/EACCES report required
Expected Provider clean-clone report: regenerate after SOURCE_REVISION freeze
Expected Linux filesystem/recovery reports: regenerate after freeze
Expected Receipt signature/offline report: regenerate after browser proof set
P1 hardened release label: unverified until every frozen report and video pass
```

源码、Compose 或旧报告的存在不等于当前 `verified`。只有在一个
已提交且 clean 的 `SOURCE_REVISION` 上重新生成、成功且通过
provenance/image 一致性检查的 frozen reports 才能支撑该论断。在正式
三分钟真人有声 Demo 及外部人审 attestation 完成前，不写
“P1 hardened”。

生产 Compose 由 `npm run demo` 将当前冻结 commit 写入
`COMMITGATE_SOURCE_REVISION`。API、Runtime Broker 和 Transition Worker 任一
进程缺少完整 40 位小写十六进制 revision 都会 fail closed；Worker
还会拒绝 `EvaluationContext.sourceRevision` 与自身冻结 revision 不一致的
evidence。该环境变量不单独构成供应链证明，Release Audit 仍需核对
commit、source-tree hash 和所有 image digest。
