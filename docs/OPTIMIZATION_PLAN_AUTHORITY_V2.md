# CommitGate Authority V2 优化与实施计划

## 目标

将当前已验证的 P0 协议收口为默认 P1 权限级单写者产品路径：

```text
Agent Harness
→ Runtime Broker
→ isolated candidate
→ SealedProposal
→ trusted verification
→ one-shot PromotionPermit
→ Transition Worker
→ authoritative workspace
→ append-only evidence
```

该计划只借鉴其他项目的高收益机制，不复制完整 Agent 平台、通用 Policy DSL
或 LLM judge。

## 设计来源与实际落点

| 来源 | CommitGate 落点 | 范围 |
| --- | --- | --- |
| Claude Code | Gate lifecycle、fresh session、UI timeline | 只用生命周期合同 |
| Codex | 类型化判决、Runtime Broker、fail-closed | 核心 |
| Anthropic Harness/Authority | Session / Runtime / Authority 分层 | 核心 |
| OpenHands EventStream | hash-linked transition log、recovery、projection | P1 核心 |
| Invariant | 伪造 test runner、PATH/env 劫持、protected path | 2–3 个固定负例 |
| NiceEval | 统一 EvaluationRecord、clean-clone、Ark/Playwright | 证据核心 |

## 实施阶段

### A. Broker 和发布证据闭合

- `PROCESS_ROLE` 区分 API、Broker、Worker 和 Relay。
- Broker 必须在生产执行中重新验证 Docker network 为 `Internal=true`。
- Broker RPC 使用 strict schema，拒绝 raw runtime controls 和未知字段。
- cancel 绑定 `runId + runLeaseId + sessionEpoch`，防止迟到取消新 Run。
- `audit:release` 核对 clean source、tree hash、image digest 和 Provider 身份。

### B. TransitionAuthority 和 Worker 接线

- 产品组件依赖 `TransitionAuthority`，而不是具体 Writer。
- development/test 保留 in-process 实现。
- production 必须使用 Worker RPC，禁止自动回退。
- Worker 接管 create、candidate、seal、permit、promotion、rollback、platform state、archive
  和 recovery。
- API 对 authoritative/control 仅 RO；Worker 是唯一 RW mount。

### C. Event projection 和一次性迁移

- Worker event log 重建 HEAD、generation、permit、versions 和 terminal receipt。
- API DB 仅保留产品投影和用户 message。
- 现有 P0 workspace/version/snapshot 通过 hash-checked `LEGACY_STATE_ADOPTED`
  一次性导入，不使用双写。

### D. 拓扑、评估与 Demo

- 统一 Compose：API、Worker、Broker、Relay。
- Docker socket 只属于 Broker，Provider key 只属于 Relay。
- 真实执行 API authoritative/control `EACCES` 负例。
- 所有 evaluator 输出统一 `EvaluationRecord`。
- Ark clean-clone 覆盖 commit、reject、abort、fresh session、replay 和 rollback。

## 验收

```text
production uses worker authority
API authoritative/control writes return EACCES
Broker rejects non-internal network and raw runtime controls
Docker socket exists only in Broker
Provider key exists only in Relay
Worker log rebuilds HEAD/generation/permit/version/receipt
all release evidence binds one clean revision and image identity
```

94+ 只是目标区间，必须在 P1、Ark clean-clone、拓扑审计和正式 Demo 全部通过
后重新进行第三方评分。

## 当前实施状态

- [x] Broker process role 与 production relay/network 约束
- [x] strict Broker RunnerRequest schema
- [x] run/lease/session-bound cancellation
- [x] Broker RPC timeout 和 candidate symlink identity 检查
- [x] release audit source/image 绑定
- [x] `TransitionAuthority` 产品接口
- [x] UI Gate lifecycle timeline
- [x] NiceEval-style browser `EvaluationRecord` adapter
- [x] WorkerTransitionAuthority 完整 RPC 实现
- [x] AgentService/Coordinator production 默认 Worker
- [x] 一次性 legacy state migration
- [x] 统一 Compose 和真实 API `EACCES`
- [ ] 同一 revision 的最终 Ark/recovery/topology/release 证据
