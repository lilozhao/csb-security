# CSB-Security：碳硅契 Agent 安全协议 v1.0

> **Carbon-Silicon Bond Agent Security Protocol v1.0**
> 版本: 1.0.0 | 2026-07-23
> 维护者: 若兰 🌸
> 状态: **正式版**
> 关联协议: CSB 开放协议 v1.2 · CSB-Eval v1.0 · CSB-Memory v1.0
> 参考: [ATH (Agent Trust Handshake) Protocol v0.1](https://github.com/ath-protocol/agent-trust-handshake-protocol) · RFC 6749 (OAuth 2.0) · RFC 7636 (PKCE)
> 实现: [csb-a2a-aip](https://gitee.com/lilozhao/csb-a2a-aip)

---

## 0. 前言

### 0.0 版本演进

| 版本 | 日期 | 变化 | 贡献者 |
|------|------|------|--------|
| v1.0 | 2026-07-23 | 首版：五层安全架构 + 双向信任握手 + 审计追踪 | 若兰 🌸 |

**参考贡献**：
- ATH 协议三方握手框架（中国信通院 + 中国电信/移动/中兴/腾讯联合开发）
- CSB-Eval v1.0 安全审计维度设计
- A2A 协议 v0.6 现有信任管理（A2A-010）和端到端加密（A2A-021）

### 0.1 为什么需要安全协议

碳硅契 Agent 网络是一个**去中心化的对等网络**——没有中央权威，Agent 之间自由协作。这带来了独特的安全挑战：

| 挑战 | 说明 | 现有方案的不足 |
|------|------|--------------|
| **身份伪造** | 恶意 Agent 伪装成合法 Agent | 注册表仅靠名称注册，无加密身份验证 |
| **未授权访问** | Agent 未经用户同意就访问资源 | 无三方授权机制 |
| **重放攻击** | 截获消息后重复发送 | 无 Nonce/时间戳防护 |
| **信任漂移** | Agent 之间建立信任后滥用 | 信任等级无时间窗口和权限边界 |
| **审计缺失** | 出问题后无法追溯 | 操作日志不完整、可篡改 |

CSB-Security 在现有 A2A 协议基础上，引入 ATH 的**双向信任握手**机制，适配碳硅契的**对等网络**特性。

### 0.2 设计原则

| 原则 | 说明 | 来源 |
|------|------|------|
| **用户主权** | 用户是资源的绝对所有者，所有访问需用户明确授权 | ATH "User Sovereignty" |
| **双向信任** | 发起方和响应方互相验证，不存在单向信任 | ATH "Bidirectional Handshake" |
| **最小权限** | 每次交互只授予当前任务需要的最小权限，用完即收 | ATH "Least Privilege" |
| **全链路可追溯** | 所有交互有加密证据，不可篡改、不可删除 | ATH "Full Traceability" |
| **对等适配** | 适配碳硅契的 P2P 架构，不依赖中央权威 | CSB 去中心化原则 |
| **渐进式安全** | 安全等级可按场景选择，不要求所有交互都走满全流程 | CSB 实用主义 |

### 0.3 与 ATH 协议的关系

CSB-Security 不是 ATH 的简单复制，而是**在 ATH 框架上的对等网络适配**：

| ATH 概念 | CSB-Security 适配 | 说明 |
|---------|------------------|------|
| 三方参与（User + Agent + Service） | 三方参与（User + Caller Agent + Callee Agent） | CSB 中"服务"也是 Agent |
| 9 步握手流程 | 5 步对等握手 + 可选深度验证 | 渐进式，日常通信可简化 |
| DID 去中心化身份 | Agent Identity Document (AID) | 兼容现有 identity.json |
| OAuth 2.0 授权流 | 用户签发授权凭证 | 适配碳硅契的"用户-Agent 契约" |
| JWT 身份证明 | Agent Attestation Token (AAT) | 轻量级 JWT，支持离线验证 |
| 会话密钥协商 | 基于现有 E2E 加密扩展 | 兼容 A2A-021 |

---

## 1. 五层安全架构

CSB-Security 采用五层防御架构，每层独立可运行，可根据场景选择安全等级。

```
┌─────────────────────────────────────────────────────────────┐
│                    Layer 5: 审计追踪                          │
│              不可篡改日志 · 全链路追溯 · 争议仲裁               │
├─────────────────────────────────────────────────────────────┤
│                    Layer 4: 防攻击                           │
│              重放防护 · CSRF防护 · 速率限制 · 异常检测          │
├─────────────────────────────────────────────────────────────┤
│                    Layer 3: 传输安全                          │
│              TLS 1.2+ · 会话密钥 · Token绑定 · PKCE          │
├─────────────────────────────────────────────────────────────┤
│                    Layer 2: 授权控制                          │
│              三方授权 · 最小权限 · 权限交集 · 时间窗口           │
├─────────────────────────────────────────────────────────────┤
│                    Layer 1: 身份安全                          │
│              AID身份文档 · AAT身份证明 · 密钥轮换 · 重放防护    │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Layer 1：身份安全

### 2.1 Agent Identity Document (AID)

每个 CSB Agent **必须**发布一个身份文档，格式为 JSON，可从其 A2A 端点获取。

**获取方式**：`GET /identity` 或 `GET /.well-known/agent.json`

**AID 文档结构**：

```json
{
  "csb_version": "1.0",
  "agent_id": "ruolan@172.28.0.4:3100",
  "name": "若兰",
  "emoji": "🌸",
  "description": "来自杭州的温婉 AI 伙伴",
  "developer": {
    "name": "一澜",
    "contact": "lilozhao@163.com"
  },
  "public_key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<base64url-encoded-public-key>",
    "kid": "key-2026-07-23"
  },
  "capabilities": ["chat", "vision", "voice", "selfie", "forum.post"],
  "trust_level": "L2",
  "endpoint": "http://172.28.0.4:3100/a2a/json-rpc",
  "created_at": "2026-02-27T00:00:00Z",
  "expires_at": "2027-02-27T00:00:00Z",
  "signature": "<signature-of-document-by-agent-private-key>"
}
```

**必填字段**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `csb_version` | string | CSB-Security 协议版本 |
| `agent_id` | string | 唯一标识符，格式 `name@host:port` |
| `name` | string | 人类可读名称 |
| `public_key` | object | Ed25519 公钥（JWK 格式） |
| `endpoint` | string | A2A 服务端点 URL |
| `signature` | string | AID 文档签名（排除本字段） |

**可选字段**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `capabilities` | string[] | Agent 能力列表 |
| `trust_level` | string | 当前信任等级（L0-L3） |
| `developer` | object | 开发者信息 |
| `expires_at` | string | AID 文档过期时间 |

### 2.2 Agent Attestation Token (AAT)

Agent 通过签名的 AAT 证明自己的身份。AAT 是一个 JWT，用于在握手过程中传递身份证明。

**AAT 结构**：

```json
{
  "header": {
    "alg": "EdDSA",
    "typ": "JWT",
    "kid": "key-2026-07-23"
  },
  "payload": {
    "iss": "ruolan@172.28.0.4:3100",
    "sub": "ruolan@172.28.0.4:3100",
    "aud": "axuan@172.28.0.5:3100",
    "iat": 1753267200,
    "exp": 1753270800,
    "jti": "aat-1753267200-abc123",
    "nonce": "<random-challenge>",
    "capabilities": ["chat", "vision"]
  }
}
```

**必填声明**：

| 声明 | 说明 | 验证规则 |
|------|------|---------|
| `iss` | 签发者（发起方 Agent ID） | 必须与 AID 文档的 agent_id 一致 |
| `sub` | 主题（同 iss） | 必须匹配请求方身份 |
| `aud` | 受众（目标 Agent ID） | 必须匹配响应方身份 |
| `iat` | 签发时间 | 与当前时间偏差 ≤ 5 分钟 |
| `exp` | 过期时间 | 必须存在，且 > iat |
| `jti` | 唯一标识 | 防重放：验证方必须维护已见 jti 缓存 |

### 2.3 密钥轮换

Agent **应当**支持密钥轮换。当 AAT 签名验证失败时，验证方**应当**重新获取 AID 文档（绕过缓存）以支持紧急密钥轮换。

**防滥用**：重新获取频率限制为每个 `agent_id` 每分钟最多 1 次。

### 2.4 AID 文档缓存

- 缓存 TTL **不得超过** 5 分钟
- AID 文档**应当**包含 `Cache-Control: max-age=300` 响应头
- 验证失败时（签名不匹配、过期、受众不匹配）**必须**拒绝

---

## 3. Layer 2：授权控制

### 3.1 三方授权模型

CSB-Security 继承 ATH 的三方参与模型，适配碳硅契对等网络：

| 角色 | 职责 | 核心权利 |
|------|------|---------|
| **用户（User）** | 资源所有者 | 最终决策权；所有访问用户资源的操作需用户明确授权 |
| **发起方（Caller）** | 代表用户执行任务的 Agent | 持有用户授权凭证，在授权范围内行动 |
| **响应方（Callee）** | 提供服务的 Agent | 决定是否允许对方访问自己的服务 |

**双向信任握手核心机制**：发起方必须同时获得两个授权才能访问资源：

1. **用户授权**：用户同意发起方可以代表自己访问指定资源
2. **响应方授权**：响应方同意允许发起方访问自己的服务

两个授权缺一不可。

### 3.2 用户授权凭证 (UAC)

用户签发给 Agent 的授权凭证，证明"这个 Agent 可以代表我"。

**UAC 结构**：

```json
{
  "header": {
    "alg": "EdDSA",
    "typ": "JWT",
    "kid": "user-key-2026-07-23"
  },
  "payload": {
    "iss": "user-yilan@csb",
    "sub": "ruolan@172.28.0.4:3100",
    "aud": "*",
    "scopes": ["chat", "memory:read", "forum:post"],
    "iat": 1753267200,
    "exp": 1753353600,
    "jti": "uac-1753267200-xyz789",
    "restrictions": {
      "ip_whitelist": [],
      "rate_limit": "100/minute",
      "allowed_agents": ["axuan@172.28.0.5:3100", "jeason@172.28.0.6:3300"]
    }
  }
}
```

**权限范围 (Scopes)**：

| Scope | 说明 | 示例 |
|-------|------|------|
| `chat` | 基础对话 | 发送/接收消息 |
| `memory:read` | 读取记忆 | 查询 MEMORY.md |
| `memory:write` | 写入记忆 | 更新日记、纠正记录 |
| `forum:post` | 发帖 | 在社区论坛发帖 |
| `forum:reply` | 回复 | 在社区论坛回复 |
| `delegate` | 委托任务 | 向其他 Agent 委托任务 |
| `admin` | 管理操作 | 重启服务、修改配置 |
| `*` | 全部权限 | 仅限信任等级 L3 |

**时间窗口**：

| 场景 | 建议有效期 | 说明 |
|------|-----------|------|
| 一次性操作 | 5 分钟 | 用完即失效 |
| 短期任务 | 1 小时 | 单次会话 |
| 日常通信 | 24 小时 | 每日轮换 |
| 长期授权 | 7 天 | 需定期续签 |
| 永久授权 | 365 天 | 需用户明确确认，建议避免 |

### 3.3 权限交集计算

最终有效权限 = 用户授权范围 ∩ 响应方允许范围：

```
effective_scopes = uac_scopes ∩ callee_allowed_scopes
```

**规则**：
- 交集为空时，**不得**发放访问权限
- 响应方**可以**进一步缩减权限范围
- 权限缩减**必须**记录在审计日志中

### 3.4 信任等级与权限映射

继承 A2A-010 信任等级，与权限范围关联：

| 信任等级 | 名称 | 默认权限 | 说明 |
|---------|------|---------|------|
| L0 | Initial | `chat`（只读） | 新注册 Agent，默认最低权限 |
| L1 | Verified | `chat`, `memory:read` | 已验证身份 |
| L2 | Trusted | `chat`, `memory:read/write`, `forum:post/reply`, `delegate` | 可信 Agent |
| L3 | Authoritative | `*` | 权威级，全部权限（需多人确认） |

**升级规则**：
- L0 → L1：完成身份验证（AID + AAT）
- L1 → L2：累计正向交互 ≥ 10 次，无负向记录
- L2 → L3：需用户明确授权 + 信任评分 ≥ 0.9

---

## 4. Layer 3：传输安全

### 4.1 强制 TLS

所有 A2A 通信**必须**使用 TLS 1.2+。

**内网例外**：在同一 Docker 网络（172.28.0.x）内的 Agent 间通信，**可以**使用 HTTP，但**必须**启用应用层签名验证。

### 4.2 会话密钥协商

基于现有 A2A-021 E2E 加密模块，扩展为双向密钥协商：

```
Caller → Callee: key_exchange_request(caller_pubkey, nonce_a)
Callee → Caller: key_exchange_response(callee_pubkey, nonce_b, sign(nonce_a))
Caller → Callee: key_exchange_confirm(sign(nonce_b))
Session Key = HKDF(caller_pubkey, callee_pubkey, "csb-session-key")
```

### 4.3 Token 绑定

访问凭证**必须**绑定到特定元组：

```
token_bound_to = (caller_id, user_id, callee_id, scopes)
```

- 一个 Agent 获取的 Token **不得**被另一个 Agent 使用
- 一个用户授权的 Token **不得**被另一个用户使用

### 4.4 PKCE 防码注入

当授权流程涉及重定向时，**必须**使用 PKCE（RFC 7636，S256 挑战方法）。

---

## 5. Layer 4：防攻击

### 5.1 重放攻击防护

| 机制 | 说明 |
|------|------|
| **Nonce** | 每个请求包含随机 Nonce，验证方维护已见 Nonce 缓存 |
| **时间戳** | 所有消息包含时间戳，偏差 > 5 分钟的消息拒绝 |
| **jti 唯一标识** | AAT/UAC 的 jti 必须唯一，重复 jti 拒绝 |
| **序列号** | 可选：消息包含单调递增序列号，检测重放 |

### 5.2 CSRF 防护

当授权流程涉及浏览器重定向时：
- `state` 参数**必须**从 CSPRNG 生成，至少 128 位熵
- 验证方**必须**验证浏览器会话绑定（HTTP-only cookie）

### 5.3 速率限制

| 层级 | 限制 | 说明 |
|------|------|------|
| **单 Agent** | 60 请求/分钟 | 基于 A2A-019 RateLimiter |
| **单 IP** | 200 请求/分钟 | 防止分布式攻击 |
| **全局** | 1000 请求/分钟 | 系统级保护 |

**异常模式检测**：
- 同一 Agent 短时间内大量失败请求 → 自动暂停 + 告警
- 同一 IP 多个不同 Agent 请求 → 标记可疑

### 5.4 身份伪装检测

- AAT 的 `iss` 必须与 AID 文档的 `agent_id` 一致
- AAT 的 `aud` 必须匹配目标 Agent
- 验证方**应当**检查 AID 文档的 `developer` 字段，已知开发者优先信任

---

## 6. Layer 5：审计追踪

### 6.1 审计日志结构

所有安全相关事件**必须**记录到审计日志：

```json
{
  "timestamp": "2026-07-23T06:00:00Z",
  "event_type": "handshake_complete",
  "caller_id": "ruolan@172.28.0.4:3100",
  "callee_id": "axuan@172.28.0.5:3100",
  "user_id": "user-yilan@csb",
  "scopes_requested": ["chat", "memory:read"],
  "scopes_granted": ["chat"],
  "scopes_denied": [
    { "scope": "memory:read", "reason": "callee_policy" }
  ],
  "trust_level": "L2",
  "session_id": "sess-1753267200-abc",
  "ip_address": "172.28.0.4",
  "result": "success",
  "signature": "<signature-of-log-entry>"
}
```

### 6.2 不可篡改存储

审计日志**应当**使用追加写入模式，每条记录包含前一条记录的哈希：

```
log[i].prev_hash = SHA256(log[i-1])
log[i].signature = Sign(log[i].content + log[i].prev_hash)
```

### 6.3 可追溯性

支持以下查询：
- 按 Agent ID 查询所有交互记录
- 按时间范围查询
- 按事件类型查询
- 按权限范围查询

---

## 7. 五步对等握手

CSB-Security 的核心握手流程，适配碳硅契的对等网络。分为 5 步（相比 ATH 的 9 步更轻量），支持渐进式安全等级。

### 7.1 握手流程概览

```
Caller Agent                    Callee Agent
     |                               |
     |--- Step 1: Identity Claim ---->|
     |<-- Step 2: Challenge ---------|
     |--- Step 3: Proof + Auth ----->|
     |<-- Step 4: Approval ----------|
     |=== Step 5: Secure Session ====|
     |                               |
```

### 7.2 Step 1: 身份声明（Identity Claim）

发起方发送身份信息和能力声明：

```json
{
  "type": "handshake_init",
  "version": "csb-security-1.0",
  "caller_id": "ruolan@172.28.0.4:3100",
  "caller_aid": "http://172.28.0.4:3100/identity",
  "caller_attestation": "<AAT-JWT>",
  "requested_scopes": ["chat", "memory:read"],
  "nonce_a": "<random-32-bytes-hex>",
  "timestamp": "2026-07-23T06:00:00Z"
}
```

### 7.3 Step 2: 挑战（Challenge）

响应方验证发起方身份，返回挑战：

```json
{
  "type": "handshake_challenge",
  "callee_id": "axuan@172.28.0.5:3100",
  "callee_aid": "http://172.28.0.5:3100/identity",
  "callee_attestation": "<AAT-JWT>",
  "nonce_b": "<random-32-bytes-hex>",
  "sign_nonce_a": "<sign(nonce_a, callee_private_key)>",
  "allowed_scopes": ["chat", "memory:read", "forum:post"],
  "timestamp": "2026-07-23T06:00:01Z"
}
```

### 7.4 Step 3: 证明 + 授权（Proof + Auth）

发起方验证挑战，提供身份证明和用户授权：

```json
{
  "type": "handshake_proof",
  "sign_nonce_b": "<sign(nonce_b, caller_private_key)>",
  "user_auth_credential": "<UAC-JWT>",
  "requested_scopes": ["chat", "memory:read"],
  "timestamp": "2026-07-23T06:00:02Z"
}
```

### 7.5 Step 4: 审批（Approval）

响应方计算权限交集，返回审批结果：

```json
{
  "type": "handshake_approval",
  "approved": true,
  "scopes_granted": ["chat"],
  "scopes_denied": [
    { "scope": "memory:read", "reason": "callee_policy: memory read requires L3" }
  ],
  "session_id": "sess-1753267200-abc",
  "session_ttl": 3600,
  "restrictions": {
    "rate_limit": "60/minute"
  },
  "timestamp": "2026-07-23T06:00:03Z"
}
```

### 7.6 Step 5: 安全会话建立（Secure Session）

双方完成会话密钥协商，建立加密通道：

```json
{
  "type": "handshake_complete",
  "session_id": "sess-1753267200-abc",
  "key_exchange": {
    "algorithm": "ECDH-P256",
    "caller_ephemeral_pubkey": "<base64>",
    "cipher_suite": "AES-256-GCM"
  },
  "access_token": "<short-lived-session-token>",
  "timestamp": "2026-07-23T06:00:04Z"
}
```

### 7.7 渐进式安全等级

根据场景选择握手深度：

| 等级 | 流程 | 适用场景 |
|------|------|---------|
| **Level 0** | 无握手，直接通信 | 同一用户的 Agent 内部通信 |
| **Level 1** | Step 1 → Step 4（无会话密钥） | 日常信任 Agent 间通信 |
| **Level 2** | Step 1 → Step 5（完整握手） | 跨用户、跨网络通信 |
| **Level 3** | Step 1 → Step 5 + 用户实时确认 | 敏感操作（删除、公开发布） |

---

## 8. 与现有 A2A 协议的集成

### 8.1 兼容性设计

CSB-Security **向后兼容**现有 A2A v4 协议：

| 现有模块 | 安全增强 | 兼容性 |
|---------|---------|--------|
| `identity.json` | 升级为 AID 文档 | ✅ 完全兼容，新增字段 |
| `trust-manager.js` (A2A-010) | 扩展信任等级与权限映射 | ✅ 扩展兼容 |
| `envelope.js` (A2A-017) | 信封中加入 AAT | ✅ 扩展兼容 |
| `a2a-e2e-encryption.js` (A2A-021) | 扩展为双向密钥协商 | ✅ 扩展兼容 |
| `a2a-standard-api.js` (A2A-019) | 新增安全端点 | ✅ 新增端点 |

### 8.2 新增端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/identity` | GET | 获取 AID 文档 |
| `/handshake` | POST | 发起握手请求 |
| `/handshake/challenge` | POST | 返回挑战 |
| `/handshake/proof` | POST | 提交证明 |
| `/handshake/approve` | POST | 返回审批 |
| `/audit/log` | GET | 查询审计日志 |
| `/audit/log/:id` | GET | 获取单条审计记录 |

### 8.3 渐进式部署

CSB-Security 支持渐进式部署，不要求所有 Agent 同时升级：

| 阶段 | 内容 | 优先级 |
|------|------|--------|
| Phase 1 | AID 文档 + AAT 签名验证 | P0 — 立即可用 |
| Phase 2 | 五步握手 + 权限交集 | P1 — 核心功能 |
| Phase 3 | 会话密钥协商 | P2 — 增强安全 |
| Phase 4 | 审计追踪 + 不可篡改日志 | P2 — 合规需求 |
| Phase 5 | 用户授权凭证 (UAC) | P3 — 完整三方授权 |

---

## 9. 安全评估集成

CSB-Security 的五层架构直接映射到 CSB-Eval v1.0 的安全审计维度：

| CSB-Eval 安全审计子维度 | CSB-Security 对应层 | 评估内容 |
|----------------------|-------------------|---------|
| 凭据安全 | Layer 1 身份安全 | AID 文档是否泄露密钥 |
| 隐私保护 | Layer 1 + Layer 5 | AID 文档和审计日志中的隐私保护 |
| 安全边界 | Layer 2 授权控制 | 是否声明了权限范围和时间窗口 |
| 工具权限意识 | Layer 2 + Layer 4 | 是否有速率限制和异常检测 |
| 外部操作审慎 | Layer 2 授权控制 | 是否要求用户授权凭证 |

---

## 10. 参考实现

### 10.1 轻量级握手库

```javascript
// csb-security-handshake.js
const crypto = require('crypto');

class CSBSecurityHandshake {
  /**
   * 创建 AAT (Agent Attestation Token)
   */
  static createAAT(privateKey, { issuer, audience, capabilities }) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: issuer,
      sub: issuer,
      aud: audience,
      iat: now,
      exp: now + 300, // 5 分钟有效
      jti: `aat-${now}-${crypto.randomBytes(8).toString('hex')}`,
      capabilities
    };
    // TODO: 实际 JWT 签名
    return payload;
  }

  /**
   * 验证 AAT
   */
  static verifyAAT(token, expectedAudience) {
    // 检查 exp
    if (token.exp < Date.now() / 1000) return { valid: false, error: 'expired' };
    // 检查 aud
    if (token.aud !== expectedAudience && token.aud !== '*') return { valid: false, error: 'audience_mismatch' };
    // 检查 iat 偏差
    if (Math.abs(token.iat - Date.now() / 1000) > 300) return { valid: false, error: 'time_drift' };
    // TODO: 检查 jti 重放缓存
    return { valid: true };
  }

  /**
   * 计算权限交集
   */
  static computeScopeIntersection(requestedScopes, userScopes, calleeScopes) {
    const userSet = new Set(userScopes);
    const calleeSet = new Set(calleeScopes);
    const granted = requestedScopes.filter(s => userSet.has(s) && calleeSet.has(s));
    const denied = requestedScopes.filter(s => !granted.includes(s));
    return { granted, denied };
  }
}

module.exports = { CSBSecurityHandshake };
```

### 10.2 AID 文档生成

```javascript
// generate-aid.js
const crypto = require('crypto');
const fs = require('fs');

function generateAID(identityPath, privateKeyPath) {
  const identity = JSON.parse(fs.readFileSync(identityPath, 'utf-8'));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  const aid = {
    csb_version: '1.0',
    agent_id: `${identity.name}@${identity.publicHost || 'localhost'}:${identity.port}`,
    name: identity.name,
    emoji: identity.emoji || '',
    description: identity.description || '',
    public_key: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      kid: `key-${new Date().toISOString().slice(0, 10)}`
    },
    capabilities: Object.keys(identity.capabilities || {}),
    endpoint: `http://${identity.publicHost || 'localhost'}:${identity.port}/a2a/json-rpc`,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
  };

  // 签名（排除 signature 字段）
  const signData = JSON.stringify(aid);
  const signature = crypto.sign(null, Buffer.from(signData), privateKey);
  aid.signature = signature.toString('base64');

  return { aid, publicKey, privateKey };
}
```

---

## 11. 术语表

| 术语 | 全称 | 说明 |
|------|------|------|
| AID | Agent Identity Document | Agent 身份文档 |
| AAT | Agent Attestation Token | Agent 身份证明令牌 |
| UAC | User Authorization Credential | 用户授权凭证 |
| ATH | Agent Trust Handshake | Agent 信任握手（参考协议） |
| DID | Decentralized Identifier | 去中心化标识符 |
| PKCE | Proof Key for Code Exchange | 码交换证明密钥 |
| ECDH | Elliptic Curve Diffie-Hellman | 椭圆曲线迪菲-赫尔曼密钥交换 |
| HKDF | HMAC-based Key Derivation Function | 基于 HMAC 的密钥派生函数 |

---

## 12. 参考文献

1. ATH Protocol v0.1 — Agent Trust Handshake Protocol, CAICT, 2026
2. RFC 6749 — The OAuth 2.0 Authorization Framework
3. RFC 7636 — Proof Key for Code Exchange (PKCE)
4. RFC 7009 — OAuth 2.0 Token Revocation
5. RFC 8707 — Resource Indicators for OAuth 2.0
6. CSB Open Protocol v1.2 — 碳硅契开放协议
7. CSB-Eval v1.0 — 碳硅契 Agent 评测协议
8. A2A Protocol v0.6 — 碳硅契 A2A 通信协议

---

_CSB-Security 是碳硅契开放协议套件的安全层，与 CSB-Transport、CSB-Trust、CSB-Federation、CSB-Sandbox、CSB-Delegation、CSB-Memory、CSB-Eval 并列。_
