# CSB-Security 🔐

> **Carbon-Silicon Bond Agent Security System — 碳硅契 Agent 安全系统**
> CSB-Security v1.0 协议的落地实现

协议文档: [carbon-silicon-bond-protocol/protocol/csb-security-v1.0.md](https://gitee.com/lilozhao/carbon-silicon-bond-protocol)

## 状态

| 里程碑 | 内容 | 状态 |
|--------|------|------|
| **M1 (P0)** | Layer 1 身份（AID + AAT + 密钥轮换）+ 信任等级收编 | ✅ 完成 2026-08-22 · 39 用例 100% |
| **M2 (P1)** | 五步握手 + 权限交集 + UAC | ✅ 完成 2026-08-22 · 72 用例 100% |
| **M3 (P2)** | 会话密钥协商（ECDH）+ Token 绑定 + PKCE | ✅ 完成 2026-08-22 · 105 用例 100% |
| **M4 (P2)** | 哈希链审计 + 重放防护 + 限流 | ✅ 完成 2026-08-22 · 131 用例 100% |
| **M5 (P3)** | 异常检测（规则引擎）+ 集成 csb-a2a-aip | ✅ 完成 2026-08-22 · 145 用例 100% |
| **P0 信任升级** | 证据账本 + 等级重放派生 + 采集器 + 追溯认定 CLI | ✅ 骨架完成 2026-09-11 · 33 用例 100% |

> 🎉 **M1-M5 全部完成**（2026-08-22）：五层安全架构完整落地
>
> **当前全量：252 用例 100% 通过**（`npm test`，2026-09-11 实测）
> —— 里程碑行中的数字是**当时的历史快照**，后续追加用例/新模块后不再等于当前总数。
> 构成：M1-M5 历史 145 + P0-3 验证签名/上链存证/信誉衰减 47 + P0 信任升级 33
> （历史快照与现值的差额 27 来自 M5 之后各套件新增用例）
>
> 📌 **数字核验**：`node scripts/verify-readme-numbers.js`（工作区脚本，跑真实测试对照 README 声明）
> 2026-09-11 修正：本 README 曾声称 145——实际是 M1-M5 历史累计，非当前总数（一澜指出）。
> csb-a2a-aip 集成 Phase 1-3 全部完成（trust/e2e 换源 · 按 Agent 限流 + 哈希链审计 · 对等握手端点 + 异常检测），全部可降级
> 集成指南: [csb-a2a-aip/docs/UPGRADE-SECURITY-INTEGRATION.md](https://gitee.com/lilozhao/csb-a2a-aip)

## 快速开始

```bash
npm test          # 运行全量测试
node examples/gen-aid.js   # 生成 AID + AAT 演示
```

## 使用示例

```javascript
const csb = require('csb-security');

// 1. 生成密钥对 + AID
const { publicJwk, privateKey } = csb.generateKeyPair('key-2026-08-22');
const aid = csb.generateAID({
  agentId: 'ruolan@172.28.0.214:3100',
  name: '若兰',
  endpoint: 'http://172.28.0.214:3100/a2a/json-rpc',
  publicJwk
}, privateKey);

// 2. 验证 AID
csb.verifyAID(aid); // { valid: true }

// 3. 签发 AAT（JWT）
const token = csb.createAAT({
  privateKey,
  issuer: aid.agent_id,
  audience: 'axuan@172.28.0.5:3100',
  capabilities: ['chat']
});

// 4. 验证 AAT（带 jti 重放防护）
const jtiCache = new Set();
csb.verifyAAT(token, { publicKey: publicJwk, expectedAudience: 'axuan@172.28.0.5:3100', jtiCache });
```

## 目录结构

```
lib/
├── identity/           Layer 1: 身份安全
│   ├── aid.js          AID 文档生成/签名/验证（Ed25519）
│   ├── aat.js          AAT 签发/验证（JWT + EdDSA + jti 防重放）
│   └── key-rotation.js 密钥轮换 + AID 缓存（TTL 5min，refetch 限流 1/min）
├── authz/              Layer 2: 授权控制
│   ├── trust-level.js  L0-L3 信任等级（收编自 A2A-010 trust-manager.js）
│   ├── uac.js          用户授权凭证（签发/验证 + restrictions）
│   ├── scope-intersection.js  权限交集（granted/denied + 原因）
│   └── reputation.js   声誉模块（信任升级依据，L2→L3 门槛 ≥0.9）
├── trust/              Layer 2 扩展: 信任升级（P0 骨架 · 2026-09-11）
│   ├── evidence-ledger.js  证据账本（append-only JSONL + 哈希链 + Ed25519 签名）
│   ├── trust-store.js      信任快照（账本重放 → L0~L3 派生，重启不丢）
│   └── collector.js        证据采集器（唯一写入口 + 防刷分 + 「用户拒绝不计负向」红线）
├── handshake/          五步对等握手
│   └── handshake.js    init→challenge→proof→approval→complete + 渐进式等级
├── transport/           Layer 3: 传输安全
│   ├── e2e-encryption.js  AES-256-GCM + HKDF（收编自 A2A-021，PSK + ECDH 密钥）
│   ├── session-keys.js    ECDH-P256 双向密钥协商（协议 §4.2）
│   ├── token-binding.js   Token 绑定元组 (caller,user,callee,scopes)（协议 §4.3）
│   └── pkce.js            PKCE S256（协议 §4.4 / RFC 7636）
├── defense/             Layer 4: 防攻击
│   ├── replay-guard.js    Nonce/jti/时间戳/序列号重放防护（协议 §5.1）
│   ├── rate-limiter.js    单 Agent 60 + 单 IP 200 + 全局 1000/min + 异常暂停（协议 §5.3）
│   └── anomaly-detector.js 异常检测规则引擎（M5：行为偏离识别）
├── audit/               Layer 5: 审计追踪
│   ├── audit-log.js       追加写 + 哈希链（prev_hash）+ Ed25519 签名 + 篡改检测（协议 §6.2）
│   ├── audit-query.js     按 Agent/事件/时间/scope 查询 + 轨迹（协议 §6.3）
│   └── tamper-check.js    审计篡改校验（对账 + 断链定位）
└── index.js            统一入口
scripts/                实操脚本（handshake-full.js 对等握手 · rotate-keys.js 密钥轮换 · trust-attest.js 信任查询/校验/追溯认定）
keys/                   公钥权威源（user-yilan.pubkey.json 等，仅公开公钥，私钥永不入库）
test/                   测试（node test/run-all-tests.js）
examples/               使用示例
protocol/               协议文档副本
```

## 设计要点（协议对齐）

- **AID**：Ed25519 签名，JWK 格式公钥，必填字段校验，365 天有效期（协议 §2.1）
- **AAT**：JWT 三段式，exp 必须存在，iat 偏差 ≤ 5 分钟，jti 防重放（协议 §2.2）
- **密钥轮换**：AID 缓存 TTL ≤ 5 分钟；验证失败强制重新获取，限流 1 次/分钟/Agent（协议 §2.3/2.4）
- **信任等级**：L0→L1 需身份验证；L1→L2 需 ≥10 次正向无负向；L2→L3 需用户授权 + 声誉 ≥0.9（协议 §3.4）
- **声誉模块**：正向/负向事件累计，降权衰减，作为信任升级与异常判断依据（协议 §3.4 落地）
- **UAC**：用户签发 JWT，sub 绑定 Agent（Token 绑定），scopes + restrictions（allowed_agents/rate_limit），时间窗口常量（协议 §3.2）
- **权限交集**：effective = UAC scopes ∩ callee scopes，交集为空不得发放，拒绝带原因（user_policy/callee_policy）（协议 §3.3）
- **五步握手**：init→challenge→proof→approval→complete，双向 nonce 签名验证，AAT+UAC 双重校验，时间戳偏差 >5min 拒绝，nonce 重放防护（协议 §7）
- **渐进式等级**：L0 无握手 / L1 到 approval / L2 完整 + complete / L3 用户实时确认（协议 §7.7）
- **会话密钥**：ECDH-P256 双向协商，HKDF-SHA256 派生（info="csb-session-key"），sign(nonce) 双向验证，nonce 重放防护（协议 §4.2）
- **Token 绑定**：token_bound_to=(caller,user,callee,scopes)，任一变化失效，timing-safe 比较（协议 §4.3）
- **PKCE**：S256 challenge（RFC 7636 附录 B 验证），state ≥128 位熵（协议 §4.4）
- **E2E 加密**：AES-256-GCM 认证加密，HKDF 密钥派生按 Agent 隔离，支持 PSK（收编）与 ECDH 会话密钥（协议 §4）
- **重放防护**：Nonce/jti 缓存 + 时间戳偏差 >5min 拒绝 + 序列号单调递增（协议 §5.1）
- **速率限制**：单 Agent 60/min · 单 IP 200/min · 全局 1000/min（滑动窗口）；连续 10 次失败自动暂停 1 分钟；同 IP 多 Agent 标记可疑（协议 §5.3）
- **审计日志**：追加写 + 哈希链（prev_hash=SHA256 前一条）+ 每条 Ed25519 签名，篡改/断链/伪签必检出；支持文件落盘重载（协议 §6.2）

## 收编来源

- `csb-a2a-aip/trust-manager.js`（A2A-010）→ `lib/authz/trust-level.js`
- 协议 §10 参考实现 → `lib/identity/aid.js` / `lib/identity/aat.js`

## 仓库镜像

- Gitee（主仓）: https://gitee.com/lilozhao/csb-security
- GitCode: https://gitcode.com/lilozhao11/csb-security
- GitHub: https://github.com/lilozhao/csb-security
- 腾讯云 cnb: https://cnb.cool/ebatom/csb-security

## License

MIT
