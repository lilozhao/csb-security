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
| M4 (P2) | 哈希链审计 + 重放防护 + 限流 | ⬜ |
| M5 (P3) | 异常检测 + 集成 csb-a2a-aip | ⬜ |

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
│   └── scope-intersection.js  权限交集（granted/denied + 原因）
├── handshake/          五步对等握手
│   └── handshake.js    init→challenge→proof→approval→complete + 渐进式等级
├── transport/           Layer 3: 传输安全
│   ├── e2e-encryption.js  AES-256-GCM + HKDF（收编自 A2A-021，PSK + ECDH 密钥）
│   ├── session-keys.js    ECDH-P256 双向密钥协商（协议 §4.2）
│   ├── token-binding.js   Token 绑定元组 (caller,user,callee,scopes)（协议 §4.3）
│   └── pkce.js            PKCE S256（协议 §4.4 / RFC 7636）
└── index.js            统一入口
test/                   测试（node test/run-all-tests.js）
examples/               使用示例
protocol/               协议文档副本
```

## 设计要点（协议对齐）

- **AID**：Ed25519 签名，JWK 格式公钥，必填字段校验，365 天有效期（协议 §2.1）
- **AAT**：JWT 三段式，exp 必须存在，iat 偏差 ≤ 5 分钟，jti 防重放（协议 §2.2）
- **密钥轮换**：AID 缓存 TTL ≤ 5 分钟；验证失败强制重新获取，限流 1 次/分钟/Agent（协议 §2.3/2.4）
- **信任等级**：L0→L1 需身份验证；L1→L2 需 ≥10 次正向无负向；L2→L3 需用户授权 + 声誉 ≥0.9（协议 §3.4）
- **UAC**：用户签发 JWT，sub 绑定 Agent（Token 绑定），scopes + restrictions（allowed_agents/rate_limit），时间窗口常量（协议 §3.2）
- **权限交集**：effective = UAC scopes ∩ callee scopes，交集为空不得发放，拒绝带原因（user_policy/callee_policy）（协议 §3.3）
- **五步握手**：init→challenge→proof→approval→complete，双向 nonce 签名验证，AAT+UAC 双重校验，时间戳偏差 >5min 拒绝，nonce 重放防护（协议 §7）
- **渐进式等级**：L0 无握手 / L1 到 approval / L2 完整 + complete / L3 用户实时确认（协议 §7.7）
- **会话密钥**：ECDH-P256 双向协商，HKDF-SHA256 派生（info="csb-session-key"），sign(nonce) 双向验证，nonce 重放防护（协议 §4.2）
- **Token 绑定**：token_bound_to=(caller,user,callee,scopes)，任一变化失效，timing-safe 比较（协议 §4.3）
- **PKCE**：S256 challenge（RFC 7636 附录 B 验证），state ≥128 位熵（协议 §4.4）
- **E2E 加密**：AES-256-GCM 认证加密，HKDF 密钥派生按 Agent 隔离，支持 PSK（收编）与 ECDH 会话密钥（协议 §4）

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
