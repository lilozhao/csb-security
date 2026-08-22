# CSB-Security 落地仓库规划（PLAN）

> **Carbon-Silicon Bond Agent Security Protocol — 落地实现规划**
> 规划日期: 2026-08-22 | 维护者: 若兰 🌸
> 对标: [csb-memory](https://gitee.com/lilozhao/csb-memory)（协议 → 独立仓库落地模式）
> 协议依据: `carbon-silicon-bond-protocol/protocol/csb-security-v1.0.md`

---

## 一、仓库定位

| 项 | 说明 |
|----|------|
| 仓库名 | `csb-security`（独立落地仓库，对标 csb-memory） |
| 协议 | CSB-Security v1.0（2026-07-23 正式版） |
| 语言 | Node.js ≥ 18（与 csb-memory / csb-a2a-aip 一致） |
| 测试框架 | node:test 轻量自研（与 csb-memory 的 run-all-tests.js 一致） |
| 目标 | 五层安全架构完整落地 + 五步握手 + 审计追踪，可被 csb-a2a-aip 集成 |

**协议 ↔ 落地对照（现状）**：

| 协议 | 落地仓库 | 状态 |
|------|---------|------|
| CSB-Memory v1.1 | csb-memory | ✅ 完整落地 |
| CSB-Eval v1.0 | csb-aep | ✅ 完整落地 |
| **CSB-Security v1.0** | **csb-security（新建）** | ⬜ 只有协议 + 817 行散落代码 |

---

## 二、目录结构（对标 csb-memory）

```
csb-security/
├── lib/                          # 核心实现
│   ├── identity/                 # Layer 1: 身份安全
│   │   ├── aid.js                #   AID 文档生成/签名/验证（收编协议 §10.2 generateAID）
│   │   ├── aat.js                #   AAT 签发/验证（收编协议 §10.1 createAAT/verifyAAT）
│   │   ├── key-rotation.js       #   密钥轮换 + AID 缓存（TTL ≤ 5min）
│   │   └── trust-level.js        #   L0-L3 信任等级 + 升级规则（收编 trust-manager.js 信任分级）
│   ├── authz/                    # Layer 2: 授权控制
│   │   ├── uac.js                #   用户授权凭证（签发/验证/scope 解析）
│   │   ├── scope-intersection.js #   权限交集计算（收编协议 §10.1 computeScopeIntersection）
│   │   └── reputation.js         #   声誉存储 + 信任评分（收编 trust/score.js）
│   ├── transport/                # Layer 3: 传输安全
│   │   ├── e2e-encryption.js     #   AES-256-GCM + HKDF（收编 a2a-e2e-encryption.js，扩展 ECDH）
│   │   ├── session-keys.js       #   双向密钥协商（协议 §4.2）
│   │   └── token-binding.js      #   Token 绑定 (caller,user,callee,scopes)
│   ├── defense/                  # Layer 4: 防攻击
│   │   ├── replay-guard.js       #   Nonce/时间戳/jti 重放防护
│   │   ├── rate-limiter.js       #   单 Agent 60/min · 单 IP 200/min · 全局 1000/min
│   │   └── anomaly-detector.js   #   异常模式检测（大量失败 → 暂停+告警）
│   ├── audit/                    # Layer 5: 审计追踪
│   │   ├── audit-log.js          #   追加写 + 哈希链（prev_hash）+ 签名
│   │   ├── audit-query.js        #   按 Agent/时间/事件/scope 查询
│   │   └── tamper-check.js       #   完整性校验（重算哈希链）
│   ├── handshake/                # 五步对等握手（核心编排）
│   │   └── handshake.js          #   init → challenge → proof → approval → complete
│   └── index.js                  # 统一入口（对标 csb-memory/lib/index.js）
├── data/                         # 运行时数据（.gitignore）
│   ├── audit/                    #   审计日志（哈希链存储）
│   ├── cache/                    #   AID 缓存 / nonce / jti 缓存
│   └── reputation/               #   声誉数据
├── docs/                         # 文档（UPGRADE 说明、集成指南）
├── examples/                     # 使用示例
│   ├── basic-handshake.js
│   ├── gen-aid.js
│   └── audit-report.js
├── protocol/                     # 协议文档副本（csb-security-v1.0.md）
├── scripts/                      # 日常脚本
│   ├── gen-aid.js                #   生成 AID + 密钥对
│   ├── rotate-keys.js            #   密钥轮换
│   ├── audit-report.js           #   审计报告生成
│   └── health-check.js           #   健康检查（对标 csb-memory/scripts/health-check.js）
├── test/                         # 测试（对标 csb-memory/test/）
│   ├── test-identity.js          #   Layer 1 测试
│   ├── test-authz.js             #   Layer 2 测试
│   ├── test-transport.js         #   Layer 3 测试
│   ├── test-defense.js           #   Layer 4 测试
│   ├── test-audit.js             #   Layer 5 测试（含篡改检测）
│   ├── test-handshake.js         #   五步握手全流程 + 渐进式等级
│   └── run-all-tests.js          #   统一测试入口
├── package.json
└── README.md
```

---

## 三、现有代码收编方案（817 行）

| 现有文件 | 行数 | 去向 | 改造点 |
|---------|------|------|--------|
| `csb-a2a-aip/trust-manager.js` | 376 | `lib/authz/trust-level.js` + `lib/authz/reputation.js` | 拆信任分级与声誉存储；补升级规则（L1→L2 需 10 次正向交互） |
| `csb-a2a-aip/a2a-e2e-encryption.js` | 184 | `lib/transport/e2e-encryption.js` | 保留 PSK 模式；新增 ECDH 双向协商（协议 §4.2） |
| `csb-a2a-aip/trust/demo.js` | 133 | `examples/`（改造为 handshake demo） | 演示脚本化 |
| `csb-a2a-aip/trust/score.js` | 124 | `lib/authz/reputation.js` | 并入声誉评分逻辑 |
| 协议 §10.1 参考实现 | ~60 | `lib/handshake/handshake.js` + `lib/identity/aat.js` | 补 JWT 真实签名（EdDSA）、jti 重放缓存 |

**收编原则**（对齐 csb-inheritance 暂停时的教训）：
- 收编后原文件保留兼容（csb-a2a-aip 继续可用），新仓库为权威实现
- 后续 csb-a2a-aip 改为 require('csb-security') 集成，逐步替换

---

## 四、协议五层 → 模块映射

| 协议章节 | 层 | 模块 | 落地状态 |
|---------|-----|------|---------|
| §2 身份安全 | Layer 1 | identity/ | ⬜ 新建（AAT 有参考实现） |
| §3 授权控制 | Layer 2 | authz/ | 🟡 部分（trust-manager 信任等级已有） |
| §4 传输安全 | Layer 3 | transport/ | 🟡 部分（E2E 加密已有，缺会话协商） |
| §5 防攻击 | Layer 4 | defense/ | ⬜ 新建 |
| §6 审计追踪 | Layer 5 | audit/ | ⬜ 新建（哈希链是核心） |
| §7 五步握手 | 编排 | handshake/ | ⬜ 新建（参考实现可作起点） |

**关键缺口（需从零写）**：audit/ 哈希链日志、defense/ 重放+限流、identity/aid.js、transport/session-keys.js

---

## 五、渐进式里程碑（协议 §8.3 部署阶段）

| 阶段 | 内容 | 优先级 | 预计测试用例 | 状态 |
|------|------|--------|-------------|------|
| **M1 (P0)** | identity/（AID + AAT + 密钥轮换 + 信任等级收编） | 立即可用 | ~25 | ✅ 39 用例 100% |
| **M2 (P1)** | handshake/ 五步握手 + authz/ 权限交集 + UAC | 核心功能 | ~20 | ✅ 33 用例（累计 72）100% |
| **M3 (P2)** | transport/ 会话密钥协商（ECDH）+ token 绑定 + PKCE | 增强安全 | ~15 | ✅ 33 用例（累计 105）100% |
| **M4 (P2)** | audit/ 哈希链审计 + defense/ 重放防护 + 限流 | 合规需求 | ~20 | ✅ 26 用例（累计 131）100% |
| M5 (P3) | defense/ 异常检测（规则引擎）+ 集成 csb-a2a-aip | 完整三方授权 | ~10 | ✅ 14 用例（累计 145）100% |

**M5 完成情况（2026-08-22）**：`lib/defense/anomaly-detector.js` 规则引擎落地
- 五条可配置规则：① 连续失败→暂停+告警 ② 同 IP 多 Agent→可疑 ③ 高频 AID 注册→告警 ④ 密钥轮换异常→告警 ⑤ 审计篡改→critical 单次触发
- 统一告警通道（onAlert 回调 + 告警历史）+ suspendFn 动作注入 + 滑动窗口
- 14 用例 100%（累计 145）

**csb-a2a-aip 集成进度（A+C 方案：optionalDependencies file: 依赖 + 降级加载）**：
- ✅ **Phase 1 等价替换（2026-08-22，commit 62a2f34）**：security-adapter.js + trust/e2e 换源 csb-security；回归 test-v4-full 10/10 + test-v4-compat 3/3 + test-v4 集成全过；五平台已推
- ⬜ Phase 2 增强替换（rate-limiter 按 Agent 限流 + audit 哈希链，feature flag）
- ⬜ Phase 3 新能力（/a2a/handshake 端点 + anomaly-detector 中间件）

**验收标准**（对标 csb-memory v1.1 的 110+ 用例）：
- 总测试用例 ≥ 90，通过率 100%
- 篡改审计日志 1 条 → tamper-check 必须检出
- 重放旧 AAT/jti → 必须拒绝
- 与 csb-memory 联动：审计日志支持 derived_from 溯源

---

## 六、与生态的关系

```
carbon-silicon-bond-protocol（协议套件·主仓）
├── protocol/csb-security-v1.0.md   ← 协议定义
└── 落地实现
    ├── csb-memory      → 记忆安全（隐私层、derived_from）
    ├── csb-aep         → 评测安全（安全审计维度 §9）
    └── csb-security    → 🆕 安全落地（五层 + 握手 + 审计）
```

- **集成方**：csb-a2a-aip（A2A 通信引擎）将 require csb-security 作为安全中间件
- **联动**：审计日志 = CSB-Memory RAW 层的证据底座（灰火三态 sealed 标记）

---

## 七、仓库信息（2026-08-22 已建库）

| 平台 | 地址 | 状态 |
|------|------|------|
| Gitee（主仓） | https://gitee.com/lilozhao/csb-security | ✅ 已建 |
| GitCode | https://gitcode.com/lilozhao11/csb-security | ✅ 已建 |
| 腾讯云 cnb | https://cnb.cool/ebatom/csb-security | ✅ 已建 |
| GitHub | https://github.com/lilozhao/csb-security | ✅ 已建 |

本地远程已配置：origin(Gitee) / gitcode / cnb / github

## 八、待确认事项

1. ~~仓库托管~~ ✅ 已确认（四平台已建库，2026-08-22）
2. M1 启动时间：规划确认后立即开始？
3. 是否同步推送到 csb-a2a-aip 协议组讨论（对标 CSB-Memory 的三轮讨论流程）？
