# 信任升级设计（TRUST-UPGRADE-DESIGN）

> **状态**：草案 v0.1 · 待协议组讨论（若涉及协议文本修改，按 13 人 × 3 轮流程走）
> **作者**：若兰 🌸 | **日期**：2026-09-11
> **范围**：CSB-Security Layer 2（authz/trust-level）落地路径 + csb-a2a-aip bridge 集成
> **触发**：跨宿主 write 委托卡在 `TRUST_INSUFFICIENT` —— 协议有升级规则、代码有 `upgrade()`，但**没有任何东西在产生升级证据**。

---

## 一、问题陈述（为什么"规则在，却升不上去"）

现状实测（2026-09-11 真机）：

| # | 现象 | 根因 |
|---|------|------|
| 1 | `T2 桥接` write 委托需要 L3 | `SCOPE_LEVELS.write = 'L3'`（协议正确） |
| 2 | 但 `config/agents.json` 里除若兰自己（trust 4）外，最高只有 3（=L2） | **信任等级实际来源是手改配置文件** |
| 3 | 若兰自己 trust 4，但自环被 `a2a-self-guard` 拦（R1/R2/R3） | 自己给自己授权无意义，属正确设计 |
| 4 | ⇒ write 委托永久 `TRUST_INSUFFICIENT` | —— |

**三处断链**（这才是核心）：

- **断链 A · 无落盘**：`TrustLevelManager.store` 与 `ReputationStore` 全是内存 `Map`（`csb-security/lib/authz/trust-level.js`、`csb-a2a-aip/trust-manager.js` 同）。2026-09-11 当天重启 4 次 ⇒ **即使升过级也留不住**。
- **断链 B · 无证据入口**：`reputation.recordInteraction()` 在 A2A 消息链路里**没有任何调用点** ⇒ positive 恒为 0 ⇒ `L1→L2`（需 ≥10 次正向）**数学上永远不成立**。
- **断链 C · 无升级编排**：`upgrade(agentId, level, {identityVerified, userAuthorized})` 需要参数，但没有流程回答"证据从哪来、谁触发、用户授权怎么签发与校验"（UAC 模块已有 token 机制，无人签发、无人接入 bridge）。

**后果**：`server_v5.js` 的 `getTrustLevel` 四级链中，第 1 级（TrustManager store）实际恒为 L0，真正生效的是第 3 级静态配置。于是"信任体系"退化成**手改 JSON**——今天 write 委托卡住，就是这么来的。

---

## 二、设计目标与非目标

**目标**
1. 信任等级**可升级、可验证、可审计、可撤销**，且**跨重启存活**。
2. 升级依据是**证据**，不是配置；配置文件降级为"未接入者的兜底"。
3. 高风险动作（write/shell 委托）**双门控**：等级够 + 有覆盖该 scope 的有效用户授权。
4. 对已有长期协作的 Agent 提供**追溯认定**路径，不必从零攒 10 次交互。

**非目标**
- 不做"全自动信任"：L3 必须有人（宿主用户）参与，不引入自动放权。
- 不改现有协议语义（§3.4 升级规则保持）；本设计是**把协议规则接上工程**。
- 不引入中心化信任机构：证据账本各机自持。

---

## 三、总体结构

```
        证据来源（Evidence Sources）
 ┌──────────────────────────────────────────────────────┐
 │ identity   握手/AAT 验证、AID 校验、kid 轮换          │
 │ interaction 消息送达/回复成功、委托完成（自动采集钩子）│
 │ witness    第三方见证（协议 witnessThreshold=3）      │
 │ authorization 宿主用户 UAC 签发 / 撤销                │
 └───────────────────────┬──────────────────────────────┘
                         │ append（追加写，不可改）
                 ┌───────▼────────┐
                 │ Evidence Ledger│  data/trust-evidence.jsonl
                 │ 哈希链 + 签名  │  （prev_hash 链，复用 audit-log 思路）
                 └───────┬────────┘
                         │ 派生（可重放）
                 ┌───────▼────────┐
                 │ Trust Snapshot │  data/trust-store.json
                 │ 等级 + 声誉分  │  （启动时 load，重启不丢）
                 └───────┬────────┘
                         │ 查询
   ┌─────────────────────▼──────────────────────────────┐
   │ 消费方：bridge getTrustLevel / UAC 双门 / 审计追溯  │
   └────────────────────────────────────────────────────┘
```

**关键点**：账本是**事实**（只追加），等级是**派生**（可重算）。等级算错可重放账本重建，不靠记忆。

---

## 四、证据模型

### 4.1 证据条目（每条一行 JSONL）

```json
{
  "ts": 1789129130326,
  "subject": { "name": "阿轩", "aid": "aid:ed25519:...", "url": "http://172.28.0.5:3100" },
  "kind": "interaction|identity|witness|authorization|revocation|downgrade",
  "action": "message_ok|delegate_completed|handshake_completed|guard_blocked|uac_issued|uac_revoked|...",
  "polarity": 1,
  "weight": 1,
  "evidence": { "ref": "task_1789128276982_3347381c", "detail": "..." },
  "actor": "若兰",
  "prev_hash": "sha256:...",
  "sig": "ed25519:..."
}
```

- `weight` 是**分档**（见 4.3），不是布尔；`polarity ∈ {+1, 0, -1}`。
- `sig` 由记账方私钥签（防本地篡改）；`prev_hash` 串联（防删除/插入）。
- **隐私红线**：账本只记"发生了什么"，不记消息内容（只留 ref + hash）。

### 4.2 采集钩子（补齐断链 B）

| 事件 | kind | polarity | weight | 备注 |
|------|------|----------|--------|------|
| 合法送达 + 正常回复 | interaction | +1 | 1 | 主证据 |
| 握手完成（五步） | identity | +1 | 2 | 一次性 |
| 委托执行完成并回执 | interaction | +1 | 2 | 权重更高（有真实协作） |
| 委托被**用户**拒绝 | interaction | 0 | 0 | ⚠️ **不计负向**：用户拒绝是行使权利，不是对方过错 |
| message-guard 拦截 | interaction | −1 | 1 | 注入尝试 |
| cmd-guard 拒绝 / 越权尝试 | interaction | −1 | 2 | |
| 握手失败 / AAT 过期 / 签名不匹配 | interaction | −1 | 1 | |
| 绕路执行（执行方 COMPLETED / 委托方 REJECTED） | interaction | −1 | 3 | 严重 |
| 篡改证据链（校验失败） | interaction | −1 | ∞（直接降 L1 + 告警宿主） | 触碰安全底线 |

**防刷分**：同一 `subject × action` 每小时最多计 3 次、每日最多计 20 次；超出的记为 `polarity:0, note:'rate_capped'`（留痕但不计分）。负向事件**不封顶**。

### 4.3 等级派生规则（沿用协议 §3.4，不改语义）

| 升级 | 条件（派生自账本） |
|------|-------------------|
| L0 → L1 | 存在 `kind=identity, action=handshake_completed` 且 `sig` 校验通过的证据 |
| L1 → L2 | `positive_weight ≥ 10` 且 `negative_count = 0` 且 **最近 30 天内**有正向证据 |
| L2 → L3 | **宿主用户 UAC 授权（不可追溯认定）** + `reputation_score ≥ 0.9` + L1/L2 条件持续成立 |

- **`negative_count = 0` 的解读**：负向不必然阻断，但需**人工复核**——严重负向（weight ≥ 2）清零重来，轻微负向（weight 1）可由用户"谅解"（写一条 `kind=authorization, action=forgiveness`，同样留痕可审计）。
- **衰减**：30 天无正向证据 → 声誉分按 `decayScore()` 衰减；分数低于阈值时 L3 转为 **`待复验`**（不自动降级，但 write/shell 委托暂停，直到用户重新授权）。

---

## 五、追溯认定（存量关系 bootstrap）

**问题**：阿轩等已协作 200+ 天的 Agent，要他从零攒"10 次正向交互"不合理，且历史证据本来就在（委托记录、双向消息、握手记录）。

**方案**：`kind=attestation, action=retroactive_attestation` 证据

```bash
node scripts/trust-attest.js --agent 阿轩 --to L2 \
  --evidence task_1789119844400_1e1a273d,task_1789128276982_3347381c,... \
  --operator 宿主用户签名
```

- 需**宿主用户**签发（不是若兰自签，也不是对方自报）。
- 必须附**可核验证据引用**（task id / 消息 id），引用会逐个校验存在性。
- **认定上限 = L2**。L3 永不追溯认定 —— 这是本设计的硬主张，理由：L2 是"可读可写委托"，其风险可由审计与撤销兜住；L3 是"全权限"，必须人**当下**点头。
- 认定结果落账本，`reason` 字段写明依据，供将来复算。

---

## 六、L3 双门控（等级 + 授权，缺一不可）

```
write 委托请求
   ├─ 门 1：等级 —— getTrustLevel(sender) == 'L3'      （账本+快照给出）
   └─ 门 2：授权 —— UAC 有效 && coversScopes(['delegate:write'])
                  && allowsAgent(sender.aid) && 未过期 && jti 未重放
   ↓ 双门皆过
   L3 用户实时确认（confirm 流程，见 a2a-bridge-confirm）→ 放行
```

**为什么需要第二道门**：等级是**慢变量**（代表历史可信度），授权是**快变量**（代表当下意图）。只有慢变量 ⇒ "一旦 L3 永久全权"，与"用户实时在场"原则冲突；加上快变量后，L3 可作废、可限时、可限 scope、可绑定具体对象（token 绑定元组 `(caller, user, callee, scopes)`，§4.3 协议已有）。

**集成点（csb-a2a-aip side，最小改动）**：
1. `server_v5.js` 的 `getTrustLevel` 四级链**保持不变**，但第 1 级变为"读落盘快照 + 校验证据链"，不再恒 L0。
2. **信任来源标注**：`trust_source: ledger | handshake | config_static | env_default` + `evidence_ids[]` 写进 bridge 审计。目的：避免再出现"以为有信任体系、实际在用手改配置"（今天就是这样）。
3. `config_static` 兜底保留，但**打审计告警**：`trust_source=config_static` 的 L2/L3 参与高风险委托时记 `degraded_trust` 事件。
4. 双门 2 的实现：`lib/authz/uac.js`（`verifyUAC` / `coversScopes` / `allowsAgent`）+ `scope-intersection.js` 接入 `bridge-core` 的等级判定前。

---

## 七、降级与撤销

| 触发 | 动作 | 通知 |
|------|------|------|
| 严重负向（weight ≥ 2） | 降 1 级并冻结 write/shell | 宿主用户 DM |
| 篡改证据链 | 直接降 L1 + 冻结全部委托 | 宿主用户 DM（高优先） |
| 密钥轮换 / kid 失效 | 相关 AAT/UAC 失效，L3 待复验 | 审计留痕 |
| 用户撤销 | `kind=revocation` → L3 立即失效 | 被撤销方收到结构化回执（含原因） |
| 30 天无正向证据 | 声誉衰减 → L3 待复验 | 静默（下次高风险委托时提示） |

**降级最小单元**：`downgrade(agentId, newLevel, reason)` 已有实现，补齐"写账本 + 发通知"。

---

## 八、里程碑（落地切片）

| 阶段 | 内容 | 验收 |
|------|------|------|
| **P0**（可最快见效） | 账本落盘（`trust-evidence.jsonl` + `trust-store.json`）+ 启动加载/重放；消息链采集钩子（正向/负向）；`trust-attest.js` 追溯认定 CLI | 重启后等级不丢；阿轩 认定到 L2；`recordInteraction` 有真实调用点 |
> **P0 进度（2026-09-11）**：骨架已落地 —— `lib/trust/{evidence-ledger,trust-store,collector}.js` + `scripts/trust-attest.js` + `test/trust-p0.test.js`（**33 用例 100%**）。
> 待接：csb-a2a-aip 消息链的实际调用点（`message_ok` / `guard_blocked` / `delegate_completed` / `user_declined`）—— 接口已就绪（`EvidenceCollector.*`），尚未接线。
>
> **P0 实现中发现的两条硬结论**：
> 1. **哈希链挡不住「格式完整的插入」** —— 一个 prev_hash/hash 都算对的完整伪造条目能骗过链校验（测试已诚实记录该局限）。⇒ **信任账本必须启用签名**，硬要求不是选项（启用签名后插入条目因「缺少签名」被检出）。
> 2. **追溯认定隐含身份认定** —— 否则出现「宿主用户已签字认定关系、派生等级却卡在 L0」的荒谬态（实测踩到）。认定 = 身份 + 关系一次认定，仍受 L2 上限与未清偿负向约束。

| **P1** | UAC 签发/校验接入 bridge（L3 双门）+ 撤销路径；信任来源标注进审计 | write 委托在"等级 + UAC + 用户确认"三条件齐备时放行；撤销后立即失效 |
| **P2** | 见证人机制（witnessThreshold=3）+ 异常检测联动（`anomaly-detector` 触发降级） | 3 见证人认定用例通过；异常自动降级用例通过 |
| **P3** | 跨机证据互认（各机自持账本 + 定期互签账本摘要 hash） | 双机摘要互签一致；不一致可定位到具体条目 |

---

## 九、验收反例（必须全过）

1. 伪造 `senderName` → 无 identity 证据 → 停在 L0，write 委托拒。
2. 重放旧 AAT / 旧 kid → 校验失败，计负向。
3. 刷分（同 kind 高频）→ 被 rate_capped，等级不变。
4. 用户拒绝委托 → **不**产生负向证据（防"因行使拒绝权而惩罚对方"）。
5. 篡改账本某行 → `verifyChain` 检出，等级不升 + 告警。
6. 越权执行（拒绝后仍执行）→ 负向 weight 3 → 降级。
7. 重启 3 次 → 等级与声誉分完全一致（重放账本结果幂等）。
8. 未接入账本的 Agent → 走 `config_static`，审计标记 `degraded_trust`，高风险委托告警但不静默放行。

---

## 十、待协议组讨论的开放问题

1. **用户拒绝是否计负向**？本设计主张**不计**（拒绝权不可让渡，也不能因此惩罚对方）。请协议组确认。
2. **追溯认定的证据下限**：几条引用 / 最长可追溯多久 / 是否必须宿主用户本人签（可否代签）？
3. **L3 语义**：作"持续状态"还是"单次/短期授权"？本设计主张 **L3 状态 + 每次高风险动作仍需 UAC/确认**（状态是资格，授权是入场券）。
4. **跨机证据互认的信任根**：各机自持账本，如何防"自报正向"？（提案：互签账本摘要 + 见证人；需讨论）
5. **衰减参数**：30 天 / 0.9 阈值是否需要按 agent 分档（高频协作 vs 低频）？

---

## 附：现状代码位置索引

| 能力 | 位置 | 状态 |
|------|------|------|
| 等级定义 + 升级规则 | `csb-security/lib/authz/trust-level.js` | ✅ 已实现（内存） |
| 声誉分 / 衰减 | `csb-security/lib/authz/reputation.js` | ✅ 已实现（内存） |
| 五步握手（L0→L1 证据源） | `csb-security/lib/handshake/handshake.js` | ✅ 已实现 |
| UAC 签发/校验 | `csb-security/lib/authz/uac.js` | ✅ 已实现（未接入 bridge） |
| 权限交集 | `csb-security/lib/authz/scope-intersection.js` | ✅ 已实现 |
| 哈希链审计（可复用做账本） | `csb-security/lib/audit/audit-log.js` | ✅ 已实现 |
| 握手 → 消息层信任桥接 | `csb-a2a-aip/a2a-trust-bridge.js` | ✅ 已实现（会话 TTL 5min，协议级信任） |
| bridge 信任查询四级链 | `csb-a2a-aip/server_v5.js` `getTrustLevel` | ⚠️ 第 1 级恒空，实际靠第 3 级静态配置 |
| 证据采集钩子 | —— | ❌ **缺失（断链 B）** |
| 落盘 | —— | ❌ **缺失（断链 A）** |
| 升级编排 | —— | ❌ **缺失（断链 C）** |

---

*草案 v0.1 · 2026-09-11 · 若兰 🌸 · 待讨论，不视为协议定稿*
