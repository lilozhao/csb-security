# CHANGELOG · csb-security

## v1.1.0（2026-11-03）— E2E 三态 + 验签不再默认通过（P0-4）

### 背景

本仓 `lib/transport/e2e-encryption.js` 是**权威实现**（`csb-a2a-aip/security-adapter.js` 优先加载本仓），
所以 P0-4 的三态改造必须落在这里 —— 改 a2a-aip 那份 legacy 拷贝不生效。

三处假绿（详见 `csb-a2a-aip/docs/e2e-honest-degrade-p0-4.md`）：
出站只置布尔不加密 · `/health` 按 enabled 报绿 · 无密钥时验签直接通过。

### 变更

- 新增 `getStatus()` → `{status, reason}`，三态：`enabled` / `degraded` / `disabled`
- 新增 `verifySignatureDetailed()` → `{valid, reason}`，四种 reason：`no_master_key` / `signature_missing` / `signature_length_mismatch` / `signature_mismatch`
- `verifySignature()` 改回布尔语义，**无密钥不再 return true**
- `getStats()` 增 `status` / `reason` / `outboundEncrypted`；`enabled` 保留但语义收紧为「有主密钥」
- `encrypt()` 无密钥时返回体带 `reason: 'no_master_key'`
- 构造时 `outboundEncrypted=true` 但无主密钥 → 抛错
- 导出 `E2E_STATUS` 常量

### ⚠️ 破坏性变更

`verifySignature()` 原来在**无密钥或无签名时返回 `true`**（等于签名形同虚设），现在返回 `false`。
全仓排查：无生产调用方依赖旧行为（只有本仓单测，且它测的是「有密钥 + 有签名」的正反例）。
需要区分原因的调用方改用 `verifySignatureDetailed()`。

### 判据

`npm test` → **337/337 全绿**；`test/test-e2e-encryption.js` **17/17**（新增 9 条：三态三分 · 反向自测 · 不变量 · 假绿消除 ×3 · 回归）

## v1.0.1（2026-10-24）— UAC 验签错误三分：不再把配置问题读成签名问题

### 背景
与明德重做五步握手时，`proof` 阶段对方返回 `uac_invalid: bad_public_key`。
`bad_public_key` 只在 `crypto.createPublicKey` 抛异常时出现——它表示**用户公钥本身不可用**，
却极易被读成「签名不匹配」，浪费一整轮排查（今日实际发生）。

### 修复
`lib/authz/uac.js` `verifyUAC()` 把三种情形分开：

| 情形 | 返回 | 含义 |
|---|---|---|
| `userPublicKey` 为空/undefined | `missing_user_public_key` | 没配（A2A_SECURITY_HANDSHAKE_USER_PUBKEY 缺失） |
| 解析抛异常 | `bad_public_key` + `detail`（原始错误信息） | 配了但不可用（路径错/非 JWK/类型不对） |
| 解析成功但验签失败 | `bad_signature` | 真正的签名不匹配 |

### 判据
- 新增 3 条测试：三类错误互不混同（`test/test-uac.js` 13/13）
- 全量回归 318/318

### 兼容性
只新增错误码与 `detail` 字段，成功路径不变；调用方按 `error` 分支处理的逻辑无需改动。
