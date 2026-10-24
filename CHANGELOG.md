# CHANGELOG · csb-security

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
