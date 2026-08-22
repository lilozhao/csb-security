/**
 * CSB-Security Layer 3: Token 绑定
 *
 * 协议: CSB-Security v1.0 §4.3
 * token_bound_to = (caller_id, user_id, callee_id, scopes)
 *
 * 规则:
 *  - 一个 Agent 获取的 Token 不得被另一个 Agent 使用（caller_id 绑定）
 *  - 一个用户授权的 Token 不得被另一个用户使用（user_id 绑定）
 *  - 绑定元组任一变化 → Token 失效
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M3)
 */

const crypto = require('crypto');

/**
 * 计算 Token 绑定标识（HMAC-SHA256）
 *
 * @param {Object} binding
 *   - callerId: 发起方 Agent ID
 *   - userId: 用户标识
 *   - calleeId: 响应方 Agent ID
 *   - scopes: 权限范围（排序后参与计算）
 *   - secret: HMAC 密钥（可选，默认派生自元组本身）
 * @returns {string} base64 绑定标识
 */
function bindToken({ callerId, userId, calleeId, scopes = [], secret = null }) {
  if (!callerId || !userId || !calleeId) {
    throw new Error('callerId, userId, calleeId are required');
  }
  const canonicalScopes = [...scopes].sort().join(',');
  const tuple = [callerId, userId, calleeId, canonicalScopes].join('|');
  if (secret) {
    return crypto.createHmac('sha256', secret).update(tuple).digest('base64');
  }
  return crypto.createHash('sha256').update(tuple).digest('base64');
}

/**
 * 验证 Token 绑定
 * @returns {{valid: boolean, error?: string}}
 */
function verifyBinding(tokenBinding, expected) {
  const expectedBinding = bindToken(expected);
  const a = Buffer.from(tokenBinding);
  const b = Buffer.from(expectedBinding);
  if (a.length !== b.length) return { valid: false, error: 'binding_mismatch' };
  return crypto.timingSafeEqual(a, b)
    ? { valid: true }
    : { valid: false, error: 'binding_mismatch' };
}

/**
 * 生成绑定 Token（含元数据，便于调试）
 */
function createBoundToken(binding, secret = null) {
  return {
    binding: bindToken(binding, secret),
    bound_to: {
      caller_id: binding.callerId,
      user_id: binding.userId,
      callee_id: binding.calleeId,
      scopes: [...binding.scopes].sort()
    },
    created_at: new Date().toISOString()
  };
}

module.exports = { bindToken, verifyBinding, createBoundToken };
