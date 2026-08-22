/**
 * CSB-Security Layer 2: UAC (User Authorization Credential)
 *
 * 协议: CSB-Security v1.0 §3.2
 * 功能: 用户授权凭证签发/验证（JWT + EdDSA）
 *
 * UAC 是用户签发给 Agent 的授权凭证，证明"这个 Agent 可以代表我"。
 * 关键字段: iss=用户, sub=Agent, aud=*, scopes, restrictions
 *
 * 时间窗口（协议 §3.2）:
 *  - 一次性操作 5 分钟 | 短期任务 1 小时 | 日常通信 24 小时
 *  - 长期授权 7 天 | 永久授权 365 天（需用户明确确认，建议避免）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M2)
 */

const crypto = require('crypto');

const MAX_TIME_DRIFT = 300; // iat 偏差 ≤ 5 分钟（秒）

// 时间窗口常量
const UAC_TTL = {
  ONCE: 5 * 60,          // 一次性操作
  SHORT_TERM: 60 * 60,   // 短期任务
  DAILY: 24 * 60 * 60,   // 日常通信
  LONG_TERM: 7 * 24 * 60 * 60, // 长期授权
  PERMANENT: 365 * 24 * 60 * 60 // 永久授权（建议避免）
};

/**
 * 签发 UAC，返回 JWT 字符串
 *
 * @param {Object} options
 *   - userPrivateKey: 用户私钥（Ed25519）
 *   - userId: 用户标识（iss），如 'user-yilan@csb'
 *   - agentId: 被授权 Agent（sub）
 *   - scopes: 权限范围数组，如 ['chat', 'memory:read', 'forum:post']
 *   - ttl: 有效期（秒），默认 24h
 *   - restrictions: 限制条件 { ip_whitelist, rate_limit, allowed_agents }
 *   - kid: 可选，密钥标识
 */
function createUAC({ userPrivateKey, userId, agentId, scopes = [], ttl = UAC_TTL.DAILY, restrictions = null, kid = null }) {
  if (!userPrivateKey) throw new Error('userPrivateKey is required');
  if (!userId) throw new Error('userId is required');
  if (!agentId) throw new Error('agentId is required');
  if (scopes.length === 0) throw new Error('scopes cannot be empty');

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'EdDSA', typ: 'JWT' };
  if (kid) header.kid = kid;

  const payload = {
    iss: userId,
    sub: agentId,
    aud: '*',
    scopes,
    iat: now,
    exp: now + ttl,
    jti: `uac-${now}-${crypto.randomBytes(8).toString('hex')}`
  };
  if (restrictions) payload.restrictions = restrictions;

  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), userPrivateKey);

  return `${signingInput}.${signature.toString('base64url')}`;
}

/**
 * 验证 UAC
 *
 * @param {string} token JWT 字符串
 * @param {Object} options
 *   - userPublicKey: 用户公钥（JWK）
 *   - expectedAgentId: 期望的被授权 Agent（sub 必须匹配）
 *   - jtiCache: Set，防重放
 *   - now: 当前时间戳（毫秒）
 * @returns {{valid: boolean, error?: string, payload?: object}}
 */
function verifyUAC(token, { userPublicKey, expectedAgentId, jtiCache = null, now = Date.now() } = {}) {
  if (!token || typeof token !== 'string') return { valid: false, error: 'missing_token' };
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'malformed' };

  const [headerB64, payloadB64, signatureB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;

  // 1. 签名验证（用户公钥）
  try {
    const pub = crypto.createPublicKey({ key: userPublicKey, format: 'jwk' });
    const ok = crypto.verify(null, Buffer.from(signingInput), pub, Buffer.from(signatureB64, 'base64url'));
    if (!ok) return { valid: false, error: 'bad_signature' };
  } catch (e) {
    return { valid: false, error: 'bad_public_key' };
  }

  // 2. 解析 payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch (e) {
    return { valid: false, error: 'malformed_payload' };
  }

  const nowSec = Math.floor(now / 1000);

  // 3. exp 必须存在且 > iat
  if (!payload.exp) return { valid: false, error: 'missing_exp' };
  if (payload.exp <= payload.iat) return { valid: false, error: 'invalid_exp' };
  if (payload.exp < nowSec) return { valid: false, error: 'expired' };

  // 4. iat 偏差
  if (Math.abs(payload.iat - nowSec) > MAX_TIME_DRIFT) return { valid: false, error: 'time_drift' };

  // 5. sub 必须匹配请求 Agent（Token 绑定）
  if (payload.sub !== expectedAgentId) return { valid: false, error: 'agent_mismatch' };

  // 6. scopes 必须存在
  if (!Array.isArray(payload.scopes) || payload.scopes.length === 0) {
    return { valid: false, error: 'missing_scopes' };
  }

  // 7. jti 防重放
  if (jtiCache) {
    if (!payload.jti) return { valid: false, error: 'missing_jti' };
    if (jtiCache.has(payload.jti)) return { valid: false, error: 'replay_detected' };
    jtiCache.add(payload.jti);
  }

  return { valid: true, payload };
}

/**
 * 检查 UAC 是否覆盖所需 scopes
 */
function coversScopes(uacPayload, requestedScopes) {
  const granted = new Set(uacPayload.scopes);
  return requestedScopes.every(s => granted.has(s));
}

/**
 * 检查 restrictions.allowed_agents 是否允许目标 Agent
 * （空/缺省 = 不限制）
 */
function allowsAgent(uacPayload, agentId) {
  const allowed = uacPayload.restrictions?.allowed_agents;
  if (!allowed || allowed.length === 0) return true;
  return allowed.includes(agentId);
}

function base64url(str) {
  return Buffer.from(str).toString('base64url');
}

module.exports = {
  UAC_TTL,
  MAX_TIME_DRIFT,
  createUAC,
  verifyUAC,
  coversScopes,
  allowsAgent
};
