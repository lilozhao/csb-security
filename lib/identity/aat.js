/**
 * CSB-Security Layer 1: AAT (Agent Attestation Token)
 *
 * 协议: CSB-Security v1.0 §2.2
 * 功能: AAT 签发、验证（JWT 格式 + EdDSA 签名）
 *
 * 验证规则（协议 §2.2 必填声明）：
 *  - iss 必须与 AID 文档 agent_id 一致
 *  - aud 必须匹配响应方身份
 *  - iat 与当前时间偏差 ≤ 5 分钟
 *  - exp 必须存在且 > iat
 *  - jti 唯一标识，防重放（验证方维护已见 jti 缓存）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M1)
 */

const crypto = require('crypto');

const DEFAULT_TTL = 300; // 5 分钟
const MAX_TIME_DRIFT = 300; // iat 偏差 ≤ 5 分钟（秒）

/**
 * 签发 AAT，返回 JWT 字符串
 */
function createAAT({ privateKey, issuer, audience, capabilities = [], ttl = DEFAULT_TTL, kid = null, nonce = null }) {
  if (!privateKey) throw new Error('privateKey is required');
  if (!issuer) throw new Error('issuer is required');
  if (!audience) throw new Error('audience is required');

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'EdDSA', typ: 'JWT' };
  if (kid) header.kid = kid;

  const payload = {
    iss: issuer,
    sub: issuer,
    aud: audience,
    iat: now,
    exp: now + ttl,
    jti: `aat-${now}-${crypto.randomBytes(8).toString('hex')}`,
    capabilities
  };
  if (nonce) payload.nonce = nonce;

  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKey);

  return `${signingInput}.${signature.toString('base64url')}`;
}

/**
 * 验证 AAT
 *
 * @param {string} token JWT 字符串
 * @param {Object} options
 *   - publicKey: JWK 格式公钥（来自 AID）
 *   - expectedAudience: 期望受众（响应方 Agent ID）
 *   - jtiCache: Set，已见 jti（防重放），可选
 *   - now: 当前时间戳（毫秒），可选
 * @returns {{valid: boolean, error?: string, payload?: object}}
 */
function verifyAAT(token, { publicKey, expectedAudience, jtiCache = null, now = Date.now() } = {}) {
  if (!token || typeof token !== 'string') return { valid: false, error: 'missing_token' };
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'malformed' };

  const [headerB64, payloadB64, signatureB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;

  // 1. 签名验证
  try {
    const pub = crypto.createPublicKey({ key: publicKey, format: 'jwk' });
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

  // 4. iat 偏差 ≤ 5 分钟
  if (Math.abs(payload.iat - nowSec) > MAX_TIME_DRIFT) return { valid: false, error: 'time_drift' };

  // 5. aud 必须匹配
  if (payload.aud !== expectedAudience && payload.aud !== '*') {
    return { valid: false, error: 'audience_mismatch' };
  }

  // 6. jti 防重放
  if (jtiCache) {
    if (!payload.jti) return { valid: false, error: 'missing_jti' };
    if (jtiCache.has(payload.jti)) return { valid: false, error: 'replay_detected' };
    jtiCache.add(payload.jti);
  }

  return { valid: true, payload };
}

/**
 * 从 AID 文档中提取公钥并验证 AAT
 */
function verifyAATWithAID(token, aid, options = {}) {
  const structure = validateAIDShape(aid);
  if (!structure.valid) return { valid: false, error: structure.error };
  return verifyAAT(token, { ...options, publicKey: aid.public_key });
}

function validateAIDShape(aid) {
  if (!aid || !aid.public_key || !aid.public_key.x) return { valid: false, error: 'missing_public_key' };
  return { valid: true };
}

function base64url(str) {
  return Buffer.from(str).toString('base64url');
}

module.exports = {
  DEFAULT_TTL,
  MAX_TIME_DRIFT,
  createAAT,
  verifyAAT,
  verifyAATWithAID
};
