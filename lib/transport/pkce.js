/**
 * CSB-Security Layer 3: PKCE 防码注入
 *
 * 协议: CSB-Security v1.0 §4.4（RFC 7636）
 * 当授权流程涉及重定向时，必须使用 PKCE（S256 挑战方法）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M3)
 */

const crypto = require('crypto');

const VERIFIER_LENGTH = 64; // 43-128 字符，默认 64
const CHALLENGE_METHOD = 'S256'; // 协议要求 S256

/**
 * 生成 code_verifier（高熵随机串，URL-safe）
 */
function generateVerifier(length = VERIFIER_LENGTH) {
  if (length < 43 || length > 128) throw new Error('verifier length must be 43-128');
  return crypto.randomBytes(length).toString('base64url').slice(0, length);
}

/**
 * 生成 code_challenge: S256 = base64url(sha256(verifier))
 */
function generateChallenge(verifier, method = CHALLENGE_METHOD) {
  if (method !== 'S256') throw new Error('only S256 challenge method supported');
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

/**
 * 验证 verifier 是否匹配 challenge
 */
function verifyChallenge(verifier, challenge, method = CHALLENGE_METHOD) {
  const computed = generateChallenge(verifier, method);
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * 生成完整的 PKCE 对（state 也一并生成，协议 §5.2 要求 state ≥128 位熵）
 */
function generatePKCEPair() {
  const verifier = generateVerifier();
  return {
    verifier,
    challenge: generateChallenge(verifier),
    state: crypto.randomBytes(32).toString('base64url'), // 256 位熵
    method: CHALLENGE_METHOD
  };
}

module.exports = {
  VERIFIER_LENGTH,
  CHALLENGE_METHOD,
  generateVerifier,
  generateChallenge,
  verifyChallenge,
  generatePKCEPair
};
