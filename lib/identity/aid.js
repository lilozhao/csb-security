/**
 * CSB-Security Layer 1: AID (Agent Identity Document)
 *
 * 协议: CSB-Security v1.0 §2.1
 * 功能: AID 文档生成、签名、验证、密钥对生成
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M1)
 */

const crypto = require('crypto');

const CSB_VERSION = '1.0';
const AID_CACHE_TTL_MS = 5 * 60 * 1000; // 缓存 TTL 不得超过 5 分钟（协议 §2.4）

// 必填字段（协议 §2.1）
const REQUIRED_FIELDS = ['csb_version', 'agent_id', 'name', 'public_key', 'endpoint', 'signature'];

/**
 * 生成 Ed25519 密钥对（JWK 格式公钥）
 */
function generateKeyPair(kid) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  if (kid) jwk.kid = kid;
  return {
    publicKey,
    privateKey,
    publicJwk: jwk
  };
}

/**
 * 构造 AID 文档（不含签名）
 */
function buildAID({
  agentId,
  name,
  emoji = '',
  description = '',
  developer = null,
  capabilities = [],
  trustLevel = 'L0',
  endpoint,
  publicJwk,
  expiresAt = null
}) {
  if (!agentId) throw new Error('agentId is required');
  if (!name) throw new Error('name is required');
  if (!endpoint) throw new Error('endpoint is required');
  if (!publicJwk || !publicJwk.x) throw new Error('publicJwk (JWK) is required');

  const aid = {
    csb_version: CSB_VERSION,
    agent_id: agentId,
    name,
    emoji,
    description,
    public_key: publicJwk,
    endpoint,
    created_at: new Date().toISOString(),
    expires_at: expiresAt || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
  };

  if (developer) aid.developer = developer;
  if (capabilities.length > 0) aid.capabilities = capabilities;
  if (trustLevel) aid.trust_level = trustLevel;

  return aid;
}

/**
 * 对 AID 签名（排除 signature 字段，Ed25519）
 */
function signAID(aid, privateKey) {
  const { signature, ...unsigned } = aid;
  const signData = JSON.stringify(unsigned);
  const sig = crypto.sign(null, Buffer.from(signData), privateKey);
  return { ...aid, signature: sig.toString('base64') };
}

/**
 * 生成完整 AID（build + sign）
 */
function generateAID(options, privateKey) {
  const aid = buildAID(options);
  return signAID(aid, privateKey);
}

/**
 * 验证 AID 签名
 */
function verifyAID(aid) {
  if (!validateAID(aid).valid) return { valid: false, error: 'invalid_structure' };
  try {
    const pubKey = crypto.createPublicKey({ key: aid.public_key, format: 'jwk' });
    const { signature, ...unsigned } = aid;
    const ok = crypto.verify(
      null,
      Buffer.from(JSON.stringify(unsigned)),
      pubKey,
      Buffer.from(signature, 'base64')
    );
    return ok ? { valid: true } : { valid: false, error: 'bad_signature' };
  } catch (e) {
    return { valid: false, error: 'bad_public_key' };
  }
}

/**
 * 校验 AID 必填字段
 */
function validateAID(aid) {
  if (!aid || typeof aid !== 'object') return { valid: false, error: 'not_an_object' };
  for (const field of REQUIRED_FIELDS) {
    if (!aid[field]) return { valid: false, error: `missing_field:${field}` };
  }
  if (aid.csb_version !== CSB_VERSION) return { valid: false, error: 'version_mismatch' };
  if (!aid.public_key.x || !aid.public_key.crv) return { valid: false, error: 'invalid_public_key' };
  return { valid: true };
}

/**
 * 从身份 JSON（identity.json 风格）生成 AID
 * 兼容 csb-a2a-aip 现有 identity.json 字段
 */
function fromIdentity(identity, { publicJwk, privateKey, endpoint, kid } = {}) {
  if (!privateKey) throw new Error('privateKey is required to sign');
  const host = identity.publicHost || identity.host || 'localhost';
  const port = identity.port || 3100;
  const caps = identity.capabilities
    ? (Array.isArray(identity.capabilities) ? identity.capabilities : Object.keys(identity.capabilities))
    : [];
  const aid = buildAID({
    agentId: `${identity.name}@${host}:${port}`,
    name: identity.name,
    emoji: identity.emoji || '',
    description: identity.description || '',
    developer: identity.developer || null,
    capabilities: caps,
    trustLevel: identity.trust_level || 'L0',
    endpoint: endpoint || `http://${host}:${port}/a2a/json-rpc`,
    publicJwk,
    expiresAt: identity.expires_at || null
  });
  return signAID(aid, privateKey);
}

module.exports = {
  CSB_VERSION,
  AID_CACHE_TTL_MS,
  REQUIRED_FIELDS,
  generateKeyPair,
  buildAID,
  signAID,
  generateAID,
  verifyAID,
  validateAID,
  fromIdentity
};
