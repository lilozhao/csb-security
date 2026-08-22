/**
 * CSB-Security Layer 3: 会话密钥协商（ECDH-P256 双向）
 *
 * 协议: CSB-Security v1.0 §4.2
 *
 * 流程:
 *   Caller → Callee: key_exchange_request(caller_pubkey, nonce_a)
 *   Callee → Caller: key_exchange_response(callee_pubkey, nonce_b, sign(nonce_a))
 *   Caller → Callee: key_exchange_confirm(sign(nonce_b))
 *   Session Key = HKDF(caller_pubkey, callee_pubkey, "csb-session-key")
 *
 * 实现: KeyObject (generateKeyPairSync ec) + crypto.diffieHellman
 * 传输: 公钥以 JWK base64 传递（JSON 可序列化）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M3)
 */

const crypto = require('crypto');

const CURVE = 'prime256v1';
const HKDF_INFO = 'csb-session-key';
const SESSION_KEY_LENGTH = 32; // AES-256

/**
 * 生成 ECDH-P256 临时密钥对
 * @returns {{ publicKey: KeyObject, privateKey: KeyObject, publicJwk: object }}
 */
function generateEphemeralKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: CURVE });
  return {
    publicKey,
    privateKey,
    publicJwk: publicKey.export({ format: 'jwk' })
  };
}

/**
 * 计算 ECDH 共享密钥
 * @param {KeyObject} privateKey
 * @param {object|KeyObject} peerPublicKey JWK 对象或 KeyObject
 * @returns {Buffer}
 */
function computeSharedSecret(privateKey, peerPublicKey) {
  const peer = peerPublicKey instanceof crypto.KeyObject
    ? peerPublicKey
    : crypto.createPublicKey({ key: peerPublicKey, format: 'jwk' });
  return crypto.diffieHellman({ privateKey, publicKey: peer });
}

/**
 * 派生会话密钥: HKDF-SHA256(shared_secret, salt=sha256(nonce_a:nonce_b), info="csb-session-key")
 * @returns {Buffer} 32 字节
 */
function deriveSessionKey(sharedSecret, nonceA, nonceB, info = HKDF_INFO) {
  const salt = crypto.createHash('sha256').update(`${nonceA}:${nonceB}`).digest();
  const derived = crypto.hkdfSync('sha256', sharedSecret, salt, info, SESSION_KEY_LENGTH);
  return Buffer.from(derived); // 确保 Buffer 类型（兼容不同 Node 版本返回类型）
}

/**
 * 签名 nonce（KeyObject 私钥）
 */
function signNonce(nonce, privateKey) {
  return crypto.sign(null, Buffer.from(nonce), privateKey).toString('base64');
}

/**
 * 验证 nonce 签名（JWK 公钥或 KeyObject）
 */
function verifyNonceSignature(signatureB64, nonce, publicKey) {
  try {
    const pub = publicKey instanceof crypto.KeyObject
      ? publicKey
      : crypto.createPublicKey({ key: publicKey, format: 'jwk' });
    return crypto.verify(null, Buffer.from(nonce), pub, Buffer.from(signatureB64, 'base64'));
  } catch (e) {
    return false;
  }
}

/**
 * 序列化公钥为传输格式（base64 JWK）
 */
function encodePublicKey(publicKey) {
  const jwk = publicKey instanceof crypto.KeyObject
    ? publicKey.export({ format: 'jwk' })
    : publicKey;
  return Buffer.from(JSON.stringify(jwk)).toString('base64');
}

/**
 * 解析传输格式公钥为 JWK
 */
function decodePublicKey(b64) {
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

class SessionKeyNegotiator {
  /**
   * @param {Object} options - { seenNonces: Set }
   */
  constructor({ seenNonces = new Set() } = {}) {
    this.seenNonces = seenNonces;
  }

  /**
   * Caller: 发起密钥交换请求
   */
  initiate({ callerId, calleeId, callerKeyPair = null } = {}) {
    const kp = callerKeyPair || generateEphemeralKeyPair();
    return {
      type: 'key_exchange_request',
      caller_id: callerId,
      callee_id: calleeId,
      caller_pubkey: encodePublicKey(kp.publicJwk),
      nonce_a: crypto.randomBytes(32).toString('hex'),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Callee: 处理请求，返回响应（含 sign(nonce_a)）
   */
  processRequest(request, { calleeKeyPair = null } = {}) {
    if (!request || request.type !== 'key_exchange_request') {
      throw new Error('expected key_exchange_request');
    }
    if (this.seenNonces.has(request.nonce_a)) {
      throw new Error('nonce replay detected');
    }
    this.seenNonces.add(request.nonce_a);

    const kp = calleeKeyPair || generateEphemeralKeyPair();
    const nonceB = crypto.randomBytes(32).toString('hex');

    return {
      type: 'key_exchange_response',
      caller_id: request.caller_id,
      callee_id: request.callee_id,
      callee_pubkey: encodePublicKey(kp.publicJwk),
      nonce_b: nonceB,
      sign_nonce_a: signNonce(request.nonce_a, kp.privateKey),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Caller: 处理响应 → 验证 sign(nonce_a) → 生成 confirm + 会话密钥
   */
  processResponse(request, response, { callerKeyPair }) {
    if (!response || response.type !== 'key_exchange_response') {
      throw new Error('expected key_exchange_response');
    }
    const calleeJwk = decodePublicKey(response.callee_pubkey);

    // 验证 callee 签名了我们的 nonce_a
    if (!verifyNonceSignature(response.sign_nonce_a, request.nonce_a, calleeJwk)) {
      throw new Error('sign_nonce_a verification failed');
    }

    return buildConfirm(request, response, callerKeyPair);
  }
}

/**
 * 生成 confirm + 会话密钥（Caller 侧，无状态）
 */
function buildConfirm(request, response, callerKeyPair) {
  const calleeJwk = decodePublicKey(response.callee_pubkey);
  const shared = computeSharedSecret(callerKeyPair.privateKey, calleeJwk);
  const sessionKey = deriveSessionKey(shared, request.nonce_a, response.nonce_b);

  return {
    confirm: {
      type: 'key_exchange_confirm',
      caller_id: request.caller_id,
      callee_id: request.callee_id,
      caller_pubkey: encodePublicKey(callerKeyPair.publicJwk),
      nonce_a: request.nonce_a,
      nonce_b: response.nonce_b,
      sign_nonce_b: signNonce(response.nonce_b, callerKeyPair.privateKey),
      timestamp: new Date().toISOString()
    },
    sessionKey
  };
}

/**
 * 处理 confirm，得到会话密钥（Callee 侧，无状态）
 */
function processConfirmV2(confirm, calleeKeyPair, { seenNonces = new Set() } = {}) {
  if (!confirm || confirm.type !== 'key_exchange_confirm') {
    throw new Error('expected key_exchange_confirm');
  }
  if (seenNonces.has(confirm.nonce_b)) {
    throw new Error('nonce replay detected');
  }
  seenNonces.add(confirm.nonce_b);

  const callerJwk = decodePublicKey(confirm.caller_pubkey);

  if (!verifyNonceSignature(confirm.sign_nonce_b, confirm.nonce_b, callerJwk)) {
    throw new Error('sign_nonce_b verification failed');
  }

  const shared = computeSharedSecret(calleeKeyPair.privateKey, callerJwk);
  return { sessionKey: deriveSessionKey(shared, confirm.nonce_a, confirm.nonce_b) };
}

module.exports = {
  CURVE,
  HKDF_INFO,
  SESSION_KEY_LENGTH,
  generateEphemeralKeyPair,
  computeSharedSecret,
  deriveSessionKey,
  signNonce,
  verifyNonceSignature,
  encodePublicKey,
  decodePublicKey,
  SessionKeyNegotiator,
  buildConfirm,
  processConfirmV2
};
