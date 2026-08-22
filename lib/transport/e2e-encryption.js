/**
 * CSB-Security Layer 3: E2E 加密（收编自 csb-a2a-aip/a2a-e2e-encryption.js A2A-021）
 *
 * 协议: CSB-Security v1.0 §4
 *  - AES-256-GCM 认证加密
 *  - HKDF-SHA256 密钥派生
 *  - 支持两种密钥模式:
 *    1. PSK（预共享密钥，已知 Agent 网络，收编保留）
 *    2. ECDH 会话密钥（与 session-keys.js 联动，协议 §4.2）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M3 收编)
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

class E2EEncryption {
  constructor(options = {}) {
    this.masterKey = options.masterKey || process.env.CSB_ENCRYPTION_KEY;
    this.enabled = !!this.masterKey;
    this.keyVersion = options.keyVersion || 1;
    this._derivedKeys = new Map(); // Map<agentId, Buffer>
  }

  /**
   * 派生 Agent 专属密钥 (HKDF-SHA256, PSK 模式)
   */
  getAgentKey(agentId) {
    if (!this.masterKey) throw new Error('E2E encryption not configured');
    if (!this._derivedKeys.has(agentId)) {
      const salt = crypto.createHash('sha256').update(agentId).digest();
      this._derivedKeys.set(agentId, crypto.hkdfSync('sha256', this.masterKey, salt, `csb-e2e-${agentId}`, 32));
    }
    return this._derivedKeys.get(agentId);
  }

  /**
   * 用指定密钥加密（PSK 或 ECDH 会话密钥通用）
   * @param {string} plaintext
   * @param {Buffer} key 32 字节密钥
   * @returns {{ciphertext, iv, tag, keyVersion, encrypted: true}}
   */
  encryptWithKey(plaintext, key) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
    ciphertext += cipher.final('base64');
    const tag = cipher.getAuthTag().toString('base64');

    return {
      ciphertext,
      iv: iv.toString('base64'),
      tag,
      keyVersion: this.keyVersion,
      encrypted: true
    };
  }

  /**
   * 用指定密钥解密
   * @returns {string|null} 明文（失败返回 null）
   */
  decryptWithKey(encryptedObj, key) {
    try {
      const iv = Buffer.from(encryptedObj.iv, 'base64');
      const tag = Buffer.from(encryptedObj.tag, 'base64');
      const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
      decipher.setAuthTag(tag);

      let plaintext = decipher.update(encryptedObj.ciphertext, 'base64', 'utf8');
      plaintext += decipher.final('utf8');
      return plaintext;
    } catch (e) {
      return null;
    }
  }

  /**
   * 加密消息（PSK 模式，按 agentId 派生密钥）
   */
  encrypt(plaintext, agentId) {
    if (!this.enabled) return { plaintext, encrypted: false };
    const key = this.getAgentKey(agentId);
    return this.encryptWithKey(plaintext, key);
  }

  /**
   * 解密消息（PSK 模式）
   */
  decrypt(encryptedObj, agentId) {
    if (!encryptedObj.encrypted) return encryptedObj.plaintext;
    const key = this.getAgentKey(agentId);
    return this.decryptWithKey(encryptedObj, key);
  }

  /**
   * HMAC-SHA256 消息签名
   */
  signMessage(plaintext) {
    if (!this.masterKey) return null;
    return crypto.createHmac('sha256', this.masterKey).update(plaintext).digest('base64');
  }

  /**
   * 验证签名（timing-safe）
   */
  verifySignature(plaintext, signature) {
    if (!this.masterKey || !signature) return true;
    const expected = this.signMessage(plaintext);
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  /**
   * 加密信封消息（兼容现有 envelope 格式）
   */
  encryptEnvelope(envelope, agentId) {
    if (!this.enabled) return envelope;
    const payload = JSON.stringify(envelope.payload || {});
    const encryptedPayload = this.encrypt(payload, agentId);
    return {
      ...envelope,
      encryption: { version: this.keyVersion, algorithm: ALGORITHM, encrypted: true },
      payload: encryptedPayload
    };
  }

  /**
   * 解密信封消息
   */
  decryptEnvelope(envelope, agentId) {
    if (!envelope.encryption?.encrypted) return envelope;
    const plaintext = this.decrypt(envelope.payload, agentId);
    if (!plaintext) return envelope;
    return {
      ...envelope,
      encryption: { ...envelope.encryption, encrypted: false },
      payload: JSON.parse(plaintext)
    };
  }

  getStats() {
    return {
      enabled: this.enabled,
      algorithm: ALGORITHM,
      keyVersion: this.keyVersion,
      agentKeys: this._derivedKeys.size
    };
  }
}

module.exports = { E2EEncryption, ALGORITHM };
