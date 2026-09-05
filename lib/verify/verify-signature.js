/**
 * CSB-Security P0-3「约束-验证分离」D1: 验证签名（verify-signature）
 *
 * 协议: P0-3 REV-2026-09-05 D1
 *   —— validator 用 Layer 1 AID 签「验证记录」，防自证（author ≠ validator），
 *      验证记录可被任意第三方（如阿轩）用 validator 的公钥复核。
 *
 * 职责:
 *   - canonicalize : 稳定 JSON 序列化（key 排序）——签名与复核必须用同一规范化
 *   - signVerification : validator 侧对验证记录签发（自证同样被拒）
 *   - verifyVerificationRecord : 校验签名确由 validator 的 AID 私钥所签
 *   - sigHash : 记录哈希（供 D2 技能模板 sig_hash 字段 / verif-log 存证）
 *
 * 签名: signature = base64( Ed25519.sign( canonicalize(claim), validatorPrivateKey ) )
 *
 * 维护者: 思源 🌱（P0-3 D1 分工）
 * 日期: 2026-09-05
 */

const crypto = require('crypto');
const { verifyAID } = require('../identity/aid');

const REQUIRED_FIELDS = ['csb_version', 'type', 'subject_id', 'producer_id', 'validator_id', 'ts'];
const VALID_VERDICTS = ['passed', 'failed'];

/**
 * 稳定 JSON 序列化（递归按 key 排序、无空白）
 * 保证「同一语义对象 → 同一串字节」，签名才可跨侧复核。
 * @param {*} value
 * @returns {string}
 */
function canonicalize(value) {
  if (value === undefined || value === null) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]));
  return '{' + parts.join(',') + '}';
}

/**
 * 校验 claim 结构是否完整
 * @returns {string|null} 错误码或 null
 */
function validateClaim(claim) {
  if (!claim || typeof claim !== 'object') return 'invalid_claim';
  if (claim.type !== 'verification') return 'invalid_claim';
  for (const f of REQUIRED_FIELDS) {
    if (claim[f] === undefined || claim[f] === null || claim[f] === '') return 'invalid_claim';
  }
  if (!VALID_VERDICTS.includes(claim.verdict)) return 'invalid_claim';
  if (!Number.isFinite(Date.parse(claim.ts))) return 'invalid_claim';
  return null;
}

/**
 * 计算记录哈希（sha256(canonical) base64）——D2 模板 sig_hash 权威来源
 * @param {Object} claim
 * @returns {string}
 */
function sigHash(claim) {
  return crypto.createHash('sha256').update(canonicalize(claim), 'utf8').digest('base64');
}

/**
 * validator 侧签发验证记录
 * @param {Object} claim 验证声明（subject_id/producer_id/validator_id/verdict/ts 等）
 * @param {KeyObject} privateKey validator 的 Ed25519 私钥
 * @returns {{ claim: Object, signature: string, sig_hash: string }}
 */
function signVerification(claim, privateKey) {
  const err = validateClaim(claim);
  if (err) throw new Error(`signVerification: ${err}`);
  // 防自证：validator 只能验证他人的记录，不能给自己的产出背书
  if (claim.producer_id === claim.validator_id) {
    throw new Error('signVerification: self_verification (author === validator)');
  }
  const signature = crypto.sign(null, Buffer.from(canonicalize(claim), 'utf8'), privateKey);
  return {
    claim,
    signature: signature.toString('base64'),
    sig_hash: sigHash(claim)
  };
}

/**
 * 校验验证记录签名（供 verif-log / 第三方复核）
 * @param {Object} claim 验证声明
 * @param {string} signature base64 签名
 * @param {Object} validatorAid validator 的 AID（public_key JWK；带 signature 字段则先验 AID 自签）
 * @param {Object} [opts]
 *   - verifyAid {boolean}  有 signature 字段时是否先验 AID 自签（默认 true）
 *   - requireAid {boolean} 是否强制要求完整 AID（含 signature）——严格模式，默认 false
 *   - maxAgeMs  {number}   可选：超过该年龄拒绝（默认不校）
 * @returns {{valid:boolean, error?:string, subject_id?:string, producer_id?:string,
 *            validator_id?:string, verdict?:string, ts?:string}}
 */
function verifyVerificationRecord(claim, signature, validatorAid, opts = {}) {
  const err = validateClaim(claim);
  if (err) return { valid: false, error: err };

  // P0-2/P0-3 防自证：author ≠ validator
  if (claim.producer_id === claim.validator_id) {
    return { valid: false, error: 'self_verification' };
  }

  // validator AID 必须携带可用的 Ed25519 JWK 公钥
  if (!validatorAid || !validatorAid.public_key || !validatorAid.public_key.x || !validatorAid.public_key.crv) {
    return { valid: false, error: 'bad_public_key' };
  }
  if (opts.requireAid === true && !validatorAid.signature) {
    return { valid: false, error: 'missing_aid_signature' };
  }
  if (opts.verifyAid !== false && validatorAid.signature) {
    const r = verifyAID(validatorAid);
    if (!r || r.valid !== true) {
      return { valid: false, error: 'invalid_aid', detail: (r && r.error) || 'aid signature mismatch' };
    }
  }

  // 可选时效校验（存量可追溯记录可用 maxAgeMs 收紧）
  if (opts.maxAgeMs) {
    const t = Date.parse(claim.ts);
    if (Date.now() - t > opts.maxAgeMs) {
      return { valid: false, error: 'expired', ts: claim.ts };
    }
  }

  let pub;
  try {
    pub = crypto.createPublicKey({ key: validatorAid.public_key, format: 'jwk' });
  } catch (e) {
    return { valid: false, error: 'bad_public_key' };
  }

  let sigBuf;
  try {
    sigBuf = Buffer.from(signature || '', 'base64');
  } catch (e) {
    return { valid: false, error: 'signature_invalid' };
  }

  const ok = crypto.verify(null, Buffer.from(canonicalize(claim), 'utf8'), pub, sigBuf);
  if (!ok) return { valid: false, error: 'signature_invalid' };

  return {
    valid: true,
    subject_id: claim.subject_id,
    producer_id: claim.producer_id,
    validator_id: claim.validator_id,
    verdict: claim.verdict,
    ts: claim.ts
  };
}

module.exports = {
  canonicalize,
  sigHash,
  signVerification,
  verifyVerificationRecord
};
