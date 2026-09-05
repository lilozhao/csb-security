/**
 * CSB-Security P0-3「约束-验证分离」D1: 验证记录上链存证（verif-log）
 *
 * 协议: P0-3 REV-2026-09-05 D1
 *   —— validator 用 Layer 1 AID 签「验证记录」（verify-signature.js，author ≠ validator），
 *      verif-log 将验证记录上链存证（复用 lib/audit/audit-log.js 哈希链），
 *      验证记录不可篡改、可追溯（按 subject / producer / validator 查询）。
 *
 * 双层签名:
 *   1. validator AID 签名（信任层）——verify-signature.js 签发并在此验签后才准上链
 *   2. 哈希链签名（存证层）——AuditLog 追加写 + prev_hash 链 + Ed25519 链签名（配置时）
 *
 * 记录结构（audit entry 扩展字段 verification）:
 *   { claim, signature, sig_hash }  全量存证，第三方可用 validator 公钥复核
 *
 * 维护者: 若兰 🌸（P0-3 D1 分工）
 * 日期: 2026-09-05
 */

const { AuditLog } = require('../audit/audit-log');
const { verifyVerificationRecord, sigHash } = require('./verify-signature');

class VerifLog {
  /**
   * @param {Object} options
   *   - logPath: 落盘路径（可选；不传则纯内存）
   *   - chainPrivateKey: 链签名 Ed25519 私钥（可选，配置后每条上链记录带签名）
   *   - chainPublicKey: 链签名 Ed25519 公钥（可选，verifyIntegrity 时验链签名）
   */
  constructor({ logPath = null, chainPrivateKey = null, chainPublicKey = null } = {}) {
    this.audit = new AuditLog({
      logPath,
      privateKey: chainPrivateKey,
      publicKey: chainPublicKey
    });
  }

  /**
   * 验证记录上链（验签不通过 → 拒绝上链，抛错）
   *
   * @param {Object} verification signVerification() 的输出 { claim, signature, sig_hash }
   * @param {Object} validatorAid validator 的公开 AID（Ed25519/JWK）
   * @param {Object} [opts] 透传 verifyVerificationRecord: { verifyAid, requireAid, maxAgeMs }
   * @returns {Object} 上链记录（含 seq / hash / prev_hash / timestamp / verification 全量）
   * @throws {Error} 结构非法 / 防自证 / 验签失败 / sig_hash 不一致 → 拒绝上链
   */
  append(verification, validatorAid, opts = {}) {
    // 1. 结构校验
    if (!verification || typeof verification !== 'object') {
      throw new Error('verif-log: invalid_record');
    }
    const { claim, signature } = verification;
    if (!claim || typeof claim !== 'object' || typeof signature !== 'string') {
      throw new Error('verif-log: invalid_record');
    }

    // 2. 验签（复用 verify-signature：结构 + 防自证 + AID 自签 + Ed25519 验签）
    const check = verifyVerificationRecord(claim, signature, validatorAid, opts);
    if (!check.valid) {
      throw new Error(`verif-log: ${check.error}`);
    }

    // 3. sig_hash 锚点一致性（防记录与哈希脱节）
    const sh = sigHash(claim);
    if (verification.sig_hash !== undefined && verification.sig_hash !== sh) {
      throw new Error('verif-log: sig_hash_mismatch');
    }

    // 4. 上链（verification 全量入扩展字段——自动纳入哈希，不可篡改）
    return this.audit.append({
      event_type: 'verification',
      caller_id: claim.validator_id,   // 验证者
      callee_id: claim.producer_id,    // 被验证的作者（≠ validator，防自证）
      user_id: claim.subject_id,       // 验证对象（技能/经验/记录 id）
      result: claim.verdict === 'passed' ? 'success' : 'failed'
    }, {
      verification: {
        claim,
        signature,
        sig_hash: sh
      }
    });
  }

  /**
   * 链完整性校验（哈希链断链 / 单条篡改 / 链签名无效 → 必检出）
   */
  verifyIntegrity() {
    return this.audit.verifyChain();
  }

  /**
   * 按验证对象追溯（某技能/经验/记录被谁验证过）
   */
  queryBySubject(subjectId) {
    if (!subjectId) return [];
    return this.audit.entries.filter(
      (e) => e.event_type === 'verification' && e.user_id === subjectId
    );
  }

  /**
   * 按验证者追溯（某 validator 签过哪些记录——信誉衰减 D4 的数据源）
   */
  queryByValidator(validatorId) {
    if (!validatorId) return [];
    return this.audit.entries.filter(
      (e) => e.event_type === 'verification' && e.caller_id === validatorId
    );
  }

  /**
   * 按作者追溯（某 producer 的产出被谁验证过——防自证审计）
   */
  queryByProducer(producerId) {
    if (!producerId) return [];
    return this.audit.entries.filter(
      (e) => e.event_type === 'verification' && e.callee_id === producerId
    );
  }

  /**
   * 统计摘要（含 verdict 分布 + 链状态）
   */
  summary() {
    const base = this.audit.summary();
    const byVerdict = { passed: 0, failed: 0 };
    for (const e of this.audit.entries) {
      if (e.event_type === 'verification' && e.verification) {
        const v = e.verification.claim && e.verification.claim.verdict;
        if (v === 'passed') byVerdict.passed++;
        else if (v === 'failed') byVerdict.failed++;
      }
    }
    return { ...base, byVerdict };
  }

  /**
   * 导出全部上链记录（JSON）
   */
  exportJSON() {
    return this.audit.exportJSON();
  }
}

module.exports = { VerifLog };
