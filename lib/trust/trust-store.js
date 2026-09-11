/**
 * CSB-Security Layer 2: 信任快照（Trust Snapshot，账本的派生层）
 *
 * 信任升级设计的「派生层」（TRUST-UPGRADE-DESIGN.md §三）
 *
 * 核心原则：**账本是事实，等级是派生**。
 *   等级永远可以从账本重放重建（replay），快照只是加速读的缓存。
 *   ⇒ 重启不丢（落盘）、算错可复现（重放）、可审计（每条等级都能追到证据 seq）。
 *
 * 派生规则（协议 §3.4 + 设计 §4.3，语义不改）：
 *   L0 → L1：存在 identity/handshake_completed
 *            —— 或 追溯认定（attestation/retroactive_attestation，由宿主用户签字，身份一并认定）
 *   L1 → L2：positiveWeight ≥ 10 且无未清偿负向（或有 forgiveness 覆盖）
 *            —— 或 追溯认定（上限 L2）
 *   L2 → L3：L2 成立 + 用户授权有效（authorization/user_authorized，未过期、未被 revocation 覆盖）
 *            + 声誉分 ≥ 0.9 + 未过期衰减（30 天内有正向证据）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-09-11 (P0)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { EvidenceLedger, KIND, POLARITY } = require('./evidence-ledger');

const DEFAULTS = Object.freeze({
  l2PositiveWeight: 10,        // L1→L2：正向权重下限（协议「≥10 次正向交互」）
  l3ReputationScore: 0.9,      // L2→L3：声誉分下限（协议）
  staleAfterMs: 30 * 24 * 3600 * 1000, // 30 天无正向 → L3 待复验
  maxRetroactiveLevel: 'L2',   // 追溯认定上限（L3 永不追溯认定）
  severeNegativeWeight: 2,     // ≥2 视为严重负向（需人工复核/宽恕）
});

const LEVEL_ORDER = { L0: 0, L1: 1, L2: 2, L3: 3 };

class TrustStore {
  /**
   * @param {Object} options
   *   - ledgerPath / snapshotPath
   *   - ledger: 复用已有 EvidenceLedger 实例（可选）
   *   - privateKey / publicKey: Ed25519（透传给账本）
   *   - 阈值覆盖：l2PositiveWeight / l3ReputationScore / staleAfterMs
   */
  constructor(options = {}) {
    this.ledgerPath = options.ledgerPath || null;
    this.snapshotPath = options.snapshotPath || null;
    this.cfg = { ...DEFAULTS, ...options };
    this.ledger = options.ledger || new EvidenceLedger({
      ledgerPath: this.ledgerPath,
      privateKey: options.privateKey || null,
      publicKey: options.publicKey || null,
    });
    this.snapshot = null;
    if (this.snapshotPath) this.loadSnapshot();
  }

  // ---------- 派生 ----------

  /**
   * 从账本重放派生某主体（或全部主体）的信任状态
   *
   * @param {string} [subjectId] 省略则返回全部
   * @returns {Object|Object[]} { agentId, level, trustLevel, score, ... source:'ledger', evidenceSeqs }
   */
  replay(subjectId = null) {
    const bySubject = new Map();
    for (const e of this.ledger.entries) {
      const id = e.subjectId || 'unknown';
      if (!bySubject.has(id)) bySubject.set(id, []);
      bySubject.get(id).push(e);
    }
    const now = Date.now();
    const deriveOne = (id, entries) => {
      let identityVerified = false;
      let attestationL2 = false;
      let positiveWeight = 0;
      let negativeWeight = 0;
      let negativeCount = 0;
      let maxNegativeWeight = 0;
      let lastNegativeTs = 0;
      let lastPositiveTs = 0;
      let forgivenessTs = 0;
      let lastAuth = null;
      let lastRevocationTs = 0;
      const evidenceSeqs = [];

      for (const e of entries) {
        evidenceSeqs.push(e.seq);
        if (e.kind === KIND.IDENTITY && e.action === 'handshake_completed' && e.polarity > 0) identityVerified = true;
        if (e.kind === KIND.ATTESTATION && e.action === 'retroactive_attestation') {
          attestationL2 = true;
          // 追溯认定由宿主用户签字（operator），已核验证据引用
          // ⇒ 身份一并被认定（否则会出现「认定了关系却卡在 L0」的荒谬态）
          identityVerified = true;
        }
        if (e.action === 'forgiveness') forgivenessTs = Math.max(forgivenessTs, e.ts);
        if (e.action === 'user_authorized') lastAuth = e;
        if (e.kind === KIND.REVOCATION || e.action === 'revoked') lastRevocationTs = Math.max(lastRevocationTs, e.ts);
        if (e.polarity > 0 && e.weight > 0) { positiveWeight += e.weight; lastPositiveTs = Math.max(lastPositiveTs, e.ts); }
        if (e.polarity < 0 && e.weight > 0) {
          negativeWeight += e.weight; negativeCount++;
          maxNegativeWeight = Math.max(maxNegativeWeight, e.weight);
          lastNegativeTs = Math.max(lastNegativeTs, e.ts);
        }
      }

      // 未清偿负向 = 最后一次宽恕之后的负向条目
      const outstandingNegatives = entries.filter((e) => e.polarity < 0 && e.weight > 0 && e.ts > forgivenessTs);
      const outstandingNegCount = outstandingNegatives.length;
      const outstandingSevere = outstandingNegatives.some((e) => e.weight >= this.cfg.severeNegativeWeight);
      const cleared = outstandingNegCount === 0;

      const totalWeight = positiveWeight + negativeWeight;
      const score = totalWeight > 0 ? positiveWeight / totalWeight : 0.5;
      const stale = lastPositiveTs > 0 ? (now - lastPositiveTs) > this.cfg.staleAfterMs : true;

      // 逐级判定
      let level = 'L0';
      if (identityVerified) level = 'L1';
      if (level === 'L1') {
        const byInteractions = positiveWeight >= this.cfg.l2PositiveWeight && cleared;
        const byAttestation = attestationL2 && cleared;
        if (byInteractions || byAttestation) level = 'L2';
      }
      let requiresReauth = false;
      let authValid = false;
      if (level === 'L2') {
        const authNotRevoked = lastAuth && lastAuth.ts > lastRevocationTs;
        const notExpired = lastAuth && (!lastAuth.expiresAt || lastAuth.expiresAt > now);
        authValid = Boolean(authNotRevoked && notExpired);
        if (authValid && score >= this.cfg.l3ReputationScore && !stale) level = 'L3';
        if (authValid && (stale || score < this.cfg.l3ReputationScore)) requiresReauth = true;
      }

      const name = entries.find((e) => e.subject?.name)?.subject?.name || id;
      return {
        agentId: id,
        name,
        level,
        trustLevel: level,           // 兼容 TrustLevelManager 命名
        score: Number(score.toFixed(4)),
        positiveWeight,
        negativeWeight,
        negativeCount,
        outstandingNegCount,
        maxNegativeWeight,
        outstandingSevere,
        identityVerified,
        attested: attestationL2,
        authValid,
        requiresReauth,
        stale,
        coveredByForgiveness: negativeCount > 0 && clearanceTsAfter(entries, forgivenessTs, lastNegativeTs),
        lastPositiveTs: lastPositiveTs || null,
        lastNegativeTs: lastNegativeTs || null,
        evidenceSeqs,
        source: 'ledger',
        derivedAt: now,
        since: lastPositiveTs || null,
      };
    };

    if (subjectId) {
      const entries = bySubject.get(subjectId) || [];
      return entries.length ? deriveOne(subjectId, entries) : this._empty(subjectId);
    }
    return Array.from(bySubject.entries()).map(([id, entries]) => deriveOne(id, entries));
  }

  _empty(subjectId) {
    return {
      agentId: subjectId, name: subjectId, level: 'L0', trustLevel: 'L0', score: 0.5,
      positiveWeight: 0, negativeWeight: 0, negativeCount: 0, outstandingNegCount: 0,
      maxNegativeWeight: 0, outstandingSevere: false, identityVerified: false, attested: false,
      authValid: false, requiresReauth: false, stale: true, coveredByForgiveness: false,
      lastPositiveTs: null, lastNegativeTs: null, evidenceSeqs: [], source: 'ledger',
      derivedAt: Date.now(), since: null,
    };
  }

  /** 便捷读取（只读派生结果，不做缓存合并） */
  getLevel(subjectId) { return this.replay(subjectId); }

  // ---------- 快照（加速读；可随时由 replay 重建） ----------

  saveSnapshot() {
    const agents = {};
    for (const rec of this.replay()) agents[rec.agentId] = { ...rec, evidenceSeqs: rec.evidenceSeqs.slice(-20) };
    this.snapshot = {
      version: 1,
      updatedAt: Date.now(),
      ledgerHead: this.ledger.headHash,
      ledgerEntries: this.ledger.entries.length,
      agents,
    };
    if (this.snapshotPath) {
      fs.mkdirSync(path.dirname(this.snapshotPath), { recursive: true });
      fs.writeFileSync(this.snapshotPath, JSON.stringify(this.snapshot, null, 2), 'utf-8');
    }
    return this.snapshot;
  }

  loadSnapshot() {
    try {
      if (!fs.existsSync(this.snapshotPath)) return null;
      this.snapshot = JSON.parse(fs.readFileSync(this.snapshotPath, 'utf-8'));
    } catch { this.snapshot = null; }
    return this.snapshot;
  }

  /**
   * 快照是否与账本一致（防止「账本已更新、快照没跟上」这类静默漂移）
   * 不一致时调用方应自行 replay 重建。
   */
  snapshotFresh() {
    if (!this.snapshot) return false;
    return this.snapshot.ledgerHead === this.ledger.headHash &&
      this.snapshot.ledgerEntries === this.ledger.entries.length;
  }

  /** 账本校验（篡改必检出）—— 信任体系的自检入口 */
  verify() { return this.ledger.verifyChain(); }
}

/** forgiveness 是否晚于最后一次负向（即"真的宽恕了"） */
function clearanceTsAfter(entries, forgivenessTs, lastNegativeTs) {
  return forgivenessTs > 0 && forgivenessTs >= lastNegativeTs;
}

module.exports = { TrustStore, DEFAULTS, LEVEL_ORDER };
