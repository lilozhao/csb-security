/**
 * CSB-Security Layer 2: 信任等级管理（收编自 csb-a2a-aip/trust-manager.js A2A-010）
 *
 * 协议: CSB-Security v1.0 §3.4
 * 升级规则（协议）:
 *  - L0 → L1: 完成身份验证（AID + AAT）
 *  - L1 → L2: 累计正向交互 ≥ 10 次，无负向记录
 *  - L2 → L3: 用户明确授权 + 信任评分 ≥ 0.9
 *
 * 保留: ReputationStore（信任衰减）、TrustChainVerifier、WoTCertifier
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M1 收编)
 */

// ============================================
// 信任等级定义（协议 §3.4 权限映射）
// ============================================

const TRUST_LEVELS = {
  L0: { name: 'Initial', permissions: ['chat'], description: '初始等级，仅限公开信息（只读）' },
  L1: { name: 'Verified', permissions: ['chat', 'memory:read'], description: '已验证身份，可读记忆' },
  L2: { name: 'Trusted', permissions: ['chat', 'memory:read', 'memory:write', 'forum:post', 'forum:reply', 'delegate'], description: '可信，支持读写与委托' },
  L3: { name: 'Authoritative', permissions: ['*'], description: '权威级，全部权限（需用户明确授权）' }
};

const LEVEL_ORDER = { L0: 0, L1: 1, L2: 2, L3: 3 };

// ============================================
// ReputationStore - 声誉数据存储（收编）
// ============================================

class ReputationStore {
  constructor(config = {}) {
    this.ttl = config.ttl || 2592000000; // 30 天毫秒
    this.store = new Map();
  }

  recordInteraction(agentId, success, details = {}) {
    const record = this.store.get(agentId) || { positive: 0, negative: 0, history: [] };
    if (success) record.positive++;
    else record.negative++;

    record.history.push({
      success,
      timestamp: Date.now(),
      ...details
    });

    // 保留最近 50 条历史
    if (record.history.length > 50) record.history = record.history.slice(-50);
    this.store.set(agentId, record);
    return record;
  }

  getReputationScore(agentId) {
    const record = this.store.get(agentId);
    if (!record) return 0.5; // 默认中性
    const total = record.positive + record.negative;
    if (total === 0) return 0.5;
    return record.positive / total;
  }

  getStats(agentId) {
    const record = this.store.get(agentId);
    if (!record) return { positive: 0, negative: 0, total: 0, score: 0.5, decayedScore: 0.5, historyCount: 0 };
    const total = record.positive + record.negative;
    const baseScore = total > 0 ? record.positive / total : 0.5;
    return {
      positive: record.positive,
      negative: record.negative,
      total,
      score: baseScore,
      decayedScore: this.getDecayedScore(agentId),
      historyCount: record.history.length
    };
  }

  /**
   * 信任衰减：距离最后一次交互每过 24 小时衰减 0.05，最低 0.1，最长追溯 30 天
   */
  getDecayedScore(agentId) {
    const record = this.store.get(agentId);
    if (!record) return 0.5;

    const total = record.positive + record.negative;
    const baseScore = total > 0 ? record.positive / total : 0.5;

    const lastInteraction = record.history.length > 0
      ? record.history[record.history.length - 1].timestamp
      : Date.now();

    const hoursSinceLastInteraction = (Date.now() - lastInteraction) / (1000 * 60 * 60);

    if (hoursSinceLastInteraction <= 24) return baseScore;

    const daysPast = Math.min(Math.floor(hoursSinceLastInteraction / 24), 30);
    const decay = daysPast * 0.05;
    return Math.max(0.1, Math.round((baseScore - decay) * 100) / 100);
  }

  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.store) {
      record.history = record.history.filter(h => now - h.timestamp < this.ttl);
      if (record.history.length === 0) this.store.delete(key);
    }
  }
}

// ============================================
// TrustLevelManager - 信任等级管理器（协议升级规则）
// ============================================

class TrustLevelManager {
  constructor(config = {}) {
    this.maxHops = config.maxHops || 3;
    this.witnessThreshold = config.witnessThreshold || 3;
    this.l2PositiveThreshold = config.l2PositiveThreshold || 10; // 协议：L1→L2 需 ≥10 次正向
    this.l3ReputationThreshold = config.l3ReputationThreshold || 0.9; // 协议：L2→L3 需声誉 ≥0.9
    this.store = new Map();
    this.reputation = new ReputationStore(config);
    this.history = [];
  }

  getTrustLevel(agentId) {
    return this.store.get(agentId) || {
      agentId,
      trustLevel: 'L0',
      since: Date.now(),
      witnesses: [],
      history: []
    };
  }

  setTrustLevel(agentId, newLevel, reason = 'manual') {
    const record = this.getTrustLevel(agentId);
    const oldLevel = record.trustLevel;

    record.history.push({
      timestamp: Date.now(),
      action: oldLevel === 'L0' ? 'init' : (this.levelToInt(newLevel) > this.levelToInt(oldLevel) ? 'upgrade' : 'downgrade'),
      fromLevel: oldLevel,
      toLevel: newLevel,
      reason
    });

    record.trustLevel = newLevel;
    record.since = Date.now();
    this.store.set(agentId, record);

    this.history.push({ agentId, oldLevel, newLevel, reason, timestamp: Date.now() });
    return record;
  }

  /**
   * 升级（协议 §3.4 规则）
   * @param {Object} options - { identityVerified, userAuthorized, witnesses, reason }
   */
  upgrade(agentId, newLevel, options = {}) {
    const current = this.getTrustLevel(agentId);
    const currentInt = this.levelToInt(current.trustLevel);
    const newInt = this.levelToInt(newLevel);

    // 不能跳级
    if (newInt > currentInt + 1) {
      return { success: false, error: `Cannot skip trust levels. Current: ${current.trustLevel}` };
    }

    // L0 → L1: 完成身份验证（AID + AAT）
    if (newLevel === 'L1' && !options.identityVerified) {
      return { success: false, error: 'L1 requires identity verification (AID + AAT)' };
    }

    // L1 → L2: 累计正向交互 ≥ 10 次，无负向记录
    if (newLevel === 'L2') {
      const stats = this.reputation.getStats(agentId);
      if (stats.positive < this.l2PositiveThreshold || stats.negative > 0) {
        return {
          success: false,
          error: `L2 needs >= ${this.l2PositiveThreshold} positive interactions with 0 negative, got ${stats.positive}+/${stats.negative}-`
        };
      }
    }

    // L2 → L3: 用户明确授权 + 信任评分 ≥ 0.9
    if (newLevel === 'L3') {
      if (!options.userAuthorized) {
        return { success: false, error: 'L3 requires explicit user authorization' };
      }
      const score = this.reputation.getReputationScore(agentId);
      if (score < this.l3ReputationThreshold) {
        return { success: false, error: `L3 needs reputation >= ${this.l3ReputationThreshold}, got ${score.toFixed(2)}` };
      }
    }

    this.setTrustLevel(agentId, newLevel, options.reason || 'upgrade');
    return { success: true, agentId, newLevel };
  }

  downgrade(agentId, newLevel, reason = 'misbehavior') {
    const current = this.getTrustLevel(agentId);
    const newInt = this.levelToInt(newLevel);
    const currentInt = this.levelToInt(current.trustLevel);

    if (newInt >= currentInt) {
      return { success: false, error: 'New level must be lower' };
    }

    this.setTrustLevel(agentId, newLevel, reason);
    return { success: true, agentId, fromLevel: current.trustLevel, newLevel };
  }

  addWitness(agentId, witnessId) {
    const record = this.getTrustLevel(agentId);
    if (!record.witnesses.includes(witnessId)) {
      record.witnesses.push(witnessId);
      this.store.set(agentId, record);
    }
    return record;
  }

  recordInteraction(agentId, success, details = {}) {
    this.reputation.recordInteraction(agentId, success, details);
    return { autoUpgrade: false };
  }

  levelToInt(level) {
    return LEVEL_ORDER[level] || 0;
  }

  getPermissions(trustLevel) {
    return TRUST_LEVELS[trustLevel]?.permissions || [];
  }

  hasPermission(trustLevel, permission) {
    const perms = this.getPermissions(trustLevel);
    return perms.includes('*') || perms.includes(permission);
  }

  getStats() {
    const levels = { L0: 0, L1: 0, L2: 0, L3: 0 };
    for (const record of this.store.values()) {
      levels[record.trustLevel]++;
    }
    return { total: this.store.size, levels, historyCount: this.history.length };
  }
}

// ============================================
// TrustChainVerifier - 信任链验证器（收编）
// ============================================

class TrustChainVerifier {
  constructor(trustManager) {
    this.trustManager = trustManager;
    this.maxHops = trustManager.maxHops;
  }

  verifyChain(fromAgentId, toAgentId, requiredLevel = 'L1') {
    const toRecord = this.trustManager.getTrustLevel(toAgentId);
    const fromRecord = this.trustManager.getTrustLevel(fromAgentId);

    // 直接信任
    if (this.trustManager.levelToInt(toRecord.trustLevel) >= this.trustManager.levelToInt(requiredLevel)) {
      return {
        valid: true,
        chain: [fromRecord, toRecord],
        hops: 1,
        effectiveLevel: toRecord.trustLevel,
        reason: 'direct_trust'
      };
    }

    // 传递信任（衰减一档）
    if (fromRecord.witnesses && fromRecord.witnesses.includes(toAgentId)) {
      const effectiveInt = Math.max(0, this.trustManager.levelToInt(toRecord.trustLevel) - 1);
      const effectiveLevel = ['L0', 'L1', 'L2', 'L3'][effectiveInt];
      return {
        valid: effectiveInt >= this.trustManager.levelToInt(requiredLevel),
        chain: [toRecord, fromRecord],
        hops: 2,
        effectiveLevel,
        reason: 'transitive_trust_attenuated'
      };
    }

    return { valid: false, hops: 0, reason: 'no_trust_chain' };
  }
}

// ============================================
// WoTCertifier - WoT 交叉见证（收编）
// ============================================

class WoTCertifier {
  constructor(trustManager) {
    this.trustManager = trustManager;
    this.signatures = new Map();
  }

  addWitnessSignature(signature) {
    const { witnessId, targetAgentId } = signature;

    const witnessRecord = this.trustManager.getTrustLevel(witnessId);
    if (this.trustManager.levelToInt(witnessRecord.trustLevel) < 1) {
      return { success: false, error: 'Witness must be at least L1' };
    }

    if (this.detectLoop(witnessId, targetAgentId)) {
      return { success: false, error: 'Trust loop detected' };
    }

    const agentSigs = this.signatures.get(targetAgentId) || [];
    agentSigs.push({ ...signature, timestamp: Date.now() });
    this.signatures.set(targetAgentId, agentSigs);

    this.trustManager.addWitness(targetAgentId, witnessId);
    return { success: true, witnessCount: agentSigs.length };
  }

  detectLoop(witnessId, targetAgentId) {
    const targetRecord = this.trustManager.getTrustLevel(targetAgentId);
    return targetRecord.witnesses && targetRecord.witnesses.includes(witnessId);
  }

  getSignatures(agentId) {
    return this.signatures.get(agentId) || [];
  }
}

module.exports = {
  TRUST_LEVELS,
  LEVEL_ORDER,
  TrustLevelManager,
  TrustChainVerifier,
  WoTCertifier,
  ReputationStore
};
