/**
 * CSB-Security Layer 2: 声誉存储与信任评分（协议 §3.4 / CSB 开放协议 v1.0 §2.2）
 *
 * 收编自:
 *  - trust-manager.js ReputationStore（csb-a2a-aip，A2A-010）
 *  - trust/score.js 信任评分公式（T = 0.3×I + 0.3×H + 0.2×A + 0.2×C）
 *
 * 功能:
 *  - ReputationStore: 交互记录 + 信任衰减（30 天 TTL，24h 衰减 0.05，最低 0.1）
 *  - calcScore: 多维信任评分（身份/历史/审计/社区）
 *  - levelForScore: 评分 → 信任等级映射（complete/high/medium/low/untrusted）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-25 (P2 补齐)
 */

// ============================================
// ReputationStore - 声誉数据存储（权威实现，自 trust-level.js 迁移）
// ============================================

class ReputationStore {
  constructor(config = {}) {
    this.ttl = config.ttl || 2592000000; // 30 天毫秒
    this.store = new Map();
  }

  /**
   * 记录一次交互结果
   * @param {string} agentId
   * @param {boolean} success
   * @param {Object} [details] 附加信息（event/session_id 等）
   * @returns {Object} 更新后的记录
   */
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

  /**
   * 基础声誉分（正向占比，无记录默认 0.5 中性）
   */
  getReputationScore(agentId) {
    const record = this.store.get(agentId);
    if (!record) return 0.5;
    const total = record.positive + record.negative;
    if (total === 0) return 0.5;
    return record.positive / total;
  }

  /**
   * 统计概览（含衰减分）
   */
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
    const decay = Math.floor(hoursSinceLastInteraction / 24) * 0.05;

    return Math.max(0.1, baseScore - decay);
  }

  /** 清理超过 TTL 未交互的 Agent（惰性，返回清理数量） */
  cleanup() {
    const now = Date.now();
    let removed = 0;
    for (const [agentId, record] of this.store.entries()) {
      const last = record.history.length > 0
        ? record.history[record.history.length - 1].timestamp
        : 0;
      if (now - last > this.ttl) {
        this.store.delete(agentId);
        removed++;
      }
    }
    return removed;
  }
}

// ============================================
// 信任评分（收编自 trust/score.js，CSB 开放协议 v1.0 §2.2）
// ============================================

const DEFAULT_WEIGHTS = {
  identity: 0.3,   // 身份验证通过度
  history: 0.3,    // 历史委托/任务完成率
  audit: 0.2,      // 审计日志完整度
  community: 0.2,  // 社区信任网络加权
};

const SCORE_LEVELS = [
  { min: 0.90, level: 'complete',  label: '🟣 完全信任', default_perm: 'full' },
  { min: 0.75, level: 'high',      label: '🔵 高信任',   default_perm: 'execute' },
  { min: 0.50, level: 'medium',    label: '🟢 中等信任', default_perm: 'request' },
  { min: 0.25, level: 'low',       label: '🟡 低信任',   default_perm: 'inform' },
  { min: 0.00, level: 'untrusted', label: '❌ 不可信',   default_perm: 'deny' },
];

const DECAY_DEFAULT_LAMBDA = 0.01;  // 约 100 天衰减至 37%
const DECAY_MIN_THRESHOLD = 0.20;   // 最低阈值 20%

/**
 * 计算多维信任评分
 * @param {Object} dims 各维度评分 (0~1): identity / history / audit / community
 * @param {Object} [weights] 自定义权重（默认见 DEFAULT_WEIGHTS）
 * @returns {{ score: number, level: string, label: string, default_perm: string }}
 */
function calcScore(dims, weights) {
  const w = weights || DEFAULT_WEIGHTS;
  const score = (
    (dims.identity  || 0) * w.identity +
    (dims.history   || 0) * w.history +
    (dims.audit     || 0) * w.audit +
    (dims.community || 0) * w.community
  );
  const matched = SCORE_LEVELS.find((l) => score >= l.min) || SCORE_LEVELS[SCORE_LEVELS.length - 1];
  return {
    score: Math.round(score * 100) / 100,
    level: matched.level,
    label: matched.label,
    default_perm: matched.default_perm,
  };
}

/**
 * 时间衰减：score × e^(-λ × days)
 * @param {number} score 原始分
 * @param {number} daysSinceLastInteraction 距上次交互天数
 * @param {Object} [opts] lambda / minThreshold
 */
function decayScore(score, daysSinceLastInteraction, opts = {}) {
  const lambda = opts.lambda || DECAY_DEFAULT_LAMBDA;
  const minThreshold = opts.minThreshold ?? DECAY_MIN_THRESHOLD;
  const decayed = score * Math.exp(-lambda * daysSinceLastInteraction);
  return Math.max(minThreshold, Math.round(decayed * 100) / 100);
}

module.exports = {
  ReputationStore,
  calcScore,
  decayScore,
  DEFAULT_WEIGHTS,
  SCORE_LEVELS,
};
