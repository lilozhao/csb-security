/**
 * CSB-Security Layer 1: 密钥轮换与 AID 缓存
 *
 * 协议: CSB-Security v1.0 §2.3 / §2.4
 *  - 密钥轮换：AAT 签名验证失败时，验证方应当重新获取 AID（绕过缓存）
 *  - 防滥用：重新获取频率限制为每个 agent_id 每分钟最多 1 次
 *  - AID 缓存 TTL 不得超过 5 分钟
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M1)
 */

const { AID_CACHE_TTL_MS } = require('./aid');

class KeyRotationManager {
  /**
   * @param {Object} options
   *   - aidFetcher: async (agentId) => AID  远程获取 AID 的函数
   *   - cacheTtlMs: 缓存 TTL（默认 5 分钟）
   *   - refetchMinIntervalMs: 强制重新获取最小间隔（默认 1 分钟）
   */
  constructor({ aidFetcher, cacheTtlMs = AID_CACHE_TTL_MS, refetchMinIntervalMs = 60 * 1000 } = {}) {
    if (!aidFetcher) throw new Error('aidFetcher is required');
    this.aidFetcher = aidFetcher;
    this.cacheTtlMs = cacheTtlMs;
    this.refetchMinIntervalMs = refetchMinIntervalMs;
    this.cache = new Map();      // agentId -> { aid, fetchedAt }
    this.lastRefetch = new Map(); // agentId -> timestamp
  }

  /**
   * 获取 AID（带缓存）
   * @param {string} agentId
   * @param {Object} options - { force: boolean } 绕过缓存（密钥轮换场景）
   */
  async getAID(agentId, { force = false } = {}) {
    const now = Date.now();
    const cached = this.cache.get(agentId);

    if (!force && cached && now - cached.fetchedAt < this.cacheTtlMs) {
      return cached.aid;
    }

    if (force) {
      const last = this.lastRefetch.get(agentId) || 0;
      if (now - last < this.refetchMinIntervalMs) {
        const err = new Error(`refetch rate limited: 1/min per agent (${agentId})`);
        err.code = 'REFETCH_RATE_LIMITED';
        throw err;
      }
      this.lastRefetch.set(agentId, now);
    }

    const aid = await this.aidFetcher(agentId);
    this.cache.set(agentId, { aid, fetchedAt: now });
    return aid;
  }

  /**
   * 强制重新获取（AAT 验证失败时调用）
   */
  async refetch(agentId) {
    return this.getAID(agentId, { force: true });
  }

  /**
   * 失效缓存（主动轮换密钥后调用）
   */
  invalidate(agentId) {
    this.cache.delete(agentId);
  }

  /**
   * 清空所有缓存
   */
  clear() {
    this.cache.clear();
    this.lastRefetch.clear();
  }

  /**
   * 缓存状态（诊断用）
   */
  stats() {
    const now = Date.now();
    return {
      cachedAgents: [...this.cache.keys()],
      fresh: [...this.cache.entries()].filter(([, v]) => now - v.fetchedAt < this.cacheTtlMs).length,
      stale: [...this.cache.entries()].filter(([, v]) => now - v.fetchedAt >= this.cacheTtlMs).length
    };
  }
}

module.exports = { KeyRotationManager };
