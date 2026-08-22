/**
 * CSB-Security Layer 4: 重放攻击防护
 *
 * 协议: CSB-Security v1.0 §5.1
 * 机制:
 *  - Nonce: 每个请求随机 Nonce，验证方维护已见 Nonce 缓存
 *  - 时间戳: 偏差 > 5 分钟的消息拒绝
 *  - jti 唯一标识: AAT/UAC 的 jti 必须唯一，重复拒绝
 *  - 序列号: 消息包含单调递增序列号，检测重放
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M4)
 */

const MAX_TIME_DRIFT_MS = 5 * 60 * 1000; // 时间戳偏差 > 5 分钟拒绝

class ReplayGuard {
  /**
   * @param {Object} options
   *   - ttlMs: 缓存 TTL（默认 5 分钟）
   *   - maxEntries: 缓存最大条目（默认 100000）
   *   - now: 时间函数（测试用）
   */
  constructor({ ttlMs = MAX_TIME_DRIFT_MS, maxEntries = 100000, now = () => Date.now() } = {}) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.now = now;
    this.nonces = new Map();    // nonce -> seenAt
    this.jtis = new Map();      // jti -> seenAt
    this.sequences = new Map(); // agentId -> lastSeq
  }

  /**
   * 检查并记录 Nonce（防重放）
   * @returns {{allowed: boolean, error?: string}}
   */
  checkNonce(nonce) {
    if (!nonce) return { allowed: false, error: 'missing_nonce' };
    const now = this.now();
    const seenAt = this.nonces.get(nonce);
    if (seenAt !== undefined) {
      if (now - seenAt > this.ttlMs) {
        this.nonces.delete(nonce); // TTL 过期，释放
      } else {
        return { allowed: false, error: 'nonce_replay' };
      }
    }
    this.nonces.set(nonce, now);
    this._evictIfNeeded(this.nonces);
    return { allowed: true };
  }

  /**
   * 检查时间戳（防重放，协议 §5.1）
   */
  checkTimestamp(timestamp) {
    if (!timestamp) return { allowed: false, error: 'missing_timestamp' };
    const ts = new Date(timestamp).getTime();
    if (Number.isNaN(ts)) return { allowed: false, error: 'bad_timestamp' };
    if (Math.abs(this.now() - ts) > MAX_TIME_DRIFT_MS) {
      return { allowed: false, error: 'time_drift' };
    }
    return { allowed: true };
  }

  /**
   * 检查并记录 jti（AAT/UAC 防重放，协议 §5.1）
   */
  checkJti(jti) {
    if (!jti) return { allowed: false, error: 'missing_jti' };
    const now = this.now();
    const seenAt = this.jtis.get(jti);
    if (seenAt !== undefined) {
      if (now - seenAt > this.ttlMs) {
        this.jtis.delete(jti); // TTL 过期，释放
      } else {
        return { allowed: false, error: 'jti_replay' };
      }
    }
    this.jtis.set(jti, now);
    this._evictIfNeeded(this.jtis);
    return { allowed: true };
  }

  /**
   * 检查序列号（单调递增，可选机制，协议 §5.1）
   * @param {string} agentId
   * @param {number} seq
   */
  checkSequence(agentId, seq) {
    if (typeof seq !== 'number' || seq < 0) return { allowed: false, error: 'bad_sequence' };
    const last = this.sequences.get(agentId);
    if (last !== undefined && seq <= last) {
      return { allowed: false, error: 'sequence_replay' };
    }
    this.sequences.set(agentId, seq);
    return { allowed: true };
  }

  /**
   * 清理过期条目
   */
  cleanup() {
    const now = this.now();
    for (const [key, seenAt] of this.nonces) {
      if (now - seenAt > this.ttlMs) this.nonces.delete(key);
    }
    for (const [key, seenAt] of this.jtis) {
      if (now - seenAt > this.ttlMs) this.jtis.delete(key);
    }
  }

  /**
   * 状态统计
   */
  stats() {
    return {
      nonces: this.nonces.size,
      jtis: this.jtis.size,
      sequences: this.sequences.size
    };
  }

  _evictIfNeeded(map) {
    if (map.size > this.maxEntries) {
      const now = this.now();
      for (const [key, seenAt] of map) {
        if (map.size <= this.maxEntries * 0.8) break;
        if (now - seenAt > this.ttlMs) map.delete(key);
      }
    }
  }
}

module.exports = { ReplayGuard, MAX_TIME_DRIFT_MS };
