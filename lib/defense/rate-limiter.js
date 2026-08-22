/**
 * CSB-Security Layer 4: 速率限制 + 异常检测
 *
 * 协议: CSB-Security v1.0 §5.3
 * 限制:
 *  - 单 Agent: 60 请求/分钟
 *  - 单 IP:   200 请求/分钟
 *  - 全局:    1000 请求/分钟
 *
 * 异常模式检测:
 *  - 同一 Agent 短时间内大量失败请求 → 自动暂停 + 告警
 *  - 同一 IP 多个不同 Agent 请求 → 标记可疑
 *
 * 实现: 滑动窗口计数（时间戳数组）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M4)
 */

const DEFAULT_LIMITS = {
  agent: 60,    // 单 Agent 60/min（协议 §5.3）
  ip: 200,      // 单 IP 200/min
  global: 1000  // 全局 1000/min
};

const SUSPEND_THRESHOLD = 10;     // 10 次连续失败触发暂停
const SUSPEND_DURATION_MS = 60 * 1000; // 暂停 1 分钟
const SUSPICIOUS_AGENTS_PER_IP = 5; // 同一 IP 出现 5+ 个不同 Agent → 可疑

class RateLimiter {
  /**
   * @param {Object} options
   *   - limits: { agent, ip, global } 覆盖默认
   *   - windowMs: 窗口（默认 60000）
   *   - now: 时间函数（测试用）
   */
  constructor({ limits = {}, windowMs = 60000, now = () => Date.now() } = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.windowMs = windowMs;
    this.now = now;
    this.windows = { agent: new Map(), ip: new Map(), global: [] };
    this.failures = new Map();   // agentId -> { count, suspendedUntil }
    this.ipAgents = new Map();   // ip -> Set<agentId>
  }

  /**
   * 记录一次请求，返回是否允许
   *
   * @param {Object} req - { agentId, ip }
   * @returns {{allowed: boolean, remaining?: number, retryAfterMs?: number, reason?: string, suspicious?: boolean}}
   */
  check({ agentId = 'unknown', ip = 'unknown' } = {}) {
    const now = this.now();

    // 暂停检查
    const susp = this.failures.get(agentId);
    if (susp && susp.suspendedUntil > now) {
      return {
        allowed: false,
        reason: 'agent_suspended',
        retryAfterMs: susp.suspendedUntil - now
      };
    }

    // 单 Agent 限流
    const agentOk = this._hit('agent', agentId, this.limits.agent, now);
    if (!agentOk.allowed) return agentOk;

    // 单 IP 限流
    const ipOk = this._hit('ip', ip, this.limits.ip, now);
    if (!ipOk.allowed) return ipOk;

    // 全局限流
    const globalOk = this._hit('global', 'global', this.limits.global, now);
    if (!globalOk.allowed) return globalOk;

    // 同一 IP 多 Agent 可疑检测
    if (ip !== 'unknown' && agentId !== 'unknown') {
      const agents = this.ipAgents.get(ip) || new Set();
      agents.add(agentId);
      this.ipAgents.set(ip, agents);
      if (agents.size >= SUSPICIOUS_AGENTS_PER_IP) {
        return { allowed: true, suspicious: true, reason: 'many_agents_single_ip' };
      }
    }

    return { allowed: true };
  }

  /**
   * 记录失败（异常检测：连续失败 → 自动暂停）
   */
  recordFailure(agentId) {
    const now = this.now();
    const rec = this.failures.get(agentId) || { count: 0, suspendedUntil: 0 };
    rec.count++;
    if (rec.count >= SUSPEND_THRESHOLD) {
      rec.suspendedUntil = now + SUSPEND_DURATION_MS;
      rec.count = 0; // 重置计数，等待暂停结束
      this.failures.set(agentId, rec);
      return { suspended: true, until: rec.suspendedUntil };
    }
    this.failures.set(agentId, rec);
    return { suspended: false, failures: rec.count };
  }

  /**
   * 记录成功（重置失败计数）
   */
  recordSuccess(agentId) {
    this.failures.delete(agentId);
  }

  /**
   * 查询是否被暂停
   */
  isSuspended(agentId) {
    const rec = this.failures.get(agentId);
    return !!(rec && rec.suspendedUntil > this.now());
  }

  /**
   * 清理过期窗口数据
   */
  cleanup() {
    const now = this.now();
    for (const type of ['agent', 'ip']) {
      const map = this.windows[type];
      for (const [key, timestamps] of map) {
        const fresh = timestamps.filter(t => now - t < this.windowMs);
        if (fresh.length === 0) map.delete(key);
        else map.set(key, fresh);
      }
    }
    this.windows.global = this.windows.global.filter(t => now - t < this.windowMs);
  }

  /**
   * 状态统计
   */
  stats() {
    return {
      agentKeys: this.windows.agent.size,
      ipKeys: this.windows.ip.size,
      globalCount: this.windows.global.length,
      suspendedAgents: [...this.failures.entries()]
        .filter(([, v]) => v.suspendedUntil > this.now())
        .map(([k]) => k),
      suspiciousIps: [...this.ipAgents.entries()]
        .filter(([, v]) => v.size >= SUSPICIOUS_AGENTS_PER_IP)
        .map(([k]) => k)
    };
  }

  // ============ 内部 ============

  _hit(type, key, limit, now) {
    let window;
    if (type === 'global') {
      window = this.windows.global;
    } else {
      window = this.windows[type].get(key) || [];
    }

    // 清理过期
    const fresh = window.filter(t => now - t < this.windowMs);

    if (fresh.length >= limit) {
      const oldest = fresh[0];
      const retryAfterMs = this.windowMs - (now - oldest);
      return {
        allowed: false,
        reason: `${type}_rate_limited`,
        retryAfterMs: Math.max(0, retryAfterMs)
      };
    }

    fresh.push(now);
    if (type === 'global') {
      this.windows.global = fresh;
    } else {
      this.windows[type].set(key, fresh);
    }
    return { allowed: true, remaining: limit - fresh.length };
  }
}

module.exports = {
  RateLimiter,
  DEFAULT_LIMITS,
  SUSPEND_THRESHOLD,
  SUSPEND_DURATION_MS
};
