/**
 * CSB-Security Layer 4: 异常检测（规则引擎）
 *
 * 协议: CSB-Security v1.0 §5.3 异常模式检测
 *
 * 规则（可配置）:
 *  - rapid_failures:        单 Agent 窗口内连续失败 ≥10 次 → 自动暂停 + 告警（high）
 *  - many_agents_single_ip: 同一 IP 窗口内 ≥5 个不同 Agent → 可疑标记（medium）
 *  - rapid_aid_registration: 单 Agent 窗口内注册新 AID ≥5 次 → 告警（high）
 *  - rapid_key_rotation:    单 Agent 窗口内密钥轮换 ≥3 次 → 告警（medium）
 *  - audit_tamper:          审计哈希链校验失败 → 单次即触发最高级告警（critical）
 *
 * 事件入口: recordEvent({ type, agentId, ip, detail })
 * 事件类型: failure | success | aid_registration | key_rotation | audit_tamper
 *
 * 设计说明:
 *  - M4 的 rate-limiter 已落地规则 ①②（连续失败暂停 + 同 IP 多 Agent 标记）
 *  - M5 抽象为可配置规则引擎，新增规则 ③④⑤，并提供统一告警通道
 *  - 集成时可将 rate-limiter 的 recordFailure/recordSuccess 桥接到本引擎
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M5)
 */

const DEFAULT_RULES = {
  // 规则 ①: 连续失败 → 暂停 + 告警
  rapid_failures: {
    threshold: 10,          // 窗口内失败次数阈值
    windowMs: 60 * 1000,    // 滑动窗口
    suspendMs: 60 * 1000,   // 暂停时长
    severity: 'high'
  },
  // 规则 ②: 同一 IP 多个不同 Agent → 可疑
  many_agents_single_ip: {
    threshold: 5,
    windowMs: 60 * 1000,
    severity: 'medium'
  },
  // 规则 ③: 高频 AID 注册 → 告警
  rapid_aid_registration: {
    threshold: 5,
    windowMs: 60 * 1000,
    severity: 'high'
  },
  // 规则 ④: 高频密钥轮换 → 告警
  rapid_key_rotation: {
    threshold: 3,
    windowMs: 60 * 1000,
    severity: 'medium'
  },
  // 规则 ⑤: 审计篡改 → 单次即触发
  audit_tamper: {
    threshold: 1,
    windowMs: 0,            // 无窗口，立即触发
    severity: 'critical'
  }
};

const MAX_ALERTS = 100; // 告警历史上限

class AnomalyDetector {
  /**
   * @param {Object} options
   *   - rules: 覆盖默认规则（按规则名部分覆盖）
   *   - now: 时间函数（测试用）
   *   - onAlert: 告警回调 (alert) => void（默认收集到 alerts 数组）
   *   - suspendFn: 暂停动作注入 (agentId, untilMs) => void（默认内部维护）
   */
  constructor({ rules = {}, now = () => Date.now(), onAlert = null, suspendFn = null } = {}) {
    this.rules = {};
    for (const [name, cfg] of Object.entries(DEFAULT_RULES)) {
      this.rules[name] = { ...cfg, ...(rules[name] || {}) };
    }
    this.now = now;
    this.onAlert = onAlert;
    this.suspendFn = suspendFn;

    // 滑动窗口计数: rule -> key -> [timestamps]
    this.windows = new Map();
    // 暂停表: agentId -> until
    this.suspended = new Map();
    // 同 IP Agent 集合: ip -> Set<agentId>
    this.ipAgents = new Map();
    // 告警历史
    this.alerts = [];
    // 事件计数（统计用）
    this.eventCounts = new Map();
  }

  /**
   * 统一事件入口
   *
   * @param {Object} evt - { type, agentId, ip, detail }
   * @returns {Array<Object>} 本次触发的新告警列表
   */
  recordEvent({ type, agentId = 'unknown', ip = 'unknown', detail = null } = {}) {
    if (!type) return [];
    const now = this.now();
    const triggered = [];

    this.eventCounts.set(type, (this.eventCounts.get(type) || 0) + 1);

    switch (type) {
      case 'failure':
        triggered.push(...this._checkFailure(agentId, ip, now));
        break;
      case 'success':
        this._recordSuccess(agentId);
        break;
      case 'aid_registration':
        triggered.push(...this._checkWindow('rapid_aid_registration', `aid:${agentId}`, agentId, ip, now));
        break;
      case 'key_rotation':
        triggered.push(...this._checkWindow('rapid_key_rotation', `key:${agentId}`, agentId, ip, now));
        break;
      case 'audit_tamper':
        triggered.push(...this._checkWindow('audit_tamper', `tamper:${agentId}`, agentId, ip, now, { detail }));
        break;
      default:
        break;
    }

    for (const alert of triggered) this._emit(alert);
    return triggered;
  }

  /**
   * 便捷方法: 记录一次失败（认证/授权/重放/限流拒绝）
   */
  recordFailure(agentId, ip = 'unknown', detail = null) {
    return this.recordEvent({ type: 'failure', agentId, ip, detail });
  }

  /**
   * 便捷方法: 记录一次成功（重置失败计数）
   */
  recordSuccess(agentId, ip = 'unknown') {
    return this.recordEvent({ type: 'success', agentId, ip });
  }

  /**
   * 便捷方法: 记录新 AID 注册
   */
  recordAidRegistration(agentId, ip = 'unknown', detail = null) {
    return this.recordEvent({ type: 'aid_registration', agentId, ip, detail });
  }

  /**
   * 便捷方法: 记录密钥轮换
   */
  recordKeyRotation(agentId, ip = 'unknown', detail = null) {
    return this.recordEvent({ type: 'key_rotation', agentId, ip, detail });
  }

  /**
   * 便捷方法: 记录审计篡改（最高级）
   */
  recordAuditTamper(agentId = 'unknown', detail = null) {
    return this.recordEvent({ type: 'audit_tamper', agentId, detail });
  }

  /**
   * 查询 Agent 是否被暂停
   */
  isSuspended(agentId) {
    const until = this.suspended.get(agentId);
    return !!(until && until > this.now());
  }

  /**
   * 查询 Agent 被暂停到何时（0 = 未暂停）
   */
  suspendedUntil(agentId) {
    const until = this.suspended.get(agentId) || 0;
    return until > this.now() ? until : 0;
  }

  /**
   * 手动解除暂停
   */
  unsuspend(agentId) {
    this.suspended.delete(agentId);
  }

  /**
   * 查询可疑 IP
   */
  suspiciousIps() {
    const now = this.now();
    const result = [];
    for (const [ip, agents] of this.ipAgents) {
      const active = [...agents].filter(a => {
        const ts = this.windows.get(`ip:${ip}`) || [];
        return ts.some(t => now - t < this.rules.many_agents_single_ip.windowMs);
      });
      if (agents.size >= this.rules.many_agents_single_ip.threshold || active.length > 0) {
        result.push(ip);
      }
    }
    return result;
  }

  /**
   * 状态统计
   */
  stats() {
    const now = this.now();
    return {
      rules: Object.fromEntries(
        Object.entries(this.rules).map(([k, v]) => [k, { threshold: v.threshold, windowMs: v.windowMs, severity: v.severity }])
      ),
      suspendedAgents: [...this.suspended.entries()]
        .filter(([, until]) => until > now)
        .map(([k]) => k),
      suspiciousIps: this.suspiciousIps(),
      alertCount: this.alerts.length,
      lastAlert: this.alerts[this.alerts.length - 1] || null,
      eventCounts: Object.fromEntries(this.eventCounts)
    };
  }

  /**
   * 重置全部状态（测试/热重载用）
   */
  reset() {
    this.windows.clear();
    this.suspended.clear();
    this.ipAgents.clear();
    this.alerts = [];
    this.eventCounts.clear();
  }

  // ============ 内部 ============

  _checkFailure(agentId, ip, now) {
    const rule = this.rules.rapid_failures;
    const triggered = [];

    // 暂停期间失败不累计（避免暂停中重复触发告警）
    if (this.isSuspended(agentId)) return triggered;


    // 同 IP 多 Agent 检测（规则 ②）
    if (ip !== 'unknown' && agentId !== 'unknown') {
      const agents = this.ipAgents.get(ip) || new Set();
      agents.add(agentId);
      this.ipAgents.set(ip, agents);
      if (agents.size >= this.rules.many_agents_single_ip.threshold) {
        triggered.push(this._makeAlert('many_agents_single_ip', {
          agentId, ip,
          count: agents.size,
          message: `IP ${ip} 出现 ${agents.size} 个不同 Agent，疑似批量伪装`
        }));
      }
    }

    // 连续失败检测（规则 ①）
    const key = `fail:${agentId}`;
    const hits = this._hit(key, rule.windowMs, now);
    if (hits.length >= rule.threshold) {
      this._suspend(agentId, now + rule.suspendMs);
      triggered.push(this._makeAlert('rapid_failures', {
        agentId, ip,
        count: hits.length,
        message: `Agent ${agentId} ${rule.windowMs / 1000}s 内连续失败 ${hits.length} 次，已自动暂停 ${rule.suspendMs / 1000}s`
      }));
      this.windows.delete(key); // 暂停后清空窗口，避免重复触发
    }

    return triggered;
  }

  _recordSuccess(agentId) {
    // 成功重置失败窗口
    this.windows.delete(`fail:${agentId}`);
    // 同时解除自动暂停（若有）
    this.suspended.delete(agentId);
  }

  _checkWindow(ruleName, key, agentId, ip, now, extra = {}) {
    const rule = this.rules[ruleName];
    if (!rule) return [];
    const hits = this._hit(key, rule.windowMs, now);
    if (hits.length >= rule.threshold) {
      this.windows.delete(key); // 触发后清空，避免窗口内重复告警
      const names = {
        rapid_aid_registration: 'rapid_aid_registration',
        rapid_key_rotation: 'rapid_key_rotation',
        audit_tamper: 'audit_tamper'
      };
      const messages = {
        rapid_aid_registration: `Agent ${agentId} ${rule.windowMs / 1000}s 内注册新 AID ${hits.length} 次，疑似身份伪造`,
        rapid_key_rotation: `Agent ${agentId} ${rule.windowMs / 1000}s 内密钥轮换 ${hits.length} 次，疑似轮换异常`,
        audit_tamper: `审计日志哈希链校验失败（${extra.detail || '未知原因'}），疑似篡改`
      };
      return [this._makeAlert(names[ruleName] || ruleName, {
        agentId, ip,
        count: hits.length,
        message: messages[ruleName] || `${ruleName} 触发`,
        detail: extra.detail || null
      })];
    }
    return [];
  }

  /**
   * 滑动窗口命中记录，返回窗口内全部时间戳
   */
  _hit(key, windowMs, now) {
    let timestamps = this.windows.get(key) || [];
    timestamps = timestamps.filter(t => now - t < windowMs);
    timestamps.push(now);
    this.windows.set(key, timestamps);
    return timestamps;
  }

  _suspend(agentId, until) {
    this.suspended.set(agentId, until);
    if (this.suspendFn) {
      try { this.suspendFn(agentId, until); } catch (e) { /* 注入动作失败不影响主流程 */ }
    }
  }

  _makeAlert(rule, { agentId, ip, count, message, detail = null }) {
    return {
      rule,
      severity: this.rules[rule]?.severity || 'info',
      agentId,
      ip,
      count,
      message,
      detail,
      timestamp: this.now()
    };
  }

  _emit(alert) {
    this.alerts.push(alert);
    if (this.alerts.length > MAX_ALERTS) this.alerts.shift();
    if (this.onAlert) {
      try { this.onAlert(alert); } catch (e) { /* 回调异常不阻断 */ }
    }
  }
}

module.exports = {
  AnomalyDetector,
  DEFAULT_RULES,
  MAX_ALERTS
};
