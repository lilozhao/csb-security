/**
 * CSB-Security Layer 5: 审计查询（协议 §6.3）
 *
 * 可追溯性支持:
 *  - 按 Agent ID 查询所有交互记录
 *  - 按时间范围查询
 *  - 按事件类型查询
 *  - 按权限范围查询
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M4)
 */

class AuditQuery {
  constructor(auditLog) {
    this.auditLog = auditLog;
  }

  /**
   * 按 Agent ID 查询（caller 或 callee）
   */
  byAgent(agentId, options = {}) {
    return this.auditLog.query({ agentId, ...options });
  }

  /**
   * 按事件类型查询
   */
  byEventType(eventType, options = {}) {
    return this.auditLog.query({ eventType, ...options });
  }

  /**
   * 按时间范围查询
   */
  byTimeRange(from, to, options = {}) {
    return this.auditLog.query({ from, to, ...options });
  }

  /**
   * 按权限范围查询
   */
  byScope(scope, options = {}) {
    return this.auditLog.query({ scope, ...options });
  }

  /**
   * 单个 Agent 的完整交互轨迹（含时间线）
   */
  agentTimeline(agentId) {
    const records = this.byAgent(agentId);
    return records.map(r => ({
      seq: r.seq,
      timestamp: r.timestamp,
      event: r.event_type,
      counterpart: r.caller_id === agentId ? r.callee_id : r.caller_id,
      direction: r.caller_id === agentId ? 'outbound' : 'inbound',
      scopes: r.scopes_granted,
      result: r.result
    }));
  }

  /**
   * 安全事件摘要（失败/拒绝类）
   */
  securitySummary(agentId = null) {
    const records = agentId ? this.byAgent(agentId) : this.auditLog.entries;
    const failed = records.filter(r => r.result !== 'success');
    const denied = records.filter(r => (r.scopes_denied || []).length > 0);
    return {
      total: records.length,
      failed: failed.length,
      scopeDenials: denied.length,
      failedEvents: failed.slice(-10).map(r => ({
        seq: r.seq, timestamp: r.timestamp, event: r.event_type, result: r.result
      }))
    };
  }
}

module.exports = { AuditQuery };
