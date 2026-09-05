/**
 * CSB-Security Layer 5: 审计日志（哈希链不可篡改）
 *
 * 协议: CSB-Security v1.0 §6.1 / §6.2
 *
 * 不可篡改存储:
 *   log[i].prev_hash = SHA256(log[i-1])
 *   log[i].signature = Sign(log[i].content + log[i].prev_hash)
 *
 * 追加写入模式，支持:
 *  - 哈希链完整性校验（篡改必检出）
 *  - 每条记录 Ed25519 签名（配置密钥时）
 *  - 内存模式 + 文件落盘模式
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M4)
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const GENESIS_HASH = 'GENESIS';

class AuditLog {
  /**
   * @param {Object} options
   *   - logPath: 落盘路径（可选；不传则纯内存）
   *   - privateKey: Ed25519 私钥（KeyObject，可选；配置后每条签名）
   *   - publicKey: Ed25519 公钥（KeyObject，可选；verifyChain 时验签）
   *   - maxEntries: 内存最大条数（默认 10000）
   */
  constructor({ logPath = null, privateKey = null, publicKey = null, maxEntries = 10000 } = {}) {
    this.logPath = logPath;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.maxEntries = maxEntries;
    this.entries = [];
    this._loadFromDisk();
  }

  /**
   * 追加审计记录
   *
   * @param {Object} entry 协议 §6.1 结构
   *   event_type, caller_id, callee_id, user_id,
   *   scopes_requested, scopes_granted, scopes_denied,
   *   trust_level, session_id, ip_address, result
   * @returns {Object} 完整记录（含 seq/timestamp/prev_hash/hash/signature）
   */
  append(entry, extra = {}) {
    const seq = this.entries.length + 1;
    const prev = this.entries[this.entries.length - 1];
    const prevHash = prev ? prev.hash : GENESIS_HASH;

    const record = {
      seq,
      timestamp: new Date().toISOString(),
      event_type: entry.event_type,
      caller_id: entry.caller_id || null,
      callee_id: entry.callee_id || null,
      user_id: entry.user_id || null,
      scopes_requested: entry.scopes_requested || [],
      scopes_granted: entry.scopes_granted || [],
      scopes_denied: entry.scopes_denied || [],
      trust_level: entry.trust_level || null,
      session_id: entry.session_id || null,
      ip_address: entry.ip_address || null,
      result: entry.result || 'success',
      prev_hash: prevHash
    };

    // 扩展字段（如 verif-log 全量存证）——自动纳入哈希计算，不可篡改；
    // 过滤保留字段，防止覆盖链核心结构。
    if (extra && typeof extra === 'object') {
      const RESERVED = new Set(['seq', 'timestamp', 'prev_hash', 'hash', 'signature',
        'event_type', 'caller_id', 'callee_id', 'user_id', 'scopes_requested',
        'scopes_granted', 'scopes_denied', 'trust_level', 'session_id', 'ip_address', 'result']);
      for (const [k, v] of Object.entries(extra)) {
        if (!RESERVED.has(k)) record[k] = v;
      }
    }

    // 计算本条哈希（内容 = 记录本身，不含 hash/signature 字段）
    const content = this._canonicalContent(record);
    record.hash = crypto.createHash('sha256').update(content).digest('hex');

    // Ed25519 签名
    if (this.privateKey) {
      record.signature = crypto.sign(null, Buffer.from(content), this.privateKey).toString('base64');
    }

    this.entries.push(record);
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(-this.maxEntries);
    }

    this._appendToDisk(record);
    return record;
  }

  /**
   * 哈希链完整性校验
   * @returns {{valid: boolean, count?: number, brokenAt?: number, reason?: string}}
   */
  verifyChain() {
    let prevHash = GENESIS_HASH;
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];

      if (e.prev_hash !== prevHash) {
        return { valid: false, brokenAt: i, reason: 'hash_chain_broken' };
      }

      const content = this._canonicalContent(e);
      const computed = crypto.createHash('sha256').update(content).digest('hex');
      if (computed !== e.hash) {
        return { valid: false, brokenAt: i, reason: 'entry_tampered' };
      }

      if (this.publicKey && e.signature) {
        const ok = crypto.verify(null, Buffer.from(content), this.publicKey, Buffer.from(e.signature, 'base64'));
        if (!ok) {
          return { valid: false, brokenAt: i, reason: 'signature_invalid' };
        }
      }

      prevHash = e.hash;
    }
    return { valid: true, count: this.entries.length };
  }

  /**
   * 单条记录验签
   */
  verifyEntry(index) {
    const e = this.entries[index];
    if (!e) return { valid: false, error: 'not_found' };
    if (!this.publicKey || !e.signature) return { valid: true, note: 'no_signature_configured' };
    const content = this._canonicalContent(e);
    const ok = crypto.verify(null, Buffer.from(content), this.publicKey, Buffer.from(e.signature, 'base64'));
    return ok ? { valid: true } : { valid: false, error: 'signature_invalid' };
  }

  /**
   * 查询（协议 §6.3）
   * @param {Object} filters - { agentId, eventType, from, to, scope, limit }
   */
  query(filters = {}) {
    let results = this.entries;

    if (filters.agentId) {
      const id = filters.agentId;
      results = results.filter(e => e.caller_id === id || e.callee_id === id);
    }
    if (filters.eventType) {
      results = results.filter(e => e.event_type === filters.eventType);
    }
    if (filters.from) {
      results = results.filter(e => new Date(e.timestamp) >= new Date(filters.from));
    }
    if (filters.to) {
      results = results.filter(e => new Date(e.timestamp) <= new Date(filters.to));
    }
    if (filters.scope) {
      results = results.filter(e =>
        e.scopes_requested.includes(filters.scope) || e.scopes_granted.includes(filters.scope)
      );
    }
    if (filters.limit) {
      results = results.slice(-filters.limit);
    }
    return results;
  }

  /**
   * 统计摘要
   */
  summary() {
    const byEvent = {};
    const byResult = {};
    const agents = new Set();
    for (const e of this.entries) {
      byEvent[e.event_type] = (byEvent[e.event_type] || 0) + 1;
      byResult[e.result] = (byResult[e.result] || 0) + 1;
      if (e.caller_id) agents.add(e.caller_id);
      if (e.callee_id) agents.add(e.callee_id);
    }
    return {
      total: this.entries.length,
      byEvent,
      byResult,
      agents: [...agents],
      chainValid: this.verifyChain().valid
    };
  }

  /**
   * 导出全部记录
   */
  exportJSON() {
    return JSON.stringify(this.entries, null, 2);
  }

  // ============ 内部 ============

  _canonicalContent(record) {
    const { hash, signature, ...rest } = record;
    return JSON.stringify(rest);
  }

  _appendToDisk(record) {
    if (!this.logPath) return;
    try {
      fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
      fs.appendFileSync(this.logPath, JSON.stringify(record) + '\n');
    } catch (e) {
      // 落盘失败不阻断内存审计（记录到 stderr）
      console.error('[AuditLog] disk append failed:', e.message);
    }
  }

  _loadFromDisk() {
    if (!this.logPath || !fs.existsSync(this.logPath)) return;
    try {
      const lines = fs.readFileSync(this.logPath, 'utf8').split('\n').filter(Boolean);
      this.entries = lines.map(l => JSON.parse(l));
    } catch (e) {
      console.error('[AuditLog] disk load failed:', e.message);
    }
  }
}

module.exports = { AuditLog, GENESIS_HASH };
