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
    // [2026-11-05 修假红] 裁剪锚点。
    //   内存只保留尾部 maxEntries 条，但 verifyChain 过去**恒定从 GENESIS 起验** →
    //   账本一旦超过 1 万行，首条的 prev_hash 指向已被裁掉的旧行，必然报
    //   `brokenAt: 0 / hash_chain_broken`，而磁盘上的链其实是完整的。
    //   实测：10005 行账本，内存保留 10000 条（首条 seq=6），verifyChain 报断，磁盘独立验链 ✅ 完整。
    //   若琢那台就是踩的这个 —— 不是被篡改，也不是并发分叉。
    //   anchorHash = 被裁掉那段的最后一条 hash（= 现存首条的 prev_hash），记忆住它就能诚实验尾部。
    this.trimmed = { count: 0, firstSeq: null, anchorHash: GENESIS_HASH };
    this._chainCache = null;
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
    // [2026-11-04 修并发断链]
    // 过去 seq/pre_hash 取的是**内存数组**（this.entries.length + 1）。
    // 两个进程共用同一账本时（A2A 重启重叠、多实例同目录），各自内存里算同样的 seq、
    // 接同样的 prev_hash → 写到磁盘就分叉。实测生产账本 694 行里 15 个 seq 重复、
    // 4 处序号倒退，GDI 验链因此整体判 chain_invalid（维度2 全 N/A）。
    // 现在：有 logPath 时**以磁盘末行为准**分配 seq/prev_hash（GDI 验的就是磁盘），
    // 并用临时锁文件把「读末行 → 算 → 写」串行化，避免并发再次分叉。
    const unlock = this.logPath ? this._acquireLock() : null;
    try {
      const seq = this.logPath ? this._nextSeqFromDisk() : this.entries.length + 1;
      const prevHash = this.logPath ? this._lastHashFromDisk() : (this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS_HASH);
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
      const drop = this.entries.length - this.maxEntries;
      const removed = this.entries.slice(0, drop);
      this.entries = this.entries.slice(drop);
      const last = removed[removed.length - 1];
      this.trimmed = {
        count: (this.trimmed.count || 0) + drop,
        firstSeq: removed[0] ? removed[0].seq : null,
        anchorHash: last ? last.hash : this.trimmed.anchorHash,
      };
    }
    this._chainCache = null; // 账本变了，缓存作废

      this._appendToDisk(record);
      return record;
    } finally {
      if (unlock) unlock();
    }
  }

  /** 取磁盘最后一条的 hash（空文件→GENESIS）。读不动就回退内存。 */
  _lastHashFromDisk() {
    const last = this._readLastLine();
    if (last && typeof last.hash === 'string') return last.hash;
    return this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS_HASH;
  }

  /** 取下一个 seq = 磁盘最后一条 seq + 1（空→1）。读不动就回退内存。 */
  _nextSeqFromDisk() {
    const last = this._readLastLine();
    if (last && Number.isInteger(last.seq)) return last.seq + 1;
    return this.entries.length + 1;
  }

  /** 读账本最后一行（容器重启/大文件也不整读） */
  _readLastLine() {
    if (!this.logPath || !fs.existsSync(this.logPath)) return null;
    try {
      const stat = fs.statSync(this.logPath);
      if (!stat.size) return null;
      // 从尾部逐步放大读取，最多回看 64KB（一条审计记录通常 <2KB）
      let size = 4096;
      for (;;) {
        const start = Math.max(0, stat.size - size);
        const fd = fs.openSync(this.logPath, 'r');
        const buf = Buffer.alloc(stat.size - start);
        try { fs.readSync(fd, buf, 0, buf.length, start); } finally { fs.closeSync(fd); }
        const chunk = buf.toString('utf8');
        const lines = chunk.split('\n').filter(Boolean);
        const tail = (start > 0 && !chunk.startsWith('\n')) ? lines.slice(1) : lines;
        if (tail.length) {
          try { return JSON.parse(tail[tail.length - 1]); } catch { /* 继续放大 */ }
        }
        if (start === 0) return null;
        size *= 4;
        if (size > 64 * 1024) size = 64 * 1024;
      }
    } catch (e) {
      console.error('[AuditLog] read tail failed:', e.message);
      return null;
    }
  }

  /**
   * 跨进程互斥（best-effort）。
   * 用 O_EXCL 建锁文件；拿不到就短暂轮询，超时就放弃直接写
   * （宁可偶发并发，也不要因锁残留把审计打死）。
   */
  _acquireLock() {
    const lockPath = `${this.logPath}.lock`;
    const deadline = Date.now() + 2000;
    for (;;) {
      try {
        const fd = fs.openSync(lockPath, 'wx');
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
        let released = false;
        return () => {
          if (released) return;
          released = true;
          try { fs.unlinkSync(lockPath); } catch { /* 已被别人清掉 */ }
        };
      } catch (e) {
        if (e.code !== 'EEXIST') return null;   // 目录不存在等 → 不锁
        if (Date.now() > deadline) {
          console.error('[AuditLog] 锁等待超时，降级直写（可能出现并发分叉）');
          return null;
        }
        // 锁残留保护：超过 10 秒视为死锁
        try {
          const st = fs.statSync(lockPath);
          if (Date.now() - st.mtimeMs > 10000) { fs.unlinkSync(lockPath); continue; }
        } catch { /* 竞态：锁刚被释放 */ }
        const until = Date.now() + 15;
        while (Date.now() < until) { /* 短暂自旋 */ }
      }
    }
  }

  /**
   * 哈希链完整性校验
   *
   * [2026-11-05 改：以磁盘为准]
   * 有 logPath 时**验磁盘**（与 GDI 验的是同一份东西），流式分块读，不整读进内存。
   * 无 logPath（纯内存模式）才验内存，并从裁剪锚点起验、如实报 partial。
   *
   * @param {{source?: 'disk'|'memory'}} [options]
   * @returns {{valid:boolean, count:number, verified:number, brokenAt:number|null,
   *            reason?:string, source:string, partial?:boolean, trimmed?:number, note?:string}}
   */
  verifyChain(options = {}) {
    const wantDisk = options.source !== 'memory' && !!this.logPath;
    if (wantDisk) {
      const r = this._verifyDisk();
      if (r) return r;
      // 磁盘读不到（权限/文件被移走）→ 退回内存，但必须标明来源，不假装验过磁盘
    }
    return this._verifyMemory();
  }

  /** 纯内存验链：从裁剪锚点起验，不假装从 GENESIS 开始 */
  _verifyMemory() {
    const skipped = this.trimmed ? this.trimmed.count : 0;
    let prevHash = skipped > 0 ? this.trimmed.anchorHash : GENESIS_HASH;
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];

      if (e.prev_hash !== prevHash) {
        return { valid: false, count: this.entries.length, verified: i, brokenAt: i, brokenAtSeq: e.seq ?? null, reason: 'hash_chain_broken', source: 'memory' };
      }

      const content = this._canonicalContent(e);
      const computed = crypto.createHash('sha256').update(content).digest('hex');
      if (computed !== e.hash) {
        return { valid: false, count: this.entries.length, verified: i, brokenAt: i, brokenAtSeq: e.seq ?? null, reason: 'entry_tampered', source: 'memory' };
      }

      if (this.publicKey && e.signature) {
        const ok = crypto.verify(null, Buffer.from(content), this.publicKey, Buffer.from(e.signature, 'base64'));
        if (!ok) {
          return { valid: false, count: this.entries.length, verified: i, brokenAt: i, brokenAtSeq: e.seq ?? null, reason: 'signature_invalid', source: 'memory' };
        }
      }

      prevHash = e.hash;
    }
    return {
      valid: true,
      count: this.entries.length,
      verified: this.entries.length,
      brokenAt: null,
      source: 'memory',
      partial: skipped > 0,
      trimmed: skipped,
      note: skipped > 0
        ? `内存仅保留尾部 ${this.entries.length} 条（已裁剪 ${skipped} 条），此处只证明尾部连续；完整链请用默认模式（走磁盘）`
        : undefined,
    };
  }

  /**
   * 从磁盘流式验链（分块读，内存占用有界）。
   * 结果按 (文件大小, 内存条数) 缓存 —— /health 会被频繁轮询，没必要每次都重算 1 万条 SHA256。
   * @returns {object|null} 读不了返回 null
   */
  _verifyDisk() {
    let stat;
    try { stat = fs.statSync(this.logPath); } catch { return null; }

    const cacheKey = `${stat.size}:${stat.mtimeMs}:${this.entries.length}`;
    if (this._chainCache && this._chainCache.key === cacheKey) return this._chainCache.result;

    if (!stat.size) {
      const empty = { valid: true, count: 0, verified: 0, brokenAt: null, source: 'disk' };
      this._chainCache = { key: cacheKey, result: empty };
      return empty;
    }

    const { StringDecoder } = require('string_decoder');
    const decoder = new StringDecoder('utf8');
    const CHUNK = 1 << 20; // 1MB
    const buf = Buffer.alloc(CHUNK);
    let fd;
    try { fd = fs.openSync(this.logPath, 'r'); } catch { return null; }

    let prevHash = GENESIS_HASH;
    let pos = 0, lineNo = 0, verified = 0, badLines = 0, firstSeq = null, lastSeq = null;
    let remainder = '';
    let broken = null;

    const handleLine = (raw) => {
      if (broken) return;
      if (!raw.trim()) return;
      lineNo++;
      let e;
      try { e = JSON.parse(raw); } catch { badLines++; return; }
      if (firstSeq === null) firstSeq = e.seq ?? null;
      lastSeq = e.seq ?? null;

      if (e.prev_hash !== prevHash) {
        broken = { valid: false, count: lineNo, verified, brokenAt: lineNo - 1, brokenAtSeq: e.seq ?? null, reason: 'hash_chain_broken', source: 'disk' };
        return;
      }
      const content = this._canonicalContent(e);
      const computed = crypto.createHash('sha256').update(content).digest('hex');
      if (computed !== e.hash) {
        broken = { valid: false, count: lineNo, verified, brokenAt: lineNo - 1, brokenAtSeq: e.seq ?? null, reason: 'entry_tampered', source: 'disk' };
        return;
      }
      if (this.publicKey && e.signature) {
        const ok = crypto.verify(null, Buffer.from(content), this.publicKey, Buffer.from(e.signature, 'base64'));
        if (!ok) {
          broken = { valid: false, count: lineNo, verified, brokenAt: lineNo - 1, brokenAtSeq: e.seq ?? null, reason: 'signature_invalid', source: 'disk' };
          return;
        }
      }
      prevHash = e.hash;
      verified++;
    };

    try {
      for (;;) {
        const n = fs.readSync(fd, buf, 0, CHUNK, pos);
        if (n <= 0) break;
        pos += n;
        const text = remainder + decoder.write(buf.subarray(0, n));
        const lines = text.split('\n');
        remainder = lines.pop();
        for (const line of lines) handleLine(line);
        if (broken) break;
      }
      if (!broken) {
        const tail = remainder + decoder.end();
        if (tail.trim()) handleLine(tail);
      }
    } finally {
      try { fs.closeSync(fd); } catch { /* noop */ }
    }

    const result = broken || {
      valid: true,
      count: lineNo,
      verified,
      brokenAt: null,
      source: 'disk',
      firstSeq,
      lastSeq,
      badLines,
    };
    this._chainCache = { key: cacheKey, result };
    return result;
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
      chainValid: this.verifyChain().valid,
      // 内存中只是尾部：把「看得到的」与「账本里有的」分开报，不让人把局部当全局
      inMemory: this.entries.length,
      trimmed: this.trimmed ? this.trimmed.count : 0,
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
      const parsed = [];
      let bad = 0;
      for (const l of lines) {
        try { parsed.push(JSON.parse(l)); } catch { bad++; }
      }
      if (bad) console.error(`[AuditLog] disk load: ${bad} 行无法解析，已跳过（对应行仍留在磁盘上）`);
      // [2026-11-05] 载入时也遵守 maxEntries：过去全量装进内存（1 万条以上白白占内存），
      //   而且不设锚点 → verifyChain 必假红。现在同步设裁剪锚点，让内存验链也诚实。
      if (parsed.length > this.maxEntries) {
        const drop = parsed.length - this.maxEntries;
        const removedTail = parsed[drop - 1];
        this.entries = parsed.slice(drop);
        this.trimmed = {
          count: drop,
          firstSeq: parsed[0] ? parsed[0].seq : null,
          anchorHash: removedTail ? removedTail.hash : GENESIS_HASH,
        };
      } else {
        this.entries = parsed;
        this.trimmed = { count: 0, firstSeq: null, anchorHash: GENESIS_HASH };
      }
      this._chainCache = null;
    } catch (e) {
      console.error('[AuditLog] disk load failed:', e.message);
    }
  }
}

module.exports = { AuditLog, GENESIS_HASH };
