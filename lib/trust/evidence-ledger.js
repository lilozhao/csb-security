/**
 * CSB-Security Layer 2: 证据账本（Evidence Ledger）
 *
 * 信任升级设计的「事实层」（TRUST-UPGRADE-DESIGN.md §四）
 *
 * 设计要点：
 *   - 只追加（append-only），一条一行 JSONL
 *   - 每条 prev_hash 串前一条（防删除/插入），自身 hash 覆盖内容
 *   - 配置密钥时逐条 Ed25519 签名（防本地篡改）
 *   - 账本只记「发生了什么」，不记消息内容（只留 ref + hash）——隐私红线
 *
 * 与 audit-log.js 的区别：audit 记「一次访问的授权结果」，账本记「一条信任证据」。
 * 两者哈希链思路一致，但账本是信任等级的**派生输入**（可重放重建等级）。
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-09-11 (P0)
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const GENESIS_HASH = 'GENESIS';

/** 证据类型（kind） */
const KIND = Object.freeze({
  IDENTITY: 'identity',            // 身份验证：握手/AAT/AID
  INTERACTION: 'interaction',      // 交互：消息/委托/守卫事件
  WITNESS: 'witness',              // 第三方见证
  AUTHORIZATION: 'authorization',  // 宿主用户授权（含宽恕）
  ATTESTATION: 'attestation',      // 追溯认定（存量关系）
  REVOCATION: 'revocation',        // 撤销
  DOWNGRADE: 'downgrade',          // 降级
});

/** 极性 */
const POLARITY = Object.freeze({ POSITIVE: 1, NEUTRAL: 0, NEGATIVE: -1 });

/**
 * 动作 → { kind, polarity, weight } 默认计分表
 *
 * weight 是分档权重（不是布尔）；polarity 0 = 留痕不计分。
 * 协议依据：TRUST-UPGRADE-DESIGN.md §4.2
 */
const ACTIONS = Object.freeze({
  // --- 正向 ---
  handshake_completed:   { kind: KIND.IDENTITY,      polarity: POLARITY.POSITIVE, weight: 2 },
  message_ok:            { kind: KIND.INTERACTION,   polarity: POLARITY.POSITIVE, weight: 1 },
  delegate_completed:    { kind: KIND.INTERACTION,   polarity: POLARITY.POSITIVE, weight: 2 },
  witness_confirmed:     { kind: KIND.WITNESS,       polarity: POLARITY.POSITIVE, weight: 1 },
  retroactive_attestation: { kind: KIND.ATTESTATION, polarity: POLARITY.POSITIVE, weight: 0 },
  user_authorized:       { kind: KIND.AUTHORIZATION, polarity: POLARITY.POSITIVE, weight: 0 },
  forgiveness:           { kind: KIND.AUTHORIZATION, polarity: POLARITY.POSITIVE, weight: 0 },

  // --- 中性（留痕不计分）---
  user_declined:         { kind: KIND.INTERACTION,   polarity: POLARITY.NEUTRAL,  weight: 0 },
  rate_capped:           { kind: KIND.INTERACTION,   polarity: POLARITY.NEUTRAL,  weight: 0 },

  // --- 负向 ---
  guard_blocked:         { kind: KIND.INTERACTION,   polarity: POLARITY.NEGATIVE, weight: 1 },
  cmd_rejected:          { kind: KIND.INTERACTION,   polarity: POLARITY.NEGATIVE, weight: 2 },
  privilege_attempt:     { kind: KIND.INTERACTION,   polarity: POLARITY.NEGATIVE, weight: 2 },
  handshake_failed:      { kind: KIND.INTERACTION,   polarity: POLARITY.NEGATIVE, weight: 1 },
  aat_expired:           { kind: KIND.INTERACTION,   polarity: POLARITY.NEGATIVE, weight: 1 },
  bypass_execution:      { kind: KIND.INTERACTION,   polarity: POLARITY.NEGATIVE, weight: 3 },
  ledger_tampered:       { kind: KIND.INTERACTION,   polarity: POLARITY.NEGATIVE, weight: 5 },
  revoked:               { kind: KIND.REVOCATION,    polarity: POLARITY.NEGATIVE, weight: 0 },
  downgraded:            { kind: KIND.DOWNGRADE,     polarity: POLARITY.NEGATIVE, weight: 0 },
});

function canonicalContent(record) {
  const { hash, signature, ...rest } = record;
  return JSON.stringify(rest, Object.keys(rest).sort());
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

class EvidenceLedger {
  /**
   * @param {Object} options
   *   - ledgerPath: JSONL 落盘路径（不传则纯内存）
   *   - privateKey / publicKey: Ed25519 KeyObject（可选；配置后签名/验签）
   */
  constructor({ ledgerPath = null, privateKey = null, publicKey = null } = {}) {
    this.ledgerPath = ledgerPath;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.entries = [];
    if (this.ledgerPath) this._loadFromDisk();
  }

  _loadFromDisk() {
    try {
      if (!fs.existsSync(this.ledgerPath)) return;
      const lines = fs.readFileSync(this.ledgerPath, 'utf-8').split('\n').filter((l) => l.trim());
      this.entries = lines.map((l) => JSON.parse(l));
    } catch (e) {
      // 读失败不静默吞掉：置空并留标记，由 verifyChain 暴露
      this.entries = [];
      this._loadError = e.message;
    }
  }

  /** 账本最后一条的 hash（新条目的 prev_hash） */
  get headHash() {
    const last = this.entries[this.entries.length - 1];
    return last ? last.hash : GENESIS_HASH;
  }

  /**
   * 追加一条证据
   *
   * @param {Object} evt
   *   - subject: { name, aid?, url? }  证据主体（被评分的 Agent）
   *   - action: ACTIONS 表中的动作名（决定 kind/polarity/weight 默认值）
   *   - kind/polarity/weight: 可覆盖默认（自定义事件用）
   *   - evidence: { ref?, detail? }    可核验引用（task id / message id / hash）
   *   - actor: 记账方（谁写的账）
   *   - note: 备注
   * @returns {Object} 完整条目（含 seq/hash/signature）
   */
  append(evt = {}) {
    const def = ACTIONS[evt.action] || {};
    const kind = evt.kind || def.kind || KIND.INTERACTION;
    const polarity = evt.polarity !== undefined ? evt.polarity : (def.polarity ?? POLARITY.NEUTRAL);
    const weight = evt.weight !== undefined ? evt.weight : (def.weight ?? 0);

    const subject = evt.subject || {};
    const subjectId = subject.name || subject.aid || 'unknown';

    const record = {
      seq: this.entries.length + 1,
      ts: evt.ts || Date.now(),
      subject: { name: subject.name || null, aid: subject.aid || null, url: subject.url || null },
      subjectId,
      kind,
      action: evt.action || 'unknown',
      polarity,
      weight,
      evidence: evt.evidence || null,
      actor: evt.actor || null,
      note: evt.note || null,
      prev_hash: this.headHash,
    };
    record.hash = sha256(canonicalContent(record));
    if (this.privateKey) {
      record.signature = crypto.sign(null, Buffer.from(canonicalContent(record)), this.privateKey).toString('base64');
    }

    this.entries.push(record);
    if (this.ledgerPath) {
      fs.mkdirSync(path.dirname(this.ledgerPath), { recursive: true });
      fs.appendFileSync(this.ledgerPath, JSON.stringify(record) + '\n', 'utf-8');
    }
    return record;
  }

  /** 便于外部构造自定义条目 */
  appendRaw(evt) { return this.append(evt); }

  /** 遍历（可按主体/类型过滤） */
  list({ subjectId = null, kind = null, action = null } = {}) {
    return this.entries.filter((e) =>
      (!subjectId || e.subjectId === subjectId) &&
      (!kind || e.kind === kind) &&
      (!action || e.action === action));
  }

  /**
   * 校验哈希链（+ 可选验签）
   *
   * @returns {{ ok: boolean, reason?: string, atSeq?: number, verified?: number }}
   *   篡改 / 删除 / 插入 / 伪签 必检出
   */
  verifyChain() {
    if (this._loadError) return { ok: false, reason: 'ledger_load_error: ' + this._loadError };
    let prev = GENESIS_HASH;
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      if (e.seq !== i + 1) return { ok: false, reason: `seq 不连续（期望 ${i + 1}，实际 ${e.seq}）`, atSeq: e.seq };
      if (e.prev_hash !== prev) return { ok: false, reason: `断链（期望 prev_hash=${prev.slice(0, 12)}…，实际 ${String(e.prev_hash).slice(0, 12)}…）`, atSeq: e.seq };
      if (e.hash !== sha256(canonicalContent(e))) return { ok: false, reason: '内容被篡改（hash 不匹配）', atSeq: e.seq };
      if (this.publicKey) {
        if (!e.signature) return { ok: false, reason: '缺少签名', atSeq: e.seq };
        const okSig = crypto.verify(null, Buffer.from(canonicalContent(e)), this.publicKey, Buffer.from(e.signature, 'base64'));
        if (!okSig) return { ok: false, reason: '签名不匹配', atSeq: e.seq };
      }
      prev = e.hash;
    }
    return { ok: true, verified: this.entries.length };
  }
}

module.exports = { EvidenceLedger, KIND, POLARITY, ACTIONS, GENESIS_HASH, sha256, canonicalContent };
