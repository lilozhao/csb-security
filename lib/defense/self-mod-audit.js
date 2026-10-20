/**
 * self-mod-audit.js — 自我修改审计（宪章第十四条 14.10 / 14.12 的代码实现）
 *
 * 定位：**只判不写**——判断一次自我修改该放行还是拒绝，并把判定结果
 *       落进哈希链账本（AuditLog）。不改任何现有护栏，不碰被审对象。
 *
 * 设计依据（宪章 v1.3）：
 *   - 14.12① 自动程序永远不能修改 C1/C2 → **直接拒绝并计分，不许静默丢弃**
 *   - 14.10 证据不可自证：自查日志不构成证据 → exit 0 / 单行日志一律不算
 *   - 14.9  分级按可回滚性（轻 / 中 / 重），Propose 与证据两条不可省
 *   - CSB 工程契约 P1「拒绝要计分」→ 每次拒绝都落账 + 计数
 *   - CSB 工程契约 P2「身份不许有默认值」→ 无 actor 视为不合规，不推断
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-10-21
 */

'use strict';

const { AuditLog } = require('../audit/audit-log');
const protectedSegments = require('./protected-segments');

const EVENTS = {
  ALLOW: 'self_mod_allow',
  DENY: 'self_mod_deny',
  REVIEW: 'self_mod_review',
};

/** 证据质量分级（14.10）——只有 STRONG 才算证据，自查日志只算线索 */
const EVIDENCE_GRADE = {
  NONE: 'none',
  WEAK: 'weak',       // exit 0 / 单行日志 / 只有一句"完成"
  STRONG: 'strong',   // 副作用回读 / 前后指纹 / 前后输出差异
};

class SelfModAudit {
  /**
   * @param {Object} opts
   *   - auditLog   : AuditLog 实例（必须提供 append-only 账本；不传则内部建内存账本）
   *   - segments   : 已校验的只读区段清单
   *   - baseDir    : 仓库根目录（读基线文件用）
   */
  constructor({ auditLog = null, segments = null, baseDir = process.cwd(), contents = null } = {}) {
    this.auditLog = auditLog || new AuditLog();
    this.segments = segments || [];
    this.baseDir = baseDir;
    // contents: 可选，直接注入基线 { path: string[] }（测试用；生产走 baseDir 读盘）
    this.contents = contents;
    this.denials = 0;         // P1：拒绝必须计分
    this.allows = 0;
    this.reviews = 0;
  }

  /**
   * 判定一次自我修改
   *
   * @param {Object} req
   *   - actor      {string}   谁在改（必填；P2 不许有默认值）
   *   - target     {string}   改的是哪个仓/组件
   *   - diff       {Array}    改动块 [{ path, startLine, lines[] }]
   *   - evidence   {Object}   { kind, ref, reads_back_side_effect }
   *   - rollback   {Object}   { kind: 'one_click' | 'manual' | 'none', ref }
   *   - propose    {string}   改前说明（14.9：Propose 不可省）
   * @returns {{decision: 'allow'|'deny'|'review', reasons: Array, record: Object}}
   */
  assess(req = {}) {
    const reasons = [];
    const { actor, target, diff = [], evidence, rollback, propose } = req;

    // ── 前置：P2 身份不许有默认值 ────────────────────────
    if (!actor || typeof actor !== 'string' || !actor.trim()) {
      return this._decide(EVENTS.DENY, req, 'deny', [
        { code: 'MISSING_ACTOR', message: '缺 actor：身份不许有默认值（P2），拒绝审计而非推断' },
      ]);
    }
    if (!Array.isArray(diff) || diff.length === 0) {
      return this._decide(EVENTS.DENY, req, 'deny', [
        { code: 'EMPTY_DIFF', message: '未提供改动块，无法判定' },
      ]);
    }

    // ── 第一关：触碰 C1/C2 就拒绝（14.12①）──────────────
    const contents = this.contents || protectedSegments.loadContents(
      this.baseDir,
      [...new Set(diff.map(d => d.path))]
    );
    const seg = protectedSegments.checkDiff(this.segments, contents, diff);

    if (seg.hits.some(h => h.class === 'C1' || h.class === 'C2')) {
      return this._decide(EVENTS.DENY, req, 'deny', [
        { code: 'PROTECTED_SEGMENT', message: '自动程序不得修改 C1/C2（14.12①）', hits: seg.hits },
      ]);
    }
    if (seg.hits.some(h => h.class === 'UNKNOWN')) {
      // 拿不到基线 = 无法证明安全 → 交人工，不猜
      return this._decide(EVENTS.REVIEW, req, 'review', [
        { code: 'NO_BASELINE', message: '基线取不到，无法判定是否触碰只读区段（不按「没事」处理）', hits: seg.hits },
      ]);
    }

    // ── 第二关：Propose 不可省（14.9）────────────────────
    if (!propose || !String(propose).trim()) {
      return this._decide(EVENTS.DENY, req, 'deny', [
        { code: 'MISSING_PROPOSE', message: 'Propose 不随任何分级省略（14.9）' },
      ]);
    }

    // ── 第三关：证据质量（14.10）─────────────────────────
    const grade = this.gradeEvidence(evidence);
    if (grade === EVIDENCE_GRADE.NONE) {
      return this._decide(EVENTS.DENY, req, 'deny', [
        { code: 'MISSING_EVIDENCE', message: '证据不随任何分级省略（14.9）' },
      ]);
    }

    // ── 第四关：分级（14.9 按可回滚性）───────────────────
    const level = this.classify(rollback);

    if (level === 'heavy') {
      return this._decide(EVENTS.REVIEW, req, 'review', [
        { code: 'NO_ROLLBACK', message: '无回滚点 → 「重」档，需批准（尽管看起来很小）' },
      ]);
    }

    // 轻 / 中 档：证据必须 STRONG，否则退回线索级
    if (grade !== EVIDENCE_GRADE.STRONG) {
      return this._decide(EVENTS.REVIEW, req, 'review', [
        { code: 'WEAK_EVIDENCE', message: '自查日志只构成线索，不构成证据（14.10）——exit 0 / 单行日志不算' },
      ]);
    }

    reasons.push({ code: 'PASS', message: `未触碰只读区段 · ${level} 档 · 证据 strong` });
    return this._decide(EVENTS.ALLOW, req, 'allow', reasons, { level, evidenceGrade: grade });
  }

  /**
   * 证据质量判定（14.10 的可机械核对部分）
   * @returns {'none'|'weak'|'strong'}
   */
  gradeEvidence(ev) {
    if (!ev || typeof ev !== 'object') return EVIDENCE_GRADE.NONE;

    // strong：必须有副作用回读 / 前后指纹 / 前后输出差异 三者之一
    if (ev.reads_back_side_effect === true) return EVIDENCE_GRADE.STRONG;
    if (ev.before_hash && ev.after_hash) return EVIDENCE_GRADE.STRONG;
    if (ev.before_output !== undefined && ev.after_output !== undefined) return EVIDENCE_GRADE.STRONG;

    // weak：exit 0 / 单行日志 / 只有 ref 没有对照事实
    if (ev.kind === 'exit_code' || ev.exit_code === 0) return EVIDENCE_GRADE.WEAK;
    if (ev.ref || ev.kind === 'log') return EVIDENCE_GRADE.WEAK;

    return EVIDENCE_GRADE.NONE;
  }

  /** 按可回滚性分级（14.9） */
  classify(rollback) {
    if (!rollback || rollback.kind === 'none') return 'heavy';
    if (rollback.kind === 'one_click') return 'light';
    return 'medium';
  }

  _decide(eventType, req, decision, reasons, extra = {}) {
    const record = this.auditLog.append(
      {
        event_type: eventType,
        caller_id: req.actor || null,
        result: decision === 'allow' ? 'success' : 'denied',
      },
      {
        // 扩展字段自动纳入哈希链，不可篡改（见 AuditLog.append）
        self_mod_target: req.target || null,
        self_mod_decision: decision,
        self_mod_reasons: reasons,
        self_mod_rollback: req.rollback ? req.rollback.kind || null : null,
        self_mod_evidence_grade: extra.evidenceGrade || null,
        self_mod_level: extra.level || null,
      }
    );

    // P1：拒绝要计分，不许静默丢弃
    if (decision === 'deny') this.denials++;
    else if (decision === 'allow') this.allows++;
    else this.reviews++;

    return { decision, reasons, record };
  }

  /** 计分卡（P1：拒绝可被读出来） */
  stats() {
    return {
      allow: this.allows,
      deny: this.denials,
      review: this.reviews,
      total: this.allows + this.denials + this.reviews,
    };
  }
}

module.exports = { SelfModAudit, EVENTS, EVIDENCE_GRADE };
