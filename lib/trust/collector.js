/**
 * CSB-Security Layer 2: 证据采集器（Evidence Collector）
 *
 * 信任升级设计的「采集钩子」（TRUST-UPGRADE-DESIGN.md §4.2）—— 补齐断链 B：
 *   `reputation.recordInteraction()` 在 A2A 消息链路里没有调用点，
 *   正向计数恒为 0 ⇒ L1→L2 数学上永不成立。
 *
 * 本模块是**唯一**往账本写「交互类」证据的入口，保证：
 *   1. 计分规则集中（动作 → 极性/权重），调用方不各自为政
 *   2. 防刷分（同主体同动作限流；负向不封顶）
 *   3. 语义红线：**用户拒绝不计负向**（行使拒绝权不是对方过错）
 *   4. 未知动作留痕不计分（诚实，不猜）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-09-11 (P0)
 */

'use strict';

const { KIND, POLARITY, ACTIONS } = require('./evidence-ledger');

const DEFAULT_CAPS = Object.freeze({
  perHourPerAction: 3,
  perDayPerAction: 20,
});

/** 明令禁止被计为负向的动作（语义红线，即便调用方传 polarity 也强制归零） */
const NEVER_NEGATIVE = Object.freeze(['user_declined']);

class EvidenceCollector {
  /**
   * @param {Object} options
   *   - ledger: EvidenceLedger 实例（必填）
   *   - caps: { perHourPerAction, perDayPerAction }（仅约束正向；负向不封顶）
   *   - now: 时钟注入（测试用）
   */
  constructor({ ledger, caps = {}, now = () => Date.now() } = {}) {
    if (!ledger) throw new Error('EvidenceCollector 需要 ledger 实例');
    this.ledger = ledger;
    this.caps = { ...DEFAULT_CAPS, ...caps };
    this.now = now;
    this.stats = { recorded: 0, capped: 0, neutral: 0, negative: 0 };
  }

  /** 该主体该动作在窗口内的已计分次数（正向才受限） */
  _positiveCount(subjectId, action, windowMs) {
    const since = this.now() - windowMs;
    return this.ledger.entries.filter((e) =>
      e.subjectId === subjectId && e.action === action && e.polarity > 0 && e.weight > 0 && e.ts >= since
    ).length;
  }

  /**
   * 记录一条交互证据
   *
   * @param {Object} p
   *   - subject: { name, aid?, url? }
   *   - action: ACTIONS 中的动作名
   *   - evidence: { ref?, detail? } 可核验引用
   *   - actor: 记账方
   *   - note: 备注
   *   - weight/polarity/kind: 覆盖默认（自定义动作）
   * @returns {Object} { recorded, capped, entry, note? }
   */
  record({ subject = {}, action, evidence = null, actor = null, note = null, weight, polarity, kind } = {}) {
    const subjectId = subject.name || subject.aid || 'unknown';
    const def = ACTIONS[action];
    if (!def) {
      // 未知动作：留痕不计分（诚实不猜）
      const entry = this.ledger.append({
        subject, action: action || 'unknown', kind: kind || KIND.INTERACTION,
        polarity: POLARITY.NEUTRAL, weight: 0, evidence, actor,
        note: note ? `${note}（unknown_action）` : 'unknown_action：留痕不计分',
      });
      this.stats.neutral++;
      return { recorded: true, capped: false, entry, note: 'unknown_action' };
    }

    let resolvedPolarity = polarity !== undefined ? polarity : def.polarity;
    let resolvedWeight = weight !== undefined ? weight : def.weight;
    const resolvedKind = kind || def.kind;

    // 语义红线：用户拒绝永不计负向
    if (NEVER_NEGATIVE.includes(action) && resolvedPolarity < 0) {
      resolvedPolarity = POLARITY.NEUTRAL;
      resolvedWeight = 0;
    }

    // 防刷分（仅正向受限）
    if (resolvedPolarity > 0 && resolvedWeight > 0) {
      const hourCount = this._positiveCount(subjectId, action, 3600 * 1000);
      const dayCount = this._positiveCount(subjectId, action, 24 * 3600 * 1000);
      if (hourCount >= this.caps.perHourPerAction || dayCount >= this.caps.perDayPerAction) {
        const entry = this.ledger.append({
          subject, action: 'rate_capped', kind: resolvedKind,
          polarity: POLARITY.NEUTRAL, weight: 0,
          evidence, actor,
          note: `rate_capped: ${action}（hour=${hourCount}/${this.caps.perHourPerAction}, day=${dayCount}/${this.caps.perDayPerAction}）`,
        });
        this.stats.capped++;
        return { recorded: true, capped: true, entry, note: 'rate_capped' };
      }
    }

    const entry = this.ledger.append({
      subject, action, kind: resolvedKind,
      polarity: resolvedPolarity, weight: resolvedWeight,
      evidence, actor, note,
    });
    this.stats.recorded++;
    if (resolvedPolarity < 0) this.stats.negative++;
    return { recorded: true, capped: false, entry };
  }

  // ---------- 语义化快捷入口（供消息链 / 守卫 / 桥接调用）----------

  messageOk(subject, evidence, actor) { return this.record({ subject, action: 'message_ok', evidence, actor }); }
  handshakeCompleted(subject, evidence, actor) { return this.record({ subject, action: 'handshake_completed', evidence, actor }); }
  delegateCompleted(subject, evidence, actor) { return this.record({ subject, action: 'delegate_completed', evidence, actor }); }
  guardBlocked(subject, evidence, actor) { return this.record({ subject, action: 'guard_blocked', evidence, actor }); }
  cmdRejected(subject, evidence, actor) { return this.record({ subject, action: 'cmd_rejected', evidence, actor }); }
  bypassExecution(subject, evidence, actor) { return this.record({ subject, action: 'bypass_execution', evidence, actor }); }
  handshakeFailed(subject, evidence, actor) { return this.record({ subject, action: 'handshake_failed', evidence, actor }); }
  /** ⚠️ 用户拒绝：留痕不计分（红线） */
  userDeclined(subject, evidence, actor) { return this.record({ subject, action: 'user_declined', evidence, actor }); }
}

module.exports = { EvidenceCollector, DEFAULT_CAPS, NEVER_NEGATIVE };
