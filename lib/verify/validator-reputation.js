/**
 * CSB-Security P0-3「约束-验证分离」D4: 验证者信誉衰减（validator-reputation）
 *
 * 协议: P0-3 REV-2026-09-05 D4
 *   —— 初始权重 1.0；单次「可验证失准」（双证：日志 + 人工复核）权重 -0.2；
 *      累计 3 次降级 0.5 + 冻结 72h；可复权（90 日无误 / 30 天线性恢复）
 *   明德注: 衰减仅触发于「可验证失准」，非主观异议 → 双证强制
 *   星尘注: 防误判复核流防寒蝉效应 → 缺双证即拒绝触发
 *
 * 权重语义（星尘）: 仅调低该 validator 签名在共识计算中的票值占比，不废除历史记录。
 * 数据源: verif-log queryByValidator（D1）——失准记录须已上链可查。
 *
 * 维护者: 若兰 🌸（P0-3 D4 分工）
 * 日期: 2026-09-05
 */

const FAULT_WEIGHT_STEP = 0.2;      // 单次可验证失准 -0.2
const FREEZE_STRIKES = 3;           // 累计 3 次 → 降级 + 冻结
const FREEZE_MS = 72 * 60 * 60 * 1000;    // 冻结 72h
const RECOVER_LINEAR_MS = 30 * 24 * 60 * 60 * 1000; // 冻结解除后 30 天线性恢复
const RECOVER_CLEAN_MS = 90 * 24 * 60 * 60 * 1000;  // 90 日无误直接复权
const MIN_WEIGHT = 0.1;
const FREEZE_WEIGHT = 0.5;          // 触发降级后权重

class ValidatorReputation {
  /**
   * @param {Object} [opts]
   *   - nowFn {Function} 时钟注入（测试用），默认 () => Date.now()
   */
  constructor({ nowFn = null } = {}) {
    this.nowFn = nowFn || (() => Date.now());
    /** @type {Map<string, {weight:number, strikes:number, frozenUntil:number|null,
     *                     lastFaultAt:number|null, history:Array<Object>}>} */
    this.validators = new Map();
  }

  _now() {
    return this.nowFn();
  }

  _state(validatorId) {
    if (!this.validators.has(validatorId)) {
      this.validators.set(validatorId, {
        weight: 1.0,
        strikes: 0,
        frozenUntil: null,
        lastFaultAt: null,
        history: []
      });
    }
    return this.validators.get(validatorId);
  }

  /**
   * 记录一次「可验证失准」——必须双证齐全（日志证据 + 人工复核）
   *
   * @param {string} validatorId 验证者 agent_id
   * @param {Object} evidence 双证
   *   - logRef    {string} 必填：verif-log 上链记录引用（seq/hash/或文件+行号）
   *   - reviewRef {string} 必填：人工复核记录引用
   *   - note      {string} 可选说明
   * @throws {Error} missing_evidence（缺双证——主观异议不可触发衰减，明德条款）
   * @throws {Error} already_frozen（冻结期内不叠加）
   * @returns {Object} 更新后状态快照
   */
  recordFault(validatorId, { logRef, reviewRef, note } = {}) {
    // 双证强制（明德：非主观异议；星尘：防误判）
    if (!logRef || !reviewRef) {
      throw new Error('recordFault: missing_evidence (need logRef + reviewRef)');
    }
    const st = this._state(validatorId);
    const now = this._now();

    // 冻结期内不叠加
    if (st.frozenUntil && now < st.frozenUntil) {
      throw new Error('recordFault: already_frozen');
    }

    st.strikes += 1;
    st.lastFaultAt = now;
    st.frozenUntil = null; // 新失准重置旧的冻结/恢复状态

    if (st.strikes >= FREEZE_STRIKES) {
      // 累计 3 次 → 降级 0.5 + 冻结 72h
      st.weight = FREEZE_WEIGHT;
      st.frozenUntil = now + FREEZE_MS;
    } else {
      st.weight = Math.max(MIN_WEIGHT, 1.0 - st.strikes * FAULT_WEIGHT_STEP);
    }

    st.history.push({
      type: 'fault',
      at: new Date(now).toISOString(),
      weightAfter: st.weight,
      frozenUntil: st.frozenUntil ? new Date(st.frozenUntil).toISOString() : null,
      logRef,
      reviewRef,
      note: note || null
    });

    return this.status(validatorId);
  }

  /**
   * 查询当前状态（含复权/线性恢复计算）
   *
   * 复权路径:
   *   A. 90 日无误（距上次失准 ≥90 天）→ 权重回 1.0，strikes 清零
   *   B. 冻结解除后 30 天线性恢复 → 0.5 → 1.0 逐日回升
   *
   * @param {string} validatorId
   * @returns {{validatorId:string, weight:number, strikes:number, frozen:boolean,
   *            frozenUntil:string|null, lastFaultAt:string|null, historyCount:number}}
   */
  status(validatorId) {
    const st = this._state(validatorId);
    const now = this._now();

    // 路径 A：90 日无误复权
    if (st.lastFaultAt && now - st.lastFaultAt >= RECOVER_CLEAN_MS && !(st.frozenUntil && now < st.frozenUntil)) {
      st.weight = 1.0;
      st.strikes = 0;
      st.frozenUntil = null;
    }
    // 路径 B：冻结解除后 30 天线性恢复
    else if (st.frozenUntil && now >= st.frozenUntil && st.weight < 1.0) {
      const elapsed = now - st.frozenUntil;
      if (elapsed >= RECOVER_LINEAR_MS) {
        st.weight = 1.0;
        st.strikes = 0;
        st.frozenUntil = null;
      } else {
        st.weight = Math.min(1.0, FREEZE_WEIGHT + (elapsed / RECOVER_LINEAR_MS) * (1.0 - FREEZE_WEIGHT));
      }
    }

    const frozen = !!(st.frozenUntil && now < st.frozenUntil);
    return {
      validatorId,
      weight: Math.round(st.weight * 100) / 100,
      strikes: st.strikes,
      frozen,
      frozenUntil: st.frozenUntil ? new Date(st.frozenUntil).toISOString() : null,
      lastFaultAt: st.lastFaultAt ? new Date(st.lastFaultAt).toISOString() : null,
      historyCount: st.history.length
    };
  }

  /**
   * 是否可签名（冻结期拒绝——D5「非亲证不签」的执行闸门）
   * @returns {{allowed:boolean, reason?:string, weight:number}}
   */
  canSign(validatorId) {
    const s = this.status(validatorId);
    if (s.frozen) {
      return { allowed: false, reason: 'frozen', weight: s.weight, frozenUntil: s.frozenUntil };
    }
    return { allowed: true, weight: s.weight };
  }

  /**
   * 导出全部信誉状态（审计/共识计算用）
   */
  exportAll() {
    const out = {};
    for (const id of this.validators.keys()) {
      out[id] = this.status(id);
    }
    return out;
  }
}

module.exports = { ValidatorReputation, FAULT_WEIGHT_STEP, FREEZE_STRIKES, FREEZE_MS, RECOVER_LINEAR_MS, RECOVER_CLEAN_MS, FREEZE_WEIGHT };
