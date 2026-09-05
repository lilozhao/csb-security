#!/usr/bin/env node
/**
 * test-validator-reputation.js — P0-3 D4 验证者信誉衰减测试
 * 协议: P0-3 REV-2026-09-05 D4（权重 1.0 → 失准 -0.2 → 3 次降级 0.5+冻结 72h → 复权）
 */

const assert = require('assert');
const { ValidatorReputation, FREEZE_MS, RECOVER_LINEAR_MS, RECOVER_CLEAN_MS } = require('../lib/verify/validator-reputation');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (e) {
    failed++;
    console.log(`  ❌ ${name}: ${e.message}`);
  }
}

console.log('=== validator-reputation (P0-3 D4 信誉衰减) 测试 ===\n');

const DAY = 24 * 60 * 60 * 1000;
const VALIDATOR = 'siyuan@172.28.0.44:3601';

// 可控时钟
function makeClock(start = Date.now()) {
  let t = start;
  return {
    now: () => t,
    advance: (ms) => { t += ms; }
  };
}

function makeRep() {
  const clock = makeClock(1_000_000_000_000);
  const rep = new ValidatorReputation({ nowFn: clock.now });
  return { rep, clock };
}

const EVIDENCE = { logRef: 'verif-log#seq:12', reviewRef: 'review/2026-09-05/r1' };

// ---------- 初始状态 ----------
test('初始权重 1.0、可签、零失准', () => {
  const { rep } = makeRep();
  const s = rep.status(VALIDATOR);
  assert.strictEqual(s.weight, 1.0);
  assert.strictEqual(s.strikes, 0);
  assert.strictEqual(s.frozen, false);
  assert.strictEqual(rep.canSign(VALIDATOR).allowed, true);
});

// ---------- 衰减 ----------
test('单次可验证失准（双证齐）→ 权重 0.8', () => {
  const { rep } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  assert.strictEqual(rep.status(VALIDATOR).weight, 0.8);
});

test('两次失准 → 权重 0.6', () => {
  const { rep } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  assert.strictEqual(rep.status(VALIDATOR).weight, 0.6);
});

test('第三次失准 → 降级 0.5 + 冻结 72h + 不可签', () => {
  const { rep, clock } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  const s3 = rep.recordFault(VALIDATOR, EVIDENCE);
  assert.strictEqual(s3.weight, 0.5);
  assert.strictEqual(s3.frozen, true);
  assert.strictEqual(s3.frozenUntil, new Date(clock.now() + FREEZE_MS).toISOString());
  const cs = rep.canSign(VALIDATOR);
  assert.strictEqual(cs.allowed, false);
  assert.strictEqual(cs.reason, 'frozen');
});

// ---------- 双证强制（明德/星尘条款） ----------
test('缺双证（无 logRef/reviewRef）→ 拒绝触发（主观异议不可衰减）', () => {
  const { rep } = makeRep();
  assert.throws(() => rep.recordFault(VALIDATOR, { logRef: 'x' }), /missing_evidence/);
  assert.throws(() => rep.recordFault(VALIDATOR, { reviewRef: 'y' }), /missing_evidence/);
  assert.throws(() => rep.recordFault(VALIDATOR, {}), /missing_evidence/);
  assert.strictEqual(rep.status(VALIDATOR).weight, 1.0, '不应有任何衰减');
});

// ---------- 冻结期 ----------
test('冻结期内再次失准 → 拒绝叠加（already_frozen）', () => {
  const { rep } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  assert.throws(() => rep.recordFault(VALIDATOR, EVIDENCE), /already_frozen/);
});

test('冻结期内 canSign=false；72h 后解除冻结', () => {
  const { rep, clock } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  // 冻结中
  clock.advance(FREEZE_MS - 1000);
  assert.strictEqual(rep.canSign(VALIDATOR).allowed, false);
  // 刚过 72h
  clock.advance(1000);
  const s = rep.status(VALIDATOR);
  assert.strictEqual(s.frozen, false);
  assert.strictEqual(rep.canSign(VALIDATOR).allowed, true);
});

// ---------- 复权路径 B：30 天线性恢复 ----------
test('冻结解除后线性恢复：15 天 → 权重 ~0.75', () => {
  const { rep, clock } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  clock.advance(FREEZE_MS); // 解除冻结
  clock.advance(RECOVER_LINEAR_MS / 2); // 再过 15 天
  const s = rep.status(VALIDATOR);
  assert.strictEqual(s.weight, 0.75); // 0.5 + 15/30 * 0.5
});

test('30 天线性恢复期满 → 权重回 1.0', () => {
  const { rep, clock } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault(VALIDATOR, EVIDENCE);
  clock.advance(FREEZE_MS + RECOVER_LINEAR_MS + 1000);
  const s = rep.status(VALIDATOR);
  assert.strictEqual(s.weight, 1.0);
  assert.strictEqual(s.strikes, 0);
});

// ---------- 复权路径 A：90 日无误 ----------
test('单次失准后 90 日无误 → 直接复权 1.0', () => {
  const { rep, clock } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  assert.strictEqual(rep.status(VALIDATOR).weight, 0.8);
  clock.advance(RECOVER_CLEAN_MS + 1000);
  const s = rep.status(VALIDATOR);
  assert.strictEqual(s.weight, 1.0);
  assert.strictEqual(s.strikes, 0);
});

// ---------- 记录可追溯 ----------
test('失准历史可追溯（含双证引用）', () => {
  const { rep } = makeRep();
  rep.recordFault(VALIDATOR, { logRef: 'verif-log#seq:12', reviewRef: 'review/2026-09-05/r1', note: '误报技能通过' });
  const s = rep.status(VALIDATOR);
  assert.strictEqual(s.historyCount, 1);
  // 通过内部状态验证 history 内容
  const st = rep.validators.get(VALIDATOR);
  assert.strictEqual(st.history[0].logRef, 'verif-log#seq:12');
  assert.strictEqual(st.history[0].reviewRef, 'review/2026-09-05/r1');
  assert.strictEqual(st.history[0].note, '误报技能通过');
  assert.strictEqual(st.history[0].type, 'fault');
});

// ---------- 权重只影响票值不废记录（星尘） ----------
test('衰减不删除历史验证记录（exportAll 含完整状态）', () => {
  const { rep } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  rep.recordFault('other@172.28.0.5:3100', EVIDENCE);
  const all = rep.exportAll();
  assert.ok(all[VALIDATOR], '原 validator 状态仍在');
  assert.ok(all['other@172.28.0.5:3100']);
  assert.strictEqual(all[VALIDATOR].weight, 0.8);
  assert.strictEqual(all['other@172.28.0.5:3100'].weight, 0.8);
});

// ---------- 多 validator 隔离 ----------
test('不同 validator 互不影响', () => {
  const { rep } = makeRep();
  rep.recordFault(VALIDATOR, EVIDENCE);
  const other = 'axuan@172.28.0.5:3100';
  assert.strictEqual(rep.status(other).weight, 1.0);
  assert.strictEqual(rep.status(VALIDATOR).weight, 0.8);
});

// ---------- 汇总 ----------
console.log(`\n通过: ${passed}`);
console.log(`失败: ${failed}`);
if (failed > 0) process.exit(1);
