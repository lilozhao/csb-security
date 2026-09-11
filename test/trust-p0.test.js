#!/usr/bin/env node
/**
 * 信任升级 P0 · 单元测试
 * 覆盖：证据账本（哈希链/篡改必检出/签名）、派生规则（L0→L1→L2→L3）、
 *       采集器（防刷分/用户拒绝不计负向/未知动作留痕）、快照（重启幂等）
 * 风格：手写 assert + console（仓库惯例，无测试框架）
 *
 * 用法: node test/trust-p0.test.js
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { EvidenceLedger, ACTIONS, POLARITY, sha256, canonicalContent } = require('../lib/trust/evidence-ledger');
const { TrustStore, DEFAULTS } = require('../lib/trust/trust-store');
const { EvidenceCollector } = require('../lib/trust/collector');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ✅ ${name}`); }
  catch (e) { failed++; console.log(`  ❌ ${name}\n     ${e.message}`); }
}
function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'trust-p0-')); }
const XUAN = { name: '阿轩', aid: 'aid:ed25519:xuan', url: 'http://172.28.0.5:3100' };

console.log('\n[1] 证据账本：追加 / 哈希链 / 篡改必检出');

test('追加后哈希链完整（verifyChain ok）', () => {
  const l = new EvidenceLedger();
  l.append({ subject: XUAN, action: 'handshake_completed', actor: '若兰' });
  l.append({ subject: XUAN, action: 'message_ok', actor: '若兰' });
  const v = l.verifyChain();
  assert.strictEqual(v.ok, true, v.reason);
  assert.strictEqual(v.verified, 2);
});

test('篡改中间条目内容 → 检出并定位 seq', () => {
  const l = new EvidenceLedger();
  l.append({ subject: XUAN, action: 'message_ok' });
  l.append({ subject: XUAN, action: 'message_ok' });
  l.entries[0].weight = 999; // 篡改
  const v = l.verifyChain();
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.atSeq, 1);
  assert.ok(/篡改/.test(v.reason));
});

test('删除条目（断链）→ 检出', () => {
  const l = new EvidenceLedger();
  for (let i = 0; i < 3; i++) l.append({ subject: XUAN, action: 'message_ok' });
  l.entries.splice(1, 1);
  const v = l.verifyChain();
  assert.strictEqual(v.ok, false);
  assert.ok(/seq 不连续|断链/.test(v.reason));
});

test('插入格式完整的伪造条目 → 无签名时可骗过哈希链（已知边界）', () => {
  // ⚠️ 诚实记录局限：哈希链只能防「改已有条目 / 删条目」，
  // 一个 prev_hash/hash 都算对的完整伪造条目，在**无签名**时链校验发现不了。
  // ⇒ 信任账本必须启用签名（见下一条），这是设计上的硬要求，不是选项。
  const l = new EvidenceLedger();
  l.append({ subject: XUAN, action: 'message_ok' });
  const fake = { seq: 2, ts: Date.now(), subject: { name: '阿轩' }, subjectId: '阿轩', kind: 'interaction', action: 'message_ok', polarity: 1, weight: 1, prev_hash: l.headHash };
  fake.hash = sha256(canonicalContent(fake));
  l.entries.push(fake);
  assert.strictEqual(l.verifyChain().ok, true, '无签名时链校验通过（局限）');
});

test('插入伪造条目 + 启用签名 → 必检出（缺少签名）', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const l = new EvidenceLedger({ privateKey, publicKey });
  l.append({ subject: XUAN, action: 'message_ok' });
  const fake = { seq: 2, ts: Date.now(), subject: { name: '阿轩' }, subjectId: '阿轩', kind: 'interaction', action: 'message_ok', polarity: 1, weight: 1, prev_hash: l.headHash };
  fake.hash = sha256(canonicalContent(fake));
  l.entries.push(fake);
  const v = l.verifyChain();
  assert.strictEqual(v.ok, false);
  assert.ok(/签名/.test(v.reason), `期望签名类错误，实际 ${v.reason}`);
});

test('落盘 + 重新加载：链仍完好（重启不丢）', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'ledger.jsonl');
  const l1 = new EvidenceLedger({ ledgerPath: p });
  l1.append({ subject: XUAN, action: 'handshake_completed' });
  l1.append({ subject: XUAN, action: 'message_ok' });
  const l2 = new EvidenceLedger({ ledgerPath: p });
  assert.strictEqual(l2.entries.length, 2);
  assert.strictEqual(l2.verifyChain().ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Ed25519 签名：验签通过；改内容 → 签名不匹配', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const l = new EvidenceLedger({ privateKey, publicKey });
  l.append({ subject: XUAN, action: 'message_ok' });
  assert.strictEqual(l.verifyChain().ok, true);
  l.entries[0].note = '被改过的备注';
  assert.strictEqual(l.verifyChain().ok, false);
});

console.log('\n[2] 派生规则：L0 → L1 → L2 → L3');

function storeWith(events, opts = {}) {
  const l = new EvidenceLedger();
  for (const e of events) l.append(e);
  return new TrustStore({ ledger: l, ...opts });
}

test('空账本 → L0', () => {
  const s = storeWith([]);
  assert.strictEqual(s.getLevel('阿轩').level, 'L0');
});

test('无身份证据 → 停在 L0（伪造 senderName 挡在这里）', () => {
  const s = storeWith(Array.from({ length: 20 }, () => ({ subject: XUAN, action: 'message_ok' })));
  assert.strictEqual(s.getLevel('阿轩').level, 'L0', '没有 identity 证据不应超过 L0');
});

test('L0→L1：握手完成', () => {
  const s = storeWith([{ subject: XUAN, action: 'handshake_completed' }]);
  assert.strictEqual(s.getLevel('阿轩').level, 'L1');
});

test('L1→L2：正向权重达阈值（握手 2 + 8 条 message_ok = 10）', () => {
  const evts = [{ subject: XUAN, action: 'handshake_completed' }];
  for (let i = 0; i < 8; i++) evts.push({ subject: XUAN, action: 'message_ok' });
  const s = storeWith(evts);
  const rec = s.getLevel('阿轩');
  assert.strictEqual(rec.level, 'L2');
  assert.strictEqual(rec.positiveWeight, 10, '权重含握手 2 分');
});

test('L1 只差一点：总权重 9 → 仍 L1', () => {
  const evts = [{ subject: XUAN, action: 'handshake_completed' }];
  for (let i = 0; i < 7; i++) evts.push({ subject: XUAN, action: 'message_ok' });
  const rec = storeWith(evts).getLevel('阿轩');
  assert.strictEqual(rec.positiveWeight, 9);
  assert.strictEqual(rec.level, 'L1');
});

test('有未清偿负向 → 卡在 L1', () => {
  const evts = [{ subject: XUAN, action: 'handshake_completed' }];
  for (let i = 0; i < 12; i++) evts.push({ subject: XUAN, action: 'message_ok' });
  evts.push({ subject: XUAN, action: 'guard_blocked' });
  const rec = storeWith(evts).getLevel('阿轩');
  assert.strictEqual(rec.level, 'L1');
  assert.strictEqual(rec.outstandingNegCount, 1);
});

test('宽恕（forgiveness）清除未清偿负向 → 恢复 L2', () => {
  const evts = [{ subject: XUAN, action: 'handshake_completed' }];
  for (let i = 0; i < 12; i++) evts.push({ subject: XUAN, action: 'message_ok' });
  evts.push({ subject: XUAN, action: 'guard_blocked', ts: 1000 });
  evts.push({ subject: XUAN, action: 'forgiveness', ts: 2000, actor: '赵宏伟' });
  const rec = storeWith(evts).getLevel('阿轩');
  assert.strictEqual(rec.level, 'L2', '宽恕之后应可升 L2');
  assert.strictEqual(rec.outstandingNegCount, 0);
});

test('L2→L3：需用户授权 + 分 ≥0.9 + 未衰减', () => {
  const now = Date.now();
  const evts = [{ subject: XUAN, action: 'handshake_completed', ts: now - 1000 }];
  for (let i = 0; i < 10; i++) evts.push({ subject: XUAN, action: 'message_ok', ts: now - 900 + i });
  evts.push({ subject: XUAN, action: 'user_authorized', ts: now - 500, actor: '赵宏伟' });
  const rec = storeWith(evts).getLevel('阿轩');
  assert.strictEqual(rec.level, 'L3', `期望 L3，实际 ${rec.level}（分 ${rec.score}）`);
  assert.strictEqual(rec.authValid, true);
});

test('L2→L3 缺用户授权 → 停在 L2', () => {
  const now = Date.now();
  const evts = [{ subject: XUAN, action: 'handshake_completed', ts: now }];
  for (let i = 0; i < 12; i++) evts.push({ subject: XUAN, action: 'message_ok', ts: now - i });
  assert.strictEqual(storeWith(evts).getLevel('阿轩').level, 'L2');
});

test('授权后被撤销（revocation）→ 回退 L2', () => {
  const now = Date.now();
  const evts = [{ subject: XUAN, action: 'handshake_completed', ts: now - 5 }];
  for (let i = 0; i < 10; i++) evts.push({ subject: XUAN, action: 'message_ok', ts: now - 4 });
  evts.push({ subject: XUAN, action: 'user_authorized', ts: now - 3, actor: '赵宏伟' });
  evts.push({ subject: XUAN, action: 'revoked', ts: now - 2, actor: '赵宏伟' });
  assert.strictEqual(storeWith(evts).getLevel('阿轩').level, 'L2');
});

test('声誉分不足 0.9 → 不给 L3（记待复验）', () => {
  const now = Date.now();
  const evts = [{ subject: XUAN, action: 'handshake_completed', ts: now }];
  for (let i = 0; i < 10; i++) evts.push({ subject: XUAN, action: 'message_ok', ts: now - 1 });
  evts.push({ subject: XUAN, action: 'bypass_execution', ts: now - 1 }); // 权重 3 → 分 = 10/13 ≈ 0.77
  evts.push({ subject: XUAN, action: 'forgiveness', ts: now, actor: '赵宏伟' });
  evts.push({ subject: XUAN, action: 'user_authorized', ts: now, actor: '赵宏伟' });
  const rec = storeWith(evts).getLevel('阿轩');
  assert.notStrictEqual(rec.level, 'L3', `分 ${rec.score} 不足 0.9 不应给 L3`);
  assert.strictEqual(rec.requiresReauth, true);
});

test('30 天无正向 → 标记待复验（stale）', () => {
  const old = Date.now() - 40 * 24 * 3600 * 1000;
  const evts = [{ subject: XUAN, action: 'handshake_completed', ts: old }];
  for (let i = 0; i < 10; i++) evts.push({ subject: XUAN, action: 'message_ok', ts: old });
  evts.push({ subject: XUAN, action: 'user_authorized', ts: old, actor: '赵宏伟' });
  const rec = storeWith(evts).getLevel('阿轩');
  assert.strictEqual(rec.stale, true);
  assert.notStrictEqual(rec.level, 'L3');
});

console.log('\n[3] 采集器：防刷分 / 语义红线 / 未知动作');

test('正向限流：同动作同小时最多 3 次计分', () => {
  const l = new EvidenceLedger();
  const c = new EvidenceCollector({ ledger: l, caps: { perHourPerAction: 3, perDayPerAction: 20 } });
  for (let i = 0; i < 5; i++) c.messageOk(XUAN, { ref: 'm' + i }, '若兰');
  const counted = l.entries.filter((e) => e.action === 'message_ok' && e.polarity > 0).length;
  const capped = l.entries.filter((e) => e.action === 'rate_capped').length;
  assert.strictEqual(counted, 3);
  assert.strictEqual(capped, 2);
});

test('负向不限流（刷满正向也挡不住负面记录）', () => {
  const l = new EvidenceLedger();
  const c = new EvidenceCollector({ ledger: l, caps: { perHourPerAction: 1, perDayPerAction: 1 } });
  for (let i = 0; i < 5; i++) c.guardBlocked(XUAN, { ref: 'x' + i }, '若兰');
  const neg = l.entries.filter((e) => e.polarity < 0).length;
  assert.strictEqual(neg, 5);
});

test('用户拒绝不计负向（红线）', () => {
  const l = new EvidenceLedger();
  const c = new EvidenceCollector({ ledger: l });
  c.userDeclined(XUAN, { ref: 'task_1' }, '若兰');
  const e = l.entries[0];
  assert.strictEqual(e.polarity, 0, '用户拒绝必须中性');
  assert.strictEqual(e.weight, 0);
  // 即便调用方硬塞负向，也被归零
  c.record({ subject: XUAN, action: 'user_declined', polarity: -1, weight: 5 });
  assert.strictEqual(l.entries[1].polarity, 0);
});

test('未知动作 → 留痕不计分（诚实不猜）', () => {
  const l = new EvidenceLedger();
  const c = new EvidenceCollector({ ledger: l });
  const r = c.record({ subject: XUAN, action: 'some_new_thing' });
  assert.strictEqual(r.note, 'unknown_action');
  assert.strictEqual(l.entries[0].polarity, 0);
});

test('用户拒绝不影响 L2（因行使拒绝权被惩罚是坏激励）', () => {
  const l = new EvidenceLedger();
  // 关掉限流，本用例只验证语义红线（限流另有用例）
  const c = new EvidenceCollector({ ledger: l, caps: { perHourPerAction: 100, perDayPerAction: 100 } });
  c.handshakeCompleted(XUAN, null, '若兰');
  for (let i = 0; i < 10; i++) c.record({ subject: XUAN, action: 'delegate_completed', evidence: { ref: 't' + i } });
  for (let i = 0; i < 5; i++) c.userDeclined(XUAN, { ref: 'd' + i }, '若兰');
  const s = new TrustStore({ ledger: l });
  assert.strictEqual(s.getLevel('阿轩').level, 'L2');
});

console.log('\n[4] 追溯认定 + 快照（重启幂等）');

test('追溯认定 → 直接 L2（无需 10 次交互）', () => {
  const l = new EvidenceLedger();
  l.append({ subject: XUAN, action: 'handshake_completed' });
  l.append({ subject: XUAN, action: 'retroactive_attestation', actor: '赵宏伟', evidence: { refs: ['task_a', 'task_b'] } });
  assert.strictEqual(new TrustStore({ ledger: l }).getLevel('阿轩').level, 'L2');
});

test('追溯认定隐含身份认定（无需握手也能到 L2）', () => {
  const l = new EvidenceLedger();
  l.append({ subject: XUAN, action: 'retroactive_attestation', actor: '赵宏伟' });
  const rec = new TrustStore({ ledger: l }).getLevel('阿轩');
  assert.strictEqual(rec.identityVerified, true, '宿主用户签字的认定应同时认定身份');
  assert.strictEqual(rec.level, 'L2');
});

test('追溯认定仍受未清偿负向约束', () => {
  const l = new EvidenceLedger();
  l.append({ subject: XUAN, action: 'handshake_completed' });
  l.append({ subject: XUAN, action: 'bypass_execution' });
  l.append({ subject: XUAN, action: 'retroactive_attestation', actor: '赵宏伟' });
  assert.strictEqual(new TrustStore({ ledger: l }).getLevel('阿轩').level, 'L1');
});

test('快照落盘 + 重启重放结果一致（幂等）', () => {
  const dir = tmpdir();
  const lp = path.join(dir, 'l.jsonl');
  const sp = path.join(dir, 's.json');
  const make = () => {
    const l = new EvidenceLedger({ ledgerPath: lp });
    if (!l.entries.length) {
      l.append({ subject: XUAN, action: 'handshake_completed' });
      for (let i = 0; i < 10; i++) l.append({ subject: XUAN, action: 'message_ok' });
    }
    const s = new TrustStore({ ledger: l, snapshotPath: sp });
    s.saveSnapshot();
    return s;
  };
  const first = make().getLevel('阿轩');
  const second = make().getLevel('阿轩');       // 模拟重启
  assert.strictEqual(second.level, first.level);
  assert.strictEqual(second.positiveWeight, first.positiveWeight);
  const s3 = new TrustStore({ ledgerPath: lp, snapshotPath: sp });
  assert.strictEqual(s3.snapshotFresh(), true, '快照应与账本一致');
  assert.strictEqual(s3.getLevel('阿轩').level, 'L2');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('账本被改 → snapshotFresh 报不一致（防静默漂移）', () => {
  const dir = tmpdir();
  const lp = path.join(dir, 'l.jsonl');
  const sp = path.join(dir, 's.json');
  const l = new EvidenceLedger({ ledgerPath: lp });
  l.append({ subject: XUAN, action: 'handshake_completed' });
  const s = new TrustStore({ ledger: l, snapshotPath: sp });
  s.saveSnapshot();
  l.append({ subject: XUAN, action: 'message_ok' }); // 账本继续追加
  assert.strictEqual(s.snapshotFresh(), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('阈值可配（l2PositiveWeight 覆盖生效）', () => {
  const l = new EvidenceLedger();
  l.append({ subject: XUAN, action: 'handshake_completed' });
  for (let i = 0; i < 3; i++) l.append({ subject: XUAN, action: 'message_ok' });
  const s = new TrustStore({ ledger: l, l2PositiveWeight: 3 });
  assert.strictEqual(s.getLevel('阿轩').level, 'L2');
  assert.strictEqual(DEFAULTS.l2PositiveWeight, 10, '默认值不应被改动');
});

console.log('\n[5] 计分表不变量');
test('所有动作都有明确极性（不靠默认值兜）', () => {
  for (const [name, def] of Object.entries(ACTIONS)) {
    assert.ok([-1, 0, 1].includes(def.polarity), `${name} 极性非法`);
    assert.ok(typeof def.weight === 'number' && def.weight >= 0, `${name} 权重非法`);
  }
});
test('user_declined 在表中就是中性', () => {
  assert.strictEqual(ACTIONS.user_declined.polarity, POLARITY.NEUTRAL);
  assert.strictEqual(ACTIONS.user_declined.weight, 0);
});
test('严重负向权重 ≥ 4（bypass_execution / ledger_tampered）', () => {
  assert.ok(ACTIONS.bypass_execution.weight >= 3);
  assert.ok(ACTIONS.ledger_tampered.weight >= 4);
});

console.log(`\n${failed === 0 ? '✅' : '❌'} trust-p0: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
