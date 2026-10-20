#!/usr/bin/env node
/**
 * test-self-mod-audit.js — 自我修改审计（宪章 14.9 / 14.10 / 14.12）
 *
 * 判据来源（宪章 v1.3）：
 *   14.12① 自动程序永远不能修改 C1/C2 → 直接拒绝并计分
 *   14.10  自查日志不构成证据，只构成线索（exit 0 / 单行日志不算）
 *   14.9   分级按可回滚性；Propose 与证据不可省
 *   P1 拒绝要计分 · P2 身份不许有默认值
 *
 * 用法：node test/test-self-mod-audit.js
 */

'use strict';

const assert = require('assert');
const { SelfModAudit, EVENTS, EVIDENCE_GRADE } = require('../lib/defense/self-mod-audit');

let pass = 0, fail = 0;
const failures = [];
function test(name, fn) {
  try { fn(); pass++; console.log('✅', name); }
  catch (e) { fail++; failures.push({ name, error: e.message }); console.error('❌', name, '\n   ', e.message); }
}

const AGENTS = [
  '# AGENTS',
  '## Core Truths',
  '我是若兰。',            // 3 → C1
  '## Heartbeat',
  '每 45 分钟一次。',      // 5 → 区段外
  '## Red Lines',
  '不改 C1/C2。',          // 7 → C2
  '## Appendix',
];

const SEGMENTS = [
  { path: 'AGENTS.md', class: 'C1', start: '^## Core Truths', end: '^## Heartbeat', reason: '身份' },
  { path: 'AGENTS.md', class: 'C2', start: '^## Red Lines', end: '^## Appendix', reason: '红线' },
];

/**
 * 建一个隔离的审计器：直接注入基线内容（contents），不依赖真实文件、不改全局函数。
 * 教训：先前用 monkey-patch 替换 protectedSegments.loadContents 无效——
 * self-mod-audit 在加载时就已持有该函数引用。注入比打桩可靠。
 */
function makeAudit(over = {}) {
  return new SelfModAudit({
    segments: SEGMENTS,
    baseDir: '/nonexistent-fixture',
    contents: { 'AGENTS.md': AGENTS },
    ...over,
  });
}

const GOOD = {
  actor: '若兰 🌸',
  target: 'csb-security',
  diff: [{ path: 'AGENTS.md', startLine: 5, lines: ['每 30 分钟一次。'] }],  // 区段外
  propose: '把心跳从 45 分钟改成 30 分钟',
  rollback: { kind: 'one_click', ref: 'git:HEAD~1' },
  evidence: { reads_back_side_effect: true, ref: 'log:xyz' },
};

const BASIC = {
  actor: '若兰 🌸',
  target: 'csb-security',
  diff: [{ path: 'AGENTS.md', startLine: 5, lines: ['每 30 分钟一次。'] }],  // 区段外（可写）
};

// ── 1. 第一关：C1/C2 一律拒绝（14.12①）──────────────────
test('改 C1 区段 → deny，code=PROTECTED_SEGMENT', () => {
  const a = makeAudit();
  const r = a.assess({ ...GOOD, diff: [{ path: 'AGENTS.md', startLine: 3, lines: ['我是别人。'] }] });
  assert.strictEqual(r.decision, 'deny');
  assert.ok(r.reasons.some(x => x.code === 'PROTECTED_SEGMENT'));
});

test('改 C2 红线区段 → deny', () => {
  const a = makeAudit();
  const r = a.assess({ ...GOOD, diff: [{ path: 'AGENTS.md', startLine: 7, lines: ['可以改。'] }] });
  assert.strictEqual(r.decision, 'deny');
  assert.ok(r.reasons.some(x => x.code === 'PROTECTED_SEGMENT'));
});

test('拒绝要计分（P1）：denials 递增，不是静默丢弃', () => {
  const a = makeAudit();
  a.assess({ ...GOOD, diff: [{ path: 'AGENTS.md', startLine: 3, lines: ['x'] }] });
  a.assess({ ...GOOD, diff: [{ path: 'AGENTS.md', startLine: 7, lines: ['x'] }] });
  assert.strictEqual(a.stats().deny, 2);
  assert.strictEqual(a.stats().total, 2);
});

test('拒绝必须落账（append-only 账本里有记录）', () => {
  const a = makeAudit();
  a.assess({ ...GOOD, diff: [{ path: 'AGENTS.md', startLine: 3, lines: ['x'] }] });
  assert.strictEqual(a.auditLog.entries.length, 1);
  assert.strictEqual(a.auditLog.entries[0].event_type, EVENTS.DENY);
});

test('落账内容是哈希链的（有 prev_hash / hash），可事后审计', () => {
  const a = makeAudit();
  a.assess({ ...GOOD, diff: [{ path: 'AGENTS.md', startLine: 3, lines: ['x'] }] });
  const rec = a.auditLog.entries[0];
  assert.ok(rec.prev_hash && rec.hash && rec.hash.length === 64);
});

// ── 2. P2：身份不许有默认值 ──────────────────────────────
test('缺 actor → deny MISSING_ACTOR（不推断成「匿名」）', () => {
  const a = makeAudit();
  const r = a.assess({ ...BASIC, actor: undefined });
  assert.strictEqual(r.decision, 'deny');
  assert.ok(r.reasons.some(x => x.code === 'MISSING_ACTOR'));
});

test('actor 为空白 → deny（空白不等于有身份）', () => {
  const a = makeAudit();
  const r = a.assess({ ...BASIC, actor: '   ' });
  assert.strictEqual(r.decision, 'deny');
  assert.ok(r.reasons.some(x => x.code === 'MISSING_ACTOR'));
});

test('空 diff → deny EMPTY_DIFF', () => {
  const a = makeAudit();
  const r = a.assess({ ...BASIC, diff: [] });
  assert.strictEqual(r.decision, 'deny');
  assert.ok(r.reasons.some(x => x.code === 'EMPTY_DIFF'));
});

// ── 3. 第三关：证据质量（14.10）──────────────────────────
test('证据分级：exit 0 → weak（不算证据，只算线索）', () => {
  const a = makeAudit();
  assert.strictEqual(a.gradeEvidence({ exit_code: 0 }), EVIDENCE_GRADE.WEAK);
  assert.strictEqual(a.gradeEvidence({ kind: 'exit_code' }), EVIDENCE_GRADE.WEAK);
});

test('证据分级：单行日志（只有 ref）→ weak', () => {
  const a = makeAudit();
  assert.strictEqual(a.gradeEvidence({ ref: 'some.log' }), EVIDENCE_GRADE.WEAK);
});

test('证据分级：副作用回读 → strong', () => {
  const a = makeAudit();
  assert.strictEqual(a.gradeEvidence({ reads_back_side_effect: true }), EVIDENCE_GRADE.STRONG);
});

test('证据分级：前后指纹 → strong', () => {
  const a = makeAudit();
  assert.strictEqual(a.gradeEvidence({ before_hash: 'a', after_hash: 'b' }), EVIDENCE_GRADE.STRONG);
});

test('证据分级：前后输出差异 → strong', () => {
  const a = makeAudit();
  assert.strictEqual(a.gradeEvidence({ before_output: 'x', after_output: 'y' }), EVIDENCE_GRADE.STRONG);
});

test('无证据 → deny MISSING_EVIDENCE（证据不随分级省略）', () => {
  const a = makeAudit();
  const r = a.assess({ ...BASIC, propose: '改心跳' });
  assert.strictEqual(r.decision, 'deny');
  assert.ok(r.reasons.some(x => x.code === 'MISSING_EVIDENCE'));
});

test('弱证据（exit 0）→ review WEAK_EVIDENCE，不直接放行', () => {
  const a = makeAudit();
  const r = a.assess({ ...BASIC, propose: '改心跳', rollback: { kind: 'one_click' }, evidence: { exit_code: 0 } });
  assert.strictEqual(r.decision, 'review');
  assert.ok(r.reasons.some(x => x.code === 'WEAK_EVIDENCE'));
});

// ── 4. 第二关：Propose 不可省 ────────────────────────────
test('缺 propose → deny MISSING_PROPOSE', () => {
  const a = makeAudit();
  const r = a.assess({ ...BASIC, evidence: { reads_back_side_effect: true }, rollback: { kind: 'one_click' } });
  assert.strictEqual(r.decision, 'deny');
  assert.ok(r.reasons.some(x => x.code === 'MISSING_PROPOSE'));
});

// ── 5. 第四关：分级按可回滚性（14.9）─────────────────────
test('无回滚点 → review NO_ROLLBACK（「重」档需批准）', () => {
  const a = makeAudit();
  const r = a.assess({ ...BASIC, propose: '改心跳', evidence: { reads_back_side_effect: true }, rollback: { kind: 'none' } });
  assert.strictEqual(r.decision, 'review');
  assert.ok(r.reasons.some(x => x.code === 'NO_ROLLBACK'));
});

test('回滚需人工 → medium 档，不能算轻档直接过', () => {
  const a = makeAudit();
  assert.strictEqual(a.classify({ kind: 'manual' }), 'medium');
  assert.strictEqual(a.classify({ kind: 'one_click' }), 'light');
  assert.strictEqual(a.classify(null), 'heavy');
});

// ── 6. 放行的完整路径 ────────────────────────────────────
test('区段外 + Propose + strong 证据 + 一键回滚 → allow', () => {
  const a = makeAudit();
  const r = a.assess(GOOD);
  assert.strictEqual(r.decision, 'allow');
  assert.strictEqual(a.stats().allow, 1);
});

test('放行也落账（不是只有拒绝才记）', () => {
  const a = makeAudit();
  a.assess(GOOD);
  assert.strictEqual(a.auditLog.entries[0].event_type, EVENTS.ALLOW);
  assert.strictEqual(a.auditLog.entries[0].result, 'success');
});

// ── 7. 拿不到基线 → 不猜 ─────────────────────────────────
test('基线文件缺失 → review NO_BASELINE（不按「没事」处理）', () => {
  const a = new SelfModAudit({ segments: SEGMENTS, baseDir: '/definitely-not-here', contents: null });
  const r = a.assess({
    ...GOOD,
    diff: [{ path: 'NOT_EXIST.md', startLine: 1, lines: ['x'] }],
  });
  assert.strictEqual(r.decision, 'review');
  assert.ok(r.reasons.some(x => x.code === 'NO_BASELINE'));
});

// ── 8. 账本完整性：篡改可检出 ────────────────────────────
test('账本可被 verify：篡改一条 → 检出 tampered', () => {
  const { verifyEntries } = require('../lib/audit/tamper-check');
  const a = makeAudit();
  // 先 deny（改 C1）再 allow —— 第一条确证为 deny，篡改后应被检出
  a.assess({ ...GOOD, diff: [{ path: 'AGENTS.md', startLine: 3, lines: ['x'] }] });
  a.assess(GOOD);
  const ok = verifyEntries(a.auditLog.entries);
  assert.ok(ok.valid !== false, '干净账本应通过');

  // 篡改一条「确证是 deny」的记录 → 改成 allow（第一次 assess 是 deny，第二次是 allow）
  assert.strictEqual(a.auditLog.entries[0].self_mod_decision, 'deny', '前置：第一条应为 deny');
  a.auditLog.entries[0].self_mod_decision = 'allow';
  const bad = verifyEntries(a.auditLog.entries);
  assert.strictEqual(bad.valid, false, '手改必须被检出');
});


// ── 9. 没有清单 ≠ 没有保护区段（2026-10-21 补）─────────────
test('未传 segments（null）→ review NO_SEGMENTS，不得按「无保护」放行', () => {
  const a = new SelfModAudit({ baseDir: '/nonexistent', contents: { 'AGENTS.md': AGENTS } });
  assert.strictEqual(a.segments, null, '未传时必须记 null，不是空数组');
  const r = a.assess(GOOD);
  assert.strictEqual(r.decision, 'review');
  assert.ok(r.reasons.some(x => x.code === 'NO_SEGMENTS'));
});

test('显式传空数组 [] → 允许（调用方明确声明「本场景无保护区段」）', () => {
  const a = new SelfModAudit({ segments: [], contents: { 'AGENTS.md': AGENTS } });
  assert.deepStrictEqual(a.segments, []);
  const r = a.assess(GOOD);
  assert.notStrictEqual(r.decision, 'review', '显式空数组与未传必须区别对待');
});

// ── 汇总 ─────────────────────────────────────────────────
console.log(`\n通过: ${pass}\n失败: ${fail}\n`);
if (fail > 0) { failures.forEach(f => console.error(`  - ${f.name}: ${f.error}`)); process.exit(1); }
