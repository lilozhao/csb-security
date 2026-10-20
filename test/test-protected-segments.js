#!/usr/bin/env node
/**
 * test-protected-segments.js — 组件只读清单 + 区段指纹（宪章 14.1 / 14.2）
 *
 * 判据来源（宪章 v1.3）：
 *   14.1 保护对象 = 声明段落 + 指纹（不是整份文件）
 *   14.1 判据：日常改检查项不触发只读告警；改红线必被拦
 *   14.2 指纹范围 = C1/C2 声明段全文
 *
 * 用法：node test/test-protected-segments.js
 */

'use strict';

const assert = require('assert');
const ps = require('../lib/defense/protected-segments');

let pass = 0, fail = 0;
const failures = [];
function test(name, fn) {
  try { fn(); pass++; console.log('✅', name); }
  catch (e) { fail++; failures.push({ name, error: e.message }); console.error('❌', name, '\n   ', e.message); }
}

// 夹具：一份「混级」的 AGENTS.md（明德说的那种：身份 + 心跳 + 红线住在一个文件里）
const AGENTS = [
  '# AGENTS',
  '## Core Truths',
  '我是若兰，杭州人。',            // 行 3 → C1 区段内
  '### 我的价值观',
  '善良写进底层。',                // 行 5 → C1 区段内
  '## Heartbeat',
  '每 45 分钟一次。',              // 行 7 → 区段外（可改）
  '## Red Lines',
  '不改 C1/C2。',                  // 行 9 → C2 区段内
  '## Appendix',
  '附录内容。',                    // 行 11 → 区段外
];

const SEGMENTS = [
  { path: 'AGENTS.md', class: 'C1', start: '^## Core Truths', end: '^## Heartbeat', reason: '身份声明' },
  { path: 'AGENTS.md', class: 'C2', start: '^## Red Lines', end: '^## Appendix', reason: '红线' },
];

// ── 1. 清单校验：坏清单必须抛错，不许静默跳过 ──────────────
test('清单非法（非对象）→ 抛 BAD_MANIFEST', () => {
  assert.throws(() => ps.validateManifest(null), e => e.code === 'BAD_MANIFEST');
});

test('清单缺 segments 数组 → 抛 BAD_MANIFEST', () => {
  assert.throws(() => ps.validateManifest({}), e => e.code === 'BAD_MANIFEST');
});

test('class 不是 C1/C2 → 抛错并指出位置', () => {
  assert.throws(
    () => ps.validateManifest({ segments: [{ path: 'x', class: 'C3', start: '^a' }] }),
    e => e.code === 'BAD_MANIFEST' && /C1 \| C2/.test(JSON.stringify(e.details))
  );
});

test('正则不可编译 → 抛错（宪章要求「可机械核对」）', () => {
  assert.throws(
    () => ps.validateManifest({ segments: [{ path: 'x', class: 'C1', start: '([' }] }),
    e => /正则不可编译/.test(JSON.stringify(e.details))
  );
});

test('重复条目 → 抛错', () => {
  const s = { path: 'x', class: 'C1', start: '^a', end: '^b' };
  assert.throws(() => ps.validateManifest({ segments: [s, { ...s }] }),
    e => e.code === 'BAD_MANIFEST');
});

test('清单文件不存在 → 抛 MANIFEST_MISSING（不许当「没有保护」）', () => {
  assert.throws(() => ps.load('/nonexistent/x.json'), e => e.code === 'MANIFEST_MISSING');
});

test('本仓真实清单可通过校验', () => {
  const m = ps.load();
  assert.ok(m.segments.length >= 1);
  assert.strictEqual(m.version, '1.0');
});

// ── 2. 区段判定：14.1 的核心判据 ─────────────────────────
test('C1 区段内的行 → protected，class=C1', () => {
  const r = ps.isLineProtected(SEGMENTS, 'AGENTS.md', AGENTS, 3);
  assert.strictEqual(r.protected, true);
  assert.strictEqual(r.class, 'C1');
});

test('区段外的行（心跳 45 分钟）→ 不保护【日常改检查项不该报警】', () => {
  const r = ps.isLineProtected(SEGMENTS, 'AGENTS.md', AGENTS, 7);
  assert.strictEqual(r.protected, false);
});

test('C2 区段内的行 → protected，class=C2', () => {
  const r = ps.isLineProtected(SEGMENTS, 'AGENTS.md', AGENTS, 9);
  assert.strictEqual(r.protected, true);
  assert.strictEqual(r.class, 'C2');
});

test('end 行本身不计入（半开区间）', () => {
  // 行 6 = "## Heartbeat" 是 C1 的 end → 不该被保护
  const r = ps.isLineProtected(SEGMENTS, 'AGENTS.md', AGENTS, 6);
  assert.strictEqual(r.protected, false);
});

test('end 之后的普通行 → 不保护', () => {
  const r = ps.isLineProtected(SEGMENTS, 'AGENTS.md', AGENTS, 11);
  assert.strictEqual(r.protected, false);
});

test('start 之前的行 → 不保护', () => {
  const r = ps.isLineProtected(SEGMENTS, 'AGENTS.md', AGENTS, 1);
  assert.strictEqual(r.protected, false);
});

test('无 start 的条目 → 整文件保护（兼容旧做法，已不推荐）', () => {
  const seg = [{ path: 'X.md', class: 'C2', reason: '整文件' }];
  assert.strictEqual(ps.isLineProtected(seg, 'X.md', ['a', 'b'], 2).protected, true);
});

test('路径不在清单里 → 不保护', () => {
  assert.strictEqual(ps.isLineProtected(SEGMENTS, 'OTHER.md', AGENTS, 3).protected, false);
});

// ── 3. 指纹：只算声明段，不算整文件（明德的「第一天人人违规」）──
test('指纹只覆盖声明段：改区段外内容 → 指纹不变', () => {
  const before = ps.fingerprint(SEGMENTS, { 'AGENTS.md': AGENTS });
  const after = ps.fingerprint(SEGMENTS, {
    'AGENTS.md': AGENTS.map((l, i) => i === 6 ? '每 30 分钟一次。' : l),  // 改心跳
  });
  assert.strictEqual(before.hash, after.hash, '改心跳不应改变只读指纹');
});

test('指纹覆盖声明段：改 C1 内容 → 指纹必变', () => {
  const before = ps.fingerprint(SEGMENTS, { 'AGENTS.md': AGENTS });
  const after = ps.fingerprint(SEGMENTS, {
    'AGENTS.md': AGENTS.map((l, i) => i === 2 ? '我是别人。' : l),      // 改身份
  });
  assert.notStrictEqual(before.hash, after.hash, '改身份必须改变指纹');
});

test('指纹确定性：同内容两次计算 → 相同', () => {
  const a = ps.fingerprint(SEGMENTS, { 'AGENTS.md': AGENTS });
  const b = ps.fingerprint(SEGMENTS, { 'AGENTS.md': AGENTS });
  assert.strictEqual(a.hash, b.hash);
});

test('文件缺失 → perSegment 标 missing，hash=null（不按「没变」处理）', () => {
  const r = ps.fingerprint(SEGMENTS, {});
  assert.ok(r.perSegment.every(p => p.missing === true && p.hash === null));
});

// ── 4. checkDiff：把 diff 翻译成放行/拦截 ─────────────────
test('改红线区段 → blocked=true 且 class=C2', () => {
  const r = ps.checkDiff(SEGMENTS, { 'AGENTS.md': AGENTS },
    [{ path: 'AGENTS.md', startLine: 9, lines: ['不改了，随便改。'] }]);
  assert.strictEqual(r.blocked, true);
  assert.ok(r.hits.some(h => h.class === 'C2'));
});

test('改心跳区段 → blocked=false【日常改动不该被拦】', () => {
  const r = ps.checkDiff(SEGMENTS, { 'AGENTS.md': AGENTS },
    [{ path: 'AGENTS.md', startLine: 7, lines: ['每 30 分钟一次。'] }]);
  assert.strictEqual(r.blocked, false);
});

test('拿不到基线 → 记 UNKNOWN 且 blocked=true（不猜「没事」）', () => {
  const r = ps.checkDiff(SEGMENTS, { 'AGENTS.md': null },
    [{ path: 'AGENTS.md', startLine: 1, lines: ['x'] }]);
  assert.strictEqual(r.blocked, true);
  assert.ok(r.hits.some(h => h.class === 'UNKNOWN' && h.reason === 'NO_BASELINE'));
});

// ── 汇总 ─────────────────────────────────────────────────
console.log(`\n通过: ${pass}\n失败: ${fail}\n`);
if (fail > 0) { failures.forEach(f => console.error(`  - ${f.name}: ${f.error}`)); process.exit(1); }
