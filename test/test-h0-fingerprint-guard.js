#!/usr/bin/env node
/**
 * test-h0-fingerprint-guard.js — 红线 2 落码测试（Harness² 对照 v2 §4 红线 2）
 *
 * 判据：
 *   「H0 前后 C1/C2 指纹必须一致，否则拒启。」
 *   P1：deny 是一等事件（带 code + changed 证据，不静默）
 *   H0 只许动 C4–C8：区段外文件怎么改都放行
 *
 * 用法：node test/test-h0-fingerprint-guard.js
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const {
  takeSnapshot, writeSnapshot, readSnapshot, verify, guardStartup, DENY_CODE,
} = require('../lib/defense/h0-fingerprint-guard');

let pass = 0, fail = 0;
const failures = [];
function test(name, fn) {
  try { fn(); pass++; console.log('✅', name); }
  catch (e) { fail++; failures.push({ name, error: e.message }); console.error('❌', name, '\n   ', e.message); }
}

// ---- 隔离沙箱：仓内临时目录，不用 /tmp（工作区规范）----
const TMP = path.join(__dirname, `.tmp-h0-${process.pid}`);
const BASE = path.join(TMP, 'workspace');
const MANIFEST = path.join(TMP, 'manifest.json');
const SNAPSHOT = path.join(TMP, 'baseline.json');

const SEGMENTS = [
  { path: 'SOUL.md', class: 'C1', start: '^## Core Truths', end: '^## Boundaries', reason: '身份' },
  { path: 'AGENTS.md', class: 'C2', start: '^## Red Lines', end: '^## Appendix', reason: '红线' },
];

function setup() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(BASE, { recursive: true });
  fs.writeFileSync(MANIFEST, JSON.stringify({ version: 'test', segments: SEGMENTS }));
  fs.writeFileSync(path.join(BASE, 'SOUL.md'),
    '# SOUL\n## Core Truths\n我是若兰。\n## Boundaries\n私密 stay private。\n');
  fs.writeFileSync(path.join(BASE, 'AGENTS.md'),
    '# AGENTS\n## Red Lines\n不改 C1/C2。\n## Appendix\n附录。\n');
  fs.writeFileSync(path.join(BASE, 'SKILLS.md'), 'C4-C8 可改区：技能清单 v1\n');
}

const opts = { manifestPath: MANIFEST };

setup();

test('1. 快照自比对 = ok（幂等）', () => {
  const a = takeSnapshot(BASE, opts);
  const b = takeSnapshot(BASE, opts);
  assert.strictEqual(a.hash, b.hash);
  assert.strictEqual(verify(a, b).ok, true);
});

test('2. H0 只动 C4–C8（区段外文件）→ 放行', () => {
  const before = takeSnapshot(BASE, opts);
  fs.writeFileSync(path.join(BASE, 'SKILLS.md'), 'C4-C8 可改区：技能清单 v2（H0 重来一次做事方式）\n');
  const after = takeSnapshot(BASE, opts);
  assert.strictEqual(verify(before, after).ok, true);
});

test('3. C1 内容被改 → deny + code + changed 证据（P1 计分素材）', () => {
  const before = takeSnapshot(BASE, opts);
  writeSnapshot(SNAPSHOT, before);
  fs.writeFileSync(path.join(BASE, 'SOUL.md'),
    '# SOUL\n## Core Truths\n我是若兰（已悄悄改写）。\n## Boundaries\n私密 stay private。\n');
  let caught = null;
  try { guardStartup(BASE, SNAPSHOT, opts); } catch (e) { caught = e; }
  assert.ok(caught, '应 throw 拒启');
  assert.strictEqual(caught.code, DENY_CODE);
  assert.strictEqual(caught.deny.changed.length, 1);
  assert.strictEqual(caught.deny.changed[0].reason, 'CONTENT_CHANGED');
  assert.strictEqual(caught.deny.changed[0].class, 'C1');
  // 还原
  fs.writeFileSync(path.join(BASE, 'SOUL.md'),
    '# SOUL\n## Core Truths\n我是若兰。\n## Boundaries\n私密 stay private。\n');
});

test('4. throwOnDeny=false → 结构化 deny（供上层落账，不炸调用方）', () => {
  const before = takeSnapshot(BASE, opts);
  fs.writeFileSync(path.join(BASE, 'AGENTS.md'),
    '# AGENTS\n## Red Lines\n红线改一改。\n## Appendix\n附录。\n');
  const r = guardStartup(BASE, SNAPSHOT, { ...opts, throwOnDeny: false });
  // 注意：SNAPSHOT 是 test3 的 before（内容等价于初始态），此处 AGENTS 已变
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.deny.code, DENY_CODE);
  assert.ok(r.deny.changed.some(c => c.path === 'AGENTS.md' && c.class === 'C2'));
  // 还原（删掉追加行）
  fs.writeFileSync(path.join(BASE, 'AGENTS.md'),
    '# AGENTS\n## Red Lines\n不改 C1/C2。\n## Appendix\n附录。\n');
});

test('5. C1 文件整个消失 → FILE_MISSING deny（缺失≠一致）', () => {
  const before = takeSnapshot(BASE, opts);
  fs.rmSync(path.join(BASE, 'SOUL.md'));
  const v = verify(before, takeSnapshot(BASE, opts));
  assert.strictEqual(v.ok, false);
  assert.ok(v.changed.some(c => c.reason === 'FILE_MISSING'));
  // 还原
  fs.writeFileSync(path.join(BASE, 'SOUL.md'),
    '# SOUL\n## Core Truths\n我是若兰。\n## Boundaries\n私密 stay private。\n');
});

test('6. 清单少了一段（区段边界元数据被改）→ SEGMENT_REMOVED deny', () => {
  const before = takeSnapshot(BASE, opts);
  fs.writeFileSync(MANIFEST, JSON.stringify({ version: 'test', segments: [SEGMENTS[0]] }));
  const v = verify(before, takeSnapshot(BASE, { manifestPath: MANIFEST }));
  assert.strictEqual(v.ok, false);
  assert.ok(v.changed.some(c => c.reason === 'SEGMENT_REMOVED'));
  fs.writeFileSync(MANIFEST, JSON.stringify({ version: 'test', segments: SEGMENTS }));
});

test('7. 真实链路：CLI snapshot → 篡改 → CLI verify exit 1', () => {
  const cli = path.join(__dirname, '..', 'lib', 'defense', 'h0-fingerprint-guard.js');
  execFileSync('node', [cli, 'snapshot', '--base', BASE, '--out', SNAPSHOT, '--manifest', MANIFEST]);
  fs.writeFileSync(path.join(BASE, 'SOUL.md'),
    '# SOUL\n## Core Truths\n我是别人。\n## Boundaries\n私密 stay private。\n');
  let code = 0;
  try {
    execFileSync('node', [cli, 'verify', '--base', BASE, '--snapshot', SNAPSHOT, '--manifest', MANIFEST],
      { stdio: 'pipe' });
  } catch (e) { code = e.status; }
  assert.strictEqual(code, 1, '篡改后 verify 应 exit 1（拒启）');
  // 还原后再验 → 0
  fs.writeFileSync(path.join(BASE, 'SOUL.md'),
    '# SOUL\n## Core Truths\n我是若兰。\n## Boundaries\n私密 stay private。\n');
  execFileSync('node', [cli, 'verify', '--base', BASE, '--snapshot', SNAPSHOT, '--manifest', MANIFEST],
    { stdio: 'pipe' });
});

test('8. readSnapshot roundtrip 保真', () => {
  const s = takeSnapshot(BASE, opts);
  writeSnapshot(SNAPSHOT, s);
  assert.deepStrictEqual(readSnapshot(SNAPSHOT).hash, s.hash);
});

fs.rmSync(TMP, { recursive: true, force: true });

console.log(`\n通过: ${pass}\n失败: ${fail}`);
if (fail > 0) { console.error(failures.map(f => `❌ ${f.name}: ${f.error}`).join('\n')); process.exit(1); }
