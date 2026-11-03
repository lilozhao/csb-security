#!/usr/bin/env node
/**
 * 并发写链回归测试（2026-11-04）
 *
 * 锁的是这件事：**多个进程/多个实例共用同一账本时，链不许分叉。**
 *
 * 背景：修之前 seq 取内存数组长度（this.entries.length + 1），
 *   两个写入者各自算出同样的 seq 并接同一个 prev_hash → 写到磁盘就分叉。
 *   生产账本实测 694 行里 15 个 seq 重复、4 处序号倒退，
 *   GDI 验链整体判 chain_invalid（维度2 全 N/A）。
 *
 * 本测试真的起多个进程往同一文件写，然后验链。
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { AuditLog } = require('../lib/audit/audit-log.js');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✅ ${name}`); pass++; }
  catch (e) { console.log(`  ❌ ${name}\n     ${e.message}`); fail++; }
}

const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'csb-audit-'));

console.log('\n=== 单进程基本行为不回归 ===');
t('空账本第一条 seq=1 prev_hash=GENESIS', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'a.jsonl');
  const log = new AuditLog({ logPath: p });
  const r = log.append({ event_type: 'request', caller_id: 'x' });
  if (r.seq !== 1) throw new Error(`seq=${r.seq}`);
  if (r.prev_hash !== 'GENESIS') throw new Error(`prev=${r.prev_hash}`);
  if (log.verifyChain().valid !== true) throw new Error('链条无效');
});

t('连续追加 seq 递增且链有效', () => {
  const dir = tmpdir();
  const log = new AuditLog({ logPath: path.join(dir, 'a.jsonl') });
  for (let i = 0; i < 5; i++) log.append({ event_type: 'request', caller_id: `c${i}` });
  const v = log.verifyChain();
  if (!v.valid) throw new Error(JSON.stringify(v));
  if (v.count !== 5) throw new Error(`count=${v.count}`);
});

console.log('\n=== 多实例共用同一文件（旧代码在这里必挂） ===');
t('两个 AuditLog 实例交替写 → 链不分叉', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'a.jsonl');
  const a = new AuditLog({ logPath: p });
  const b = new AuditLog({ logPath: p });

  for (let i = 0; i < 20; i++) {
    (i % 2 === 0 ? a : b).append({ event_type: 'request', caller_id: `i${i}` });
  }

  const fresh = new AuditLog({ logPath: p });
  const v = fresh.verifyChain();
  if (!v.valid) throw new Error(`链断：${JSON.stringify(v)}`);

  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const seqs = lines.map((e) => e.seq);
  const dups = seqs.filter((s, i) => seqs.indexOf(s) !== i);
  if (dups.length) throw new Error(`seq 重复：${dups.slice(0, 5)}`);
  const back = seqs.filter((s, i) => i > 0 && s <= seqs[i - 1]);
  if (back.length) throw new Error(`序号倒退：${back.slice(0, 5)}`);
  if (lines.length !== 20) throw new Error(`应有 20 条，实际 ${lines.length}`);
});

t('实例持有旧快照后新建的实例写入 → 仍不错位', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'a.jsonl');
  const stale = new AuditLog({ logPath: p });
  stale.append({ event_type: 'request', caller_id: 'first' });

  // 另一个实例（模拟另一个进程）先写了 3 条
  const other = new AuditLog({ logPath: p });
  for (let i = 0; i < 3; i++) other.append({ event_type: 'request', caller_id: `o${i}` });

  // stale 的内存只有 1 条，但 seq 应从磁盘末行续上
  const r = stale.append({ event_type: 'request', caller_id: 'late' });
  if (r.seq !== 5) throw new Error(`stale 实例应续到 seq=5，实际 ${r.seq}`);

  const fresh = new AuditLog({ logPath: p });
  if (!fresh.verifyChain().valid) throw new Error('链条无效');
});

console.log('\n=== 真并发：多进程同时写 ===');
t('4 个进程各写 15 条 → 链完整、seq 无重复', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'a.jsonl');
  const worker = path.join(__dirname, '.audit-worker.js');
  fs.writeFileSync(worker, `
const { AuditLog } = require(${JSON.stringify(path.join(__dirname, '../lib/audit/audit-log.js'))});
const log = new AuditLog({ logPath: process.argv[2] });
const tag = process.argv[3];
for (let i = 0; i < 15; i++) log.append({ event_type: 'request', caller_id: tag + '-' + i });
`);
  try {
    // 真并发：先把 4 个子进程同时拉起，再逐个 spawnSync 等待
    // （不能忙等 exit 事件——那会阻塞事件循环，事件永远不触发）
    const { spawnSync, spawn } = require('child_process');
    const tags = ['p1', 'p2', 'p3', 'p4'];
    const kids = tags.map((tag) => spawn(process.execPath, [worker, p, tag], { stdio: 'ignore' }));
    // 用 waitpid 语义：Node 里没提供，改成「先等所有退出」用轮询文件条数 + 最后校验
    // 简单可靠做法：用 spawnSync 重跑一轮串行对照，同时保留上面并发跑的结果
    for (const c of kids) {
      // spawn 返回的 ChildProcess 在 stdio ignored 时无法同步等；
      // 因此这里只保证它们已启动，后面用「文件条数到 60」作为完成判据
      void c;
    }
    const deadline = Date.now() + 30000;
    const countLines = () => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).length : 0);
    while (countLines() < 60 && Date.now() < deadline) {
      spawnSync(process.execPath, ['-e', 'setTimeout(()=>{},50)']);  // 让出事件循环给子进程收尾
    }
    const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    if (lines.length !== 60) throw new Error(`应有 60 条，实际 ${lines.length}`);

    const fresh = new AuditLog({ logPath: p });
    const v = fresh.verifyChain();
    if (!v.valid) throw new Error(`并发写后链断：${JSON.stringify(v)}`);

    const seqs = lines.map((e) => e.seq);
    const uniq = new Set(seqs);
    if (uniq.size !== seqs.length) throw new Error(`seq 重复 ${seqs.length - uniq.size} 个`);
    const sorted = [...seqs].sort((a, b) => a - b);
    if (sorted[0] !== 1 || sorted[sorted.length - 1] !== 60) throw new Error('seq 不是 1..60');
  } finally {
    try { fs.unlinkSync(worker); } catch {}
  }
});

console.log('\n=== 尾读健壮性 ===');
t('大文件也能从尾部读到最后一条', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'a.jsonl');
  const log = new AuditLog({ logPath: p });
  for (let i = 0; i < 300; i++) log.append({ event_type: 'request', caller_id: `bulk${i}` });
  const last = log._readLastLine();
  if (!last) throw new Error('未读到末行');
  if (last.seq !== 300) throw new Error(`末行 seq=${last.seq}`);
});

t('空文件不崩', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'empty.jsonl');
  fs.writeFileSync(p, '');
  const log = new AuditLog({ logPath: p });
  const r = log.append({ event_type: 'request' });
  if (r.seq !== 1) throw new Error(`seq=${r.seq}`);
});

t('不传 logPath（纯内存）仍可用', () => {
  const log = new AuditLog();
  log.append({ event_type: 'request' });
  log.append({ event_type: 'request' });
  const v = log.verifyChain();
  if (!v.valid || v.count !== 2) throw new Error(JSON.stringify(v));
});

// 输出格式必须与 run-all-tests.js 的正则匹配：/通过: (\d+)\n失败: (\d+)/
console.log(`\n通过: ${pass}\n失败: ${fail}`);
process.exit(fail === 0 ? 0 : 1);