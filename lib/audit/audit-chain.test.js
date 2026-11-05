#!/usr/bin/env node
/**
 * audit-chain.test.js —— 验链的「能报红」自测（不依赖测试框架）
 *
 * 为什么必须有这个文件：
 *   2026-11-05 发现 verifyChain 在账本超 1 万行时**恒定报红**（假红）。
 *   假红和假绿一样坏 —— 前者让人以为被篡改，后者让人以为没事。
 *   修完之后最大的风险是「改成一律返回 true」：那会把假红换成更贵的假绿。
 *   所以这里既有**反例**（必须报红）也有**正例**（必须能报绿），还有**假红回归**（不许再误报）。
 *
 * 用法: node lib/audit/audit-chain.test.js
 * 退出码: 0 全过 / 1 有失败
 *
 * 维护: 若兰 🌸 | 2026-11-05
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { AuditLog } = require('./audit-log.js');

let pass = 0;
const fails = [];
function t(name, cond, extra) {
  if (cond) { pass++; return; }
  fails.push(name + (extra ? ` — ${extra}` : ''));
}

function tmp() { return path.join(os.tmpdir(), `audt-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`); }
function readRows(f) { return fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); }
function writeRows(f, rows) { fs.writeFileSync(f, rows.map((r) => JSON.stringify(r)).join('\n') + '\n'); }

// ── 1) 正常链：必须报绿 ──────────────────────────────────────
{
  const f = tmp();
  const l = new AuditLog({ logPath: f });
  for (let i = 0; i < 20; i++) l.append({ event_type: 'request', caller_id: 'a', result: 'success' });
  const v = l.verifyChain();
  t('正常链报绿', v.valid === true, JSON.stringify(v));
  t('正常链计数正确', v.count === 20, `count=${v.count}`);
  t('正常链来源=disk', v.source === 'disk', `source=${v.source}`);
  fs.unlinkSync(f);
}

// ── 2) 改内容不改 hash：必须报 entry_tampered ────────────────
{
  const f = tmp();
  const l = new AuditLog({ logPath: f });
  for (let i = 0; i < 5; i++) l.append({ event_type: 'request', caller_id: 'a', result: 'success' });
  const rows = readRows(f);
  rows[2].caller_id = 'mallory';       // 篡改内容，hash 保持原样
  writeRows(f, rows);
  const v = new AuditLog({ logPath: f }).verifyChain();
  t('篡改内容被检出', v.valid === false && v.reason === 'entry_tampered', JSON.stringify(v));
  t('篡改位置报对', v.brokenAt === 2, `brokenAt=${v.brokenAt}`);
  fs.unlinkSync(f);
}

// ── 3) 删中间一行：必须报 hash_chain_broken ──────────────────
{
  const f = tmp();
  const l = new AuditLog({ logPath: f });
  for (let i = 0; i < 6; i++) l.append({ event_type: 'request', caller_id: 'a', result: 'success' });
  const rows = readRows(f);
  rows.splice(3, 1);                   // 抽掉第 4 行
  writeRows(f, rows);
  const v = new AuditLog({ logPath: f }).verifyChain();
  t('删行被检出', v.valid === false && v.reason === 'hash_chain_broken', JSON.stringify(v));
  fs.unlinkSync(f);
}

// ── 4) 【假红回归】超 maxEntries 后必须仍然报绿 ──────────────
{
  const f = tmp();
  const l = new AuditLog({ logPath: f, maxEntries: 50 });
  for (let i = 0; i < 120; i++) l.append({ event_type: 'request', caller_id: 'a', result: 'success' });
  const v = l.verifyChain();
  t('超容量后不假红（核心回归）', v.valid === true, JSON.stringify(v));
  t('超容量后报全量行数', v.count === 120, `count=${v.count}`);
  t('内存确实只留尾部', l.entries.length === 50, `entries=${l.entries.length}`);
  t('裁剪锚点已记录', l.trimmed.count === 70, JSON.stringify(l.trimmed));

  // 内存模式：必须报 partial，且**不许**假装从 GENESIS 起验
  const vm = l.verifyChain({ source: 'memory' });
  t('内存模式报 partial', vm.valid === true && vm.partial === true, JSON.stringify(vm));
  t('内存模式诚实标注范围', typeof vm.note === 'string' && vm.note.includes('已裁剪 70'), vm.note);

  // 重启后（从磁盘重载）也必须绿
  const v2 = new AuditLog({ logPath: f, maxEntries: 50 }).verifyChain();
  t('重启加载后仍绿', v2.valid === true, JSON.stringify(v2));
  fs.unlinkSync(f);
}

// ── 5) 超容量后篡改尾部：仍必须报红（不能因为有裁剪就放过）──
{
  const f = tmp();
  const l = new AuditLog({ logPath: f, maxEntries: 50 });
  for (let i = 0; i < 120; i++) l.append({ event_type: 'request', caller_id: 'a', result: 'success' });
  const rows = readRows(f);
  rows[rows.length - 2].result = 'failure';
  writeRows(f, rows);
  const v = new AuditLog({ logPath: f, maxEntries: 50 }).verifyChain();
  t('超容量后篡改仍被检出', v.valid === false && v.reason === 'entry_tampered', JSON.stringify(v));
  fs.unlinkSync(f);
}

// ── 6) 坏 JSON 行不能被当成「没问题」而静默跳过 ─────────────
{
  const f = tmp();
  const l = new AuditLog({ logPath: f });
  for (let i = 0; i < 3; i++) l.append({ event_type: 'request', caller_id: 'a', result: 'success' });
  fs.appendFileSync(f, '{not json}\n');
  const v = new AuditLog({ logPath: f }).verifyChain();
  t('坏行被计数上报', v.badLines === 1, JSON.stringify(v));
  fs.unlinkSync(f);
}

// ── 7) 缓存不能掩盖新增篡改 ─────────────────────────────────
{
  const f = tmp();
  const l = new AuditLog({ logPath: f });
  for (let i = 0; i < 5; i++) l.append({ event_type: 'request', caller_id: 'a', result: 'success' });
  t('首次验绿', l.verifyChain().valid === true);
  const rows = readRows(f);
  rows[1].caller_id = 'mallory';
  writeRows(f, rows);
  const v = l.verifyChain();          // 同一实例再验（缓存键含 mtime/size，不应命中旧结果）
  t('缓存不掩盖篡改', v.valid === false, JSON.stringify(v));
  fs.unlinkSync(f);
}

// ── 8) 空账本 ───────────────────────────────────────────────
{
  const f = tmp();
  fs.writeFileSync(f, '');
  const v = new AuditLog({ logPath: f }).verifyChain();
  t('空账本报绿', v.valid === true && v.count === 0, JSON.stringify(v));
  fs.unlinkSync(f);
}

// ── 输出 ────────────────────────────────────────────────────
console.log(`审计验链自测：${pass}/${pass + fails.length} 通过`);
if (fails.length) {
  for (const f of fails) console.log(`  🚨 ${f}`);
  process.exit(1);
}
console.log('  ✅ 覆盖：正常 · 篡改 · 删行 · 超容量不假红 · 超容量后篡改 · 坏行 · 缓存 · 空账本');