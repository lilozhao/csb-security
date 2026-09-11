#!/usr/bin/env node
/**
 * trust-attest.js — 信任升级 · 追溯认定 CLI（P0）
 *
 * 信任升级设计 §五：存量关系（已协作很久的 Agent）不必从零攒 10 次正向交互，
 * 可凭**可核验证据引用** + **宿主用户签字** 一次性认定到 L2。
 * **L3 永不追溯认定** —— 必须人当下点头（本脚本会硬拒）。
 *
 * 用法:
 *   # 查询某主体当前派生等级
 *   node scripts/trust-attest.js status --agent 阿轩
 *   # 列出全部
 *   node scripts/trust-attest.js status
 *   # 校验账本哈希链（篡改必检出）
 *   node scripts/trust-attest.js verify
 *   # 追溯认定（默认 dry-run，加 --commit 才写入账本）
 *   node scripts/trust-attest.js attest --agent 阿轩 --aid aid:ed25519:xxx \
 *     --to L2 --evidence task_1789119844400_1e1a273d,task_1789128276982_3347381c \
 *     --operator 赵宏伟 --reason "长期协作证据认定（200+ 天）" --commit
 *
 * 维护者: 若兰 🌸 | 2026-09-11 (P0)
 */

'use strict';

const path = require('path');
const { TrustStore } = require('../lib/trust/trust-store');
const { DEFAULTS } = require('../lib/trust/trust-store');

const ROOT = path.join(__dirname, '..');
const LEDGER = path.join(ROOT, 'data', 'trust-evidence.jsonl');
const SNAPSHOT = path.join(ROOT, 'data', 'trust-store.json');

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) out[key] = true;
      else { out[key] = next; i++; }
    } else out._.push(a);
  }
  return out;
}

function openStore(args = {}) {
  return new TrustStore({
    ledgerPath: args.ledger || LEDGER,
    snapshotPath: args.snapshot || SNAPSHOT,
  });
}

function fmt(rec) {
  const flag = [];
  if (rec.outstandingSevere) flag.push('⛔严重负向未清偿');
  else if (rec.outstandingNegCount > 0) flag.push('⚠️负向未清偿');
  if (rec.attested) flag.push('📌追溯认定');
  if (rec.requiresReauth) flag.push('⏳待复验');
  if (rec.authValid) flag.push('🔑授权有效');
  return `${rec.level}  正向权重=${rec.positiveWeight}  负向=${rec.negativeCount}  分=${rec.score}` +
    (flag.length ? '  [' + flag.join(' ') + ']' : '');
}

function cmdStatus(args) {
  const store = openStore(args);
  const v = store.verify();
  if (!v.ok) {
    console.error(`❌ 账本校验失败：${v.reason}${v.atSeq ? ` (seq ${v.atSeq})` : ''}`);
    process.exit(2);
  }
  if (args.agent) {
    const rec = store.getLevel(args.agent);
    console.log(`${args.agent}: ${fmt(rec)}`);
    console.log(`  证据条目 ${rec.evidenceSeqs.length} 条 | 最近正向 ${rec.lastPositiveTs ? new Date(rec.lastPositiveTs).toISOString() : '（无）'}`);
    return;
  }
  const all = store.replay();
  if (!all.length) return console.log('（账本为空：还没有任何主体产生信任证据）');
  for (const rec of all.sort((a, b) => b.positiveWeight - a.positiveWeight)) {
    console.log(`${String(rec.agentId).padEnd(10)} ${fmt(rec)}`);
  }
}

function cmdVerify(args) {
  const store = openStore(args);
  const v = store.verify();
  console.log(v.ok
    ? `✅ 账本哈希链完好（${v.verified} 条，head=${store.ledger.headHash.slice(0, 12)}…）`
    : `❌ 账本被篡改/损坏：${v.reason}${v.atSeq ? ` (seq ${v.atSeq})` : ''}`);
  const fresh = store.snapshotFresh();
  console.log(fresh ? '✅ 快照与账本一致' : '⚠️ 快照与账本不一致（下次写快照会自动重建）');
  process.exit(v.ok ? 0 : 2);
}

function cmdAttest(args) {
  const agent = args.agent;
  const to = String(args.to || 'L2').toUpperCase();
  const refs = String(args.evidence || '').split(',').map((s) => s.trim()).filter(Boolean);
  const operator = args.operator;

  if (!agent) { console.error('❌ 缺少 --agent'); process.exit(1); }
  if (to === 'L3') {
    console.error('❌ 追溯认定上限为 L2：L3 必须由宿主用户在当下实时授权（设计 §五硬主张）。');
    process.exit(1);
  }
  if (to !== 'L2') { console.error('❌ 目前仅支持 --to L2'); process.exit(1); }
  if (!refs.length) { console.error('❌ 必须提供 --evidence（可核验证据引用，逗号分隔）'); process.exit(1); }
  if (!operator) { console.error('❌ 必须提供 --operator（宿主用户签字，不可由被认定方自签）'); process.exit(1); }

  const store = openStore(args);
  const before = store.getLevel(agent);
  const plan = {
    agent, aid: args.aid || null, url: args.url || null, to,
    evidenceRefs: refs, operator, reason: args.reason || null,
  };
  console.log('📋 认定计划：');
  console.log(JSON.stringify(plan, null, 2));
  console.log(`认定前：${fmt(before)}`);

  if (!args.commit) {
    console.log('（dry-run：未写入账本；加 --commit 执行）');
    return;
  }

  store.ledger.append({
    subject: { name: agent, aid: args.aid || null, url: args.url || null },
    action: 'retroactive_attestation',
    evidence: { refs, detail: '追溯认定（存量关系）', operator, reason: args.reason || null },
    actor: operator,
    note: `retroactive_attestation → ${to}（operator=${operator}）`,
  });
  store.saveSnapshot();
  const after = store.getLevel(agent);
  console.log(`✅ 已写入账本 | 认定后：${fmt(after)}`);
  if (after.level !== to) {
    console.log(`ℹ️ 派生等级为 ${after.level}（非 ${to}）：可能是存在未清偿负向，或被更高/更低层级条件约束。`);
  }
  console.log(`   证据 seq：${after.evidenceSeqs.join(', ')}`);
}

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0] || 'status';
if (cmd === 'status') cmdStatus(args);
else if (cmd === 'verify') cmdVerify(args);
else if (cmd === 'attest') cmdAttest(args);
else {
  console.error(`未知命令: ${cmd}\n用法: trust-attest.js [status|verify|attest] [--agent X] ...`);
  process.exit(1);
}
