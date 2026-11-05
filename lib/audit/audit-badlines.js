#!/usr/bin/env node
/**
 * audit-badlines.js —— 定位审计账本里「无法解析的行」
 *
 * 为什么需要它：
 *   验链时坏行会被跳过并计数（badLines），但那只是*计数*。
 *   知道「有 1 行坏了」和知道「坏在哪一行、什么时候、坏成什么样」是两件事——
 *   前者只能让人不安，后者才能判断要不要修、怎么修。
 *
 * 它回答四个问题（全部机械可核）：
 *   ① 第几行（文件行号）+ 前后最近的合法条目的 seq/timestamp
 *   ② 坏成什么样（原始字节，截断展示；附长度与首末字符）
 *   ③ 可能发生时间（用前后合法行的时间夹逼）
 *   ④ 是不是写入被截断（尾行无换行 = 典型的进程中断）
 *
 * 用法:
 *   node lib/audit/audit-badlines.js <账本路径>
 *   node lib/audit/audit-badlines.js <账本路径> --json
 *   node lib/audit/audit-badlines.js <账本路径> --line 8821   # 只看某一行
 *
 * 只读，不修改文件。
 * 维护: 若兰 🌸 | 2026-11-05
 */
'use strict';

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const out = { file: null, json: false, line: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--line') out.line = Number(argv[++i]);
    else if (a.startsWith('--line=')) out.line = Number(a.split('=')[1]);
    else if (!a.startsWith('-')) out.file = a;
  }
  return out;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.file) {
    console.error('用法: node lib/audit/audit-badlines.js <账本路径> [--json] [--line N]');
    process.exit(1);
  }
  const file = path.resolve(opts.file);
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) {
    console.error(`读不到 ${file}: ${e.message}`);
    process.exit(1);
  }

  const endsWithNewline = raw.endsWith('\n');
  const allLines = raw.split('\n');
  // 末尾无换行时 split 会多出一个空串，那是「最后一行没写完」的信号，单独处理
  const trailingEmpty = allLines.length && allLines[allLines.length - 1] === '';
  const lines = trailingEmpty ? allLines.slice(0, -1) : allLines;

  const bad = [];
  let prevGood = null;
  let goodCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) {
      bad.push({ lineNo: i + 1, kind: 'blank', raw: line, prevGood, nextGood: null });
      continue;
    }
    let obj = null;
    try { obj = JSON.parse(line); } catch { /* 坏行 */ }
    if (obj) {
      goodCount++;
      prevGood = { seq: obj.seq ?? null, timestamp: obj.timestamp ?? null, lineNo: i + 1 };
      continue;
    }
    bad.push({ lineNo: i + 1, kind: 'unparsable', raw: line, prevGood, nextGood: null });
  }

  // 回填每处坏行的「后一条合法行」
  for (const b of bad) {
    for (let j = b.lineNo; j < lines.length; j++) {
      try {
        const o = JSON.parse(lines[j]);
        b.nextGood = { seq: o.seq ?? null, timestamp: o.timestamp ?? null, lineNo: j + 1 };
        break;
      } catch { /* 继续找 */ }
    }
  }

  // 判断尾行是否被截断
  const lastBad = bad[bad.length - 1];
  if (lastBad && lastBad.lineNo === lines.length && !endsWithNewline) {
    lastBad.kind = 'truncated_at_eof';
  }

  if (opts.line) {
    const one = bad.find((b) => b.lineNo === opts.line);
    if (!one) { console.log(`第 ${opts.line} 行解析正常，不是坏行`); process.exit(0); }
    print([one], file, goodCount, lines.length, opts.json);
    process.exit(0);
  }

  print(bad, file, goodCount, lines.length, opts.json);
  process.exit(bad.length ? 0 : 0); // 只诊断，不改退出码语义（发现坏行不等于失败）
}

function preview(s, n = 160) {
  const t = String(s);
  if (t.length <= n) return t;
  return t.slice(0, n) + `…（共 ${t.length} 字符）`;
}

function print(bad, file, goodCount, totalLines, json) {
  if (json) {
    console.log(JSON.stringify({
      file,
      totalLines,
      goodLines: goodCount,
      badLines: bad.length,
      findings: bad.map((b) => ({
        lineNo: b.lineNo,
        kind: b.kind,
        length: b.raw.length,
        preview: preview(b.raw, 400),
        prevGood: b.prevGood,
        nextGood: b.nextGood,
      })),
    }, null, 2));
    return;
  }

  console.log(`账本：${file}`);
  console.log(`总行数 ${totalLines} · 合法 ${goodCount} · 坏行 ${bad.length}`);
  if (!bad.length) { console.log('✅ 没有坏行'); return; }

  console.log('');
  for (const b of bad) {
    console.log(`── 第 ${b.lineNo} 行 ─ ${kindLabel(b.kind)}`);
    console.log(`   长度 ${b.raw.length} 字符`);
    console.log(`   内容 ${JSON.stringify(preview(b.raw))}`);
    const p = b.prevGood, n = b.nextGood;
    if (p) console.log(`   前一条合法: seq=${p.seq} ts=${p.timestamp}（第 ${p.lineNo} 行）`);
    else console.log('   前一条合法: 无（这是文件开头的坏行）');
    if (n) console.log(`   后一条合法: seq=${n.seq} ts=${n.timestamp}（第 ${n.lineNo} 行）`);
    else console.log('   后一条合法: 无（坏行在文件末尾）');

    // 时间夹逼：给出可能的写入时间窗口
    if (p && n) {
      console.log(`   可能写入时间: ${p.timestamp} ~ ${n.timestamp} 之间`);
    } else if (p) {
      console.log(`   可能写入时间: ${p.timestamp} 之后（无后续，无法收窄）`);
    }
    if (b.kind === 'truncated_at_eof') {
      console.log('   ⚠️ 位置在文件末尾且无换行 → 典型的「写入过程中进程被杀/容器重启」，不是伪造');
    }
    if (b.kind === 'blank') {
      console.log('   ⚠️ 空行（非 JSON）→ 多半是并发追加时插入的空写入，可忽略但应清理');
    }
    console.log('');
  }

  console.log('提示：坏行不会被静默吞掉——验链时计入 badLines。');
  console.log('     若确认是写入中断产生的孤儿行，可另存归档后从账本移除；不要直接删了事（那是销毁证据）。');
}

function kindLabel(k) {
  return {
    unparsable: '无法解析为 JSON',
    blank: '空行',
    truncated_at_eof: '末尾被截断（无换行）',
  }[k] || k;
}

main();