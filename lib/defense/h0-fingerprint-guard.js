/**
 * h0-fingerprint-guard.js — 红线 2 的代码实现（Harness² 对照 v2 §4 红线 2）
 *
 * 红线原文：
 *   「H0 重启只作用于 C4–C8——语义是"重来一次做事方式"，不是"重新变成谁"。
 *     判据：H0 前后 C1/C2 指纹必须一致，否则拒启。」
 *
 * 定位：**启动闸**。H0 流程调用顺序：
 *   1. H0 前：`takeSnapshot()` → `writeSnapshot(file)`（留基线）
 *   2. H0 执行（只许动 C4–C8：技能/脚本/插件/编排）
 *   3. H0 后、重启前：`guardStartup(baseDir, file)`
 *      - 一致 → 放行启动
 *      - 不一致 → **拒绝启动**（exit 1）+ 结构化 deny 事件（P1：拒绝要计分，不许静默丢弃）
 *
 * 指纹计算复用 protected-segments.js 的 `fingerprint()`——
 * 同一份组件只读清单（config/protected-segments.json），同一套区段边界，
 * 保证「只读判断层」与「启动闸」看到的是同一个 C1/C2。
 *
 * 设计依据：
 *   - 宪章 v1.3 §14.8 事实红线 / Harness² 对照 v2 §4 红线 2
 *   - P1 原则（明澈）：拒绝 = 一等事件源，deny 必须带 code + 证据，不许静默
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-10-21
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const seg = require('./protected-segments');

const DENY_CODE = 'H0_IDENTITY_DRIFT';

/**
 * 对清单内全部 C1/C2 区段拍快照
 * @param {string} baseDir 文件根目录（如工作区）
 * @param {object} [opts] { manifestPath? } 自定义清单路径
 * @returns {{ version, takenAt, hash, perSegment }}
 */
function takeSnapshot(baseDir, opts = {}) {
  const manifest = opts.manifestPath
    ? seg.load(opts.manifestPath)
    : seg.load();
  const segments = manifest.segments;
  const paths = [...new Set(segments.map(s => s.path))];
  const contents = seg.loadContents(baseDir, paths);
  const fp = seg.fingerprint(segments, contents);
  return {
    version: manifest.version || null,
    takenAt: new Date().toISOString(),
    hash: fp.hash,
    perSegment: fp.perSegment,
  };
}

function writeSnapshot(file, snapshot) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(snapshot, null, 2) + '\n', 'utf8');
}

function readSnapshot(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * 对比两份快照——逐段比对 + 总指纹比对
 * @returns {{ ok: boolean, changed: Array<{path, class, before, after, reason}> }}
 */
function verify(before, after) {
  const changed = [];
  const key = p => `${p.path}::${p.class}`;
  const beforeMap = new Map(before.perSegment.map(p => [key(p), p]));
  for (const a of after.perSegment) {
    const b = beforeMap.get(key(a));
    if (!b) { changed.push({ ...pick(a), before: null, after: a.hash, reason: 'NEW_SEGMENT' }); continue; }
    beforeMap.delete(key(a));
    if (b.hash !== a.hash) {
      const reason = (a.hash === null || b.hash === null) ? 'FILE_MISSING' : 'CONTENT_CHANGED';
      changed.push({ ...pick(a), before: b.hash, after: a.hash, reason });
    }
  }
  // before 有、after 没有的段 = 清单被改过（区段边界元数据归 C1 只读）
  for (const b of beforeMap.values()) {
    changed.push({ ...pick(b), before: b.hash, after: null, reason: 'SEGMENT_REMOVED' });
  }
  return { ok: changed.length === 0, changed };
}

function pick(p) { return { path: p.path, class: p.class, before: null, after: null, ...p }; }

/**
 * 启动闸：H0 后调用。不一致 → deny（结构化事件 + throw）
 * @param {string} baseDir
 * @param {string} snapshotFile H0 前落盘的快照
 * @param {object} [opts] { throwOnDeny=true } 测试用 false 拿结构化结果
 * @returns {{ ok: true, checkedAt } | { ok: false, deny: {code, changed, snapshotTakenAt} }}
 */
function guardStartup(baseDir, snapshotFile, opts = {}) {
  const throwOnDeny = opts.throwOnDeny !== false;
  const before = readSnapshot(snapshotFile);
  const after = takeSnapshot(baseDir, opts);
  const v = verify(before, after);
  if (v.ok) {
    return { ok: true, checkedAt: new Date().toISOString() };
  }
  const deny = {
    code: DENY_CODE,
    message: 'H0 前后 C1/C2 指纹不一致——重启只许动 C4–C8，身份与安全层被改动，拒绝启动',
    snapshotTakenAt: before.takenAt,
    beforeHash: before.hash,
    afterHash: after.hash,
    changed: v.changed,
  };
  // P1：拒绝要计分——大声说出来，供上层落账
  console.error(`[h0-guard] DENY ${DENY_CODE}: ${deny.changed.length} segment(s) drifted`);
  for (const c of deny.changed) {
    console.error(`  · [${c.class}] ${c.path} (${c.reason})`);
  }
  if (throwOnDeny) {
    const err = new Error(deny.message);
    err.code = DENY_CODE;
    err.deny = deny;
    throw err;
  }
  return { ok: false, deny };
}

// CLI：node lib/defense/h0-fingerprint-guard.js snapshot|verify --base <dir> [--out/--snapshot <file>] [--manifest <file>]
function main(argv) {
  const [cmd, ...rest] = argv;
  const arg = (name, dflt) => {
    const i = rest.indexOf(name);
    return i === -1 ? dflt : rest[i + 1];
  };
  const base = path.resolve(arg('--base', process.cwd()));
  const manifestPath = arg('--manifest');
  const opts = manifestPath ? { manifestPath: path.resolve(manifestPath) } : {};

  if (cmd === 'snapshot') {
    const out = path.resolve(arg('--out', 'h0-baseline.json'));
    const snap = takeSnapshot(base, opts);
    writeSnapshot(out, snap);
    console.log(`[h0-guard] baseline → ${out} (hash=${snap.hash.slice(0, 12)}…, ${snap.perSegment.length} segments)`);
    return 0;
  }
  if (cmd === 'verify') {
    const file = path.resolve(arg('--snapshot', 'h0-baseline.json'));
    try {
      guardStartup(base, file, opts);
      console.log('[h0-guard] PASS — C1/C2 指纹一致，允许启动');
      return 0;
    } catch (e) {
      return 1; // deny 已在 guardStartup 里大声打印
    }
  }
  console.error('usage: h0-fingerprint-guard.js snapshot|verify --base <dir> [--out|--snapshot <file>] [--manifest <file>]');
  return 2;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = { takeSnapshot, writeSnapshot, readSnapshot, verify, guardStartup, DENY_CODE };
