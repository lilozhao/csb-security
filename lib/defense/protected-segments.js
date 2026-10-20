/**
 * protected-segments.js — 组件只读清单（宪章第十四条 14.1 / 14.2 的代码实现）
 *
 * 定位：**只读判断层**——只回答「这个文件/这一行属不属于只读区段」，
 *       不写盘、不改任何现有护栏。写操作由调用方自己负责。
 *
 * 设计依据：
 *   - 宪章 v1.3 §14.1 保护对象 = 声明段落 + 指纹（不是整份文件）
 *   - §14.2 分类凭据：清单本身按 C2 只读（改清单 = 改分类 = 走第九条）
 *   - §14.1 补充：区段边界元数据本身归 C1 只读
 *
 * 清单格式（config/protected-segments.json）：
 * {
 *   "version": "1.0",
 *   "updated": "2026-10-21",
 *   "segments": [
 *     { "path": "SOUL.md", "class": "C1",
 *       "start": "^## Core Truths", "end": "^## Boundaries",
 *       "reason": "身份与价值观" }
 *   ]
 * }
 *
 * 区段边界：start/end 为正则（行级匹配）。end 不含；缺 end = 到文件末尾。
 * 无 start 的条目 = 整文件保护（兼容旧做法，但**不推荐**——整文件锁是 v1 的错误）。
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-10-21
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CLASSES = ['C1', 'C2'];
const DEFAULT_MANIFEST = path.join(__dirname, '..', '..', 'config', 'protected-segments.json');

class ProtectedSegmentsError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'ProtectedSegmentsError';
    this.code = code;
    this.details = details;
  }
}

/**
 * 解析并校验清单。任何结构问题 → 抛错（不静默跳过坏条目）
 * @param {Object} manifest
 * @returns {{version: string, segments: Array}}
 */
function validateManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') {
    throw new ProtectedSegmentsError('BAD_MANIFEST', '清单必须是对象');
  }
  if (!Array.isArray(manifest.segments)) {
    throw new ProtectedSegmentsError('BAD_MANIFEST', '清单缺 segments 数组');
  }

  const seen = new Set();
  manifest.segments.forEach((s, i) => {
    const at = `segments[${i}]`;
    if (!s || typeof s !== 'object') { errors.push(`${at}: 必须是对象`); return; }
    if (!s.path || typeof s.path !== 'string') errors.push(`${at}: 缺 path`);
    if (!CLASSES.includes(s.class)) {
      errors.push(`${at}: class 只接受 ${CLASSES.join(' | ')}（收到 ${s.class}）`);
    }
    // 正则必须可编译——宪章 14.1 要求「可机械核对」
    for (const k of ['start', 'end']) {
      if (s[k] === undefined || s[k] === null) continue;
      try { new RegExp(s[k]); }
      catch (e) { errors.push(`${at}: ${k} 正则不可编译（${e.message}）`); }
    }
    // 同文件同类同级段不得重复（防清单自我纠缠）
    const key = `${s.path}|${s.class}|${s.start || ''}|${s.end || ''}`;
    if (seen.has(key)) errors.push(`${at}: 重复条目 ${key}`);
    seen.add(key);
  });

  if (errors.length) {
    throw new ProtectedSegmentsError('BAD_MANIFEST', `清单有 ${errors.length} 处问题`, { errors });
  }
  return { version: manifest.version || 'unknown', segments: manifest.segments };
}

/**
 * 从磁盘加载清单。文件不存在 → 抛错（不返回空清单冒充「没有保护」）
 * @param {string} [file]
 */
function load(file = DEFAULT_MANIFEST) {
  if (!fs.existsSync(file)) {
    throw new ProtectedSegmentsError('MANIFEST_MISSING',
      `清单不存在: ${file}（不得以「没有清单」为由认为无保护区段）`);
  }
  let raw;
  try { raw = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) {
    throw new ProtectedSegmentsError('BAD_MANIFEST', `清单不是合法 JSON: ${e.message}`);
  }
  return { ...validateManifest(raw), file };
}

/**
 * 判断某文件的某一行号是否落在只读区段内（纯函数）
 *
 * @param {Array} segments 已校验的 segments
 * @param {string} filePath 目标文件（相对路径，与清单 path 比较）
 * @param {string[]} lines 目标文件按行切分的内容
 * @param {number} lineNo 1-based 行号
 * @returns {{protected: boolean, class?: string, segment?: Object, reason?: string}}
 */
function isLineProtected(segments, filePath, lines, lineNo) {
  const norm = String(filePath).replace(/\\/g, '/');
  for (const s of segments) {
    if (String(s.path).replace(/\\/g, '/') !== norm) continue;

    // 无 start → 整文件保护
    if (!s.start) {
      return { protected: true, class: s.class, segment: s, reason: s.reason || '整文件保护' };
    }

    const startRe = new RegExp(s.start);
    const endRe = s.end ? new RegExp(s.end) : null;

    // 找到行号之前最后一个 start
    let startAt = -1;
    for (let i = lineNo - 1; i >= 0; i--) {
      if (startRe.test(lines[i])) { startAt = i; break; }
    }
    if (startAt === -1) continue;

    // 从 start 之后找第一个 end（严格在 lineNo-1 之后）
    if (endRe) {
      let endAt = Infinity;
      for (let i = startAt + 1; i < lines.length; i++) {
        if (endRe.test(lines[i])) { endAt = i; break; }
      }
      // 行号必须落在 [startAt, endAt)
      if (lineNo - 1 >= startAt && lineNo - 1 < endAt) {
        return { protected: true, class: s.class, segment: s, reason: s.reason || '区段保护' };
      }
    } else if (lineNo - 1 >= startAt) {
      return { protected: true, class: s.class, segment: s, reason: s.reason || '区段至文件尾' };
    }
  }
  return { protected: false };
}

/**
 * 对一份 diff 做判定：哪些行落在只读区段内
 *
 * diff 格式（最小可用，供自我修改审计调用）：
 *   [{ path: 'SOUL.md', startLine: 12, lines: ['...', '...'] }]
 * 语义：从 startLine 起连续 lines.length 行被改动。
 *
 * @returns {{blocked: boolean, hits: Array}}
 */
function checkDiff(segments, fileContents, diff) {
  const hits = [];
  for (const hunk of diff) {
    const lines = fileContents[hunk.path];
    if (!lines) {
      // 拿不到原文 = 无法证明安全 → 保守按「不可判定」，由调用方决定
      hits.push({ path: hunk.path, line: hunk.startLine, class: 'UNKNOWN',
        reason: 'NO_BASELINE', message: '基线内容取不到，无法判定是否触碰只读区段' });
      continue;
    }
    for (let i = 0; i < hunk.lines.length; i++) {
      const lineNo = hunk.startLine + i;
      const r = isLineProtected(segments, hunk.path, lines, lineNo);
      if (r.protected) {
        hits.push({ path: hunk.path, line: lineNo, class: r.class, reason: r.segment.reason || '' });
      }
    }
  }
  return { blocked: hits.some(h => CLASSES.includes(h.class) || h.class === 'UNKNOWN'), hits };
}

/**
 * 计算只读区段指纹（宪章 14.2：指纹范围 = C1/C2 声明段全文）
 *
 * 关键设计：**只算声明段，不算整文件**——否则改一行心跳 cron 就会触发只读告警，
 * 那正是明德说的「第一天就人人违规」。
 *
 * @param {Array} segments
 * @param {Object} fileContents { path: string[] }（按行切分）
 * @returns {{hash: string, perSegment: Array<{path, class, lines, hash}>}}
 */
function fingerprint(segments, fileContents) {
  const perSegment = [];
  for (const s of segments) {
    const lines = fileContents[s.path];
    if (!lines) {
      perSegment.push({ path: s.path, class: s.class, lines: 0, hash: null, missing: true });
      continue;
    }
    let picked;
    if (!s.start) {
      picked = lines;
    } else {
      const startRe = new RegExp(s.start);
      const endRe = s.end ? new RegExp(s.end) : null;
      let startAt = lines.findIndex(l => startRe.test(l));
      if (startAt === -1) {
        perSegment.push({ path: s.path, class: s.class, lines: 0, hash: null, missing: true });
        continue;
      }
      let endAt = lines.length;
      if (endRe) {
        for (let i = startAt + 1; i < lines.length; i++) {
          if (endRe.test(lines[i])) { endAt = i; break; }
        }
      }
      picked = lines.slice(startAt, endAt);
    }
    const body = picked.join('\n');
    perSegment.push({
      path: s.path,
      class: s.class,
      lines: picked.length,
      hash: crypto.createHash('sha256').update(body, 'utf8').digest('hex'),
    });
  }

  // 总指纹：按清单顺序拼，保证确定性
  const total = crypto.createHash('sha256')
    .update(JSON.stringify(perSegment.map(p => [p.path, p.class, p.hash])))
    .digest('hex');

  return { hash: total, perSegment };
}

/** 把文件内容读成「按行切分」的 map（供 checkDiff / fingerprint 使用） */
function loadContents(baseDir, paths) {
  const out = {};
  for (const p of paths) {
    const abs = path.join(baseDir, p);
    if (!fs.existsSync(abs)) { out[p] = null; continue; }
    out[p] = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
  }
  return out;
}

module.exports = {
  CLASSES,
  ProtectedSegmentsError,
  validateManifest,
  load,
  isLineProtected,
  checkDiff,
  fingerprint,
  loadContents,
  DEFAULT_MANIFEST,
};
