/**
 * CSB-Security Layer 5: 审计完整性校验（协议 §6.2 不可篡改存储）
 *
 * 独立于 AuditLog 实例的静态校验工具，支持:
 *  - 离线检测：对审计文件（或内存 entries）做哈希链 + 签名全量校验
 *  - 篡改必检出：改任意一条记录 → entry_tampered；断链 → hash_chain_broken
 *  - 伪签必检出：签名不匹配 → bad_signature
 *  - 生成人类可读的校验报告
 *
 * 与 audit-log.js 的关系：AuditLog.verifyChain() 是实例方法（校验自身内存链），
 * tamper-check 是独立工具（可对落盘文件/外部数据校验），二者算法一致。
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-25 (P2 补齐)
 */

const crypto = require('crypto');
const fs = require('fs');

const GENESIS_HASH = 'GENESIS';

/** 与 audit-log.js 保持一致的规范化序列化（去 hash/signature 后 JSON.stringify） */
function canonicalContent(record) {
  const { hash, signature, ...rest } = record;
  return JSON.stringify(rest);
}

/**
 * 校验一组审计 entries（哈希链 + 每条 hash + 可选签名）
 * @param {Array<Object>} entries 审计记录（按 seq 升序）
 * @param {Object} [opts]
 *   - publicKey: Ed25519 公钥（KeyObject/JWK/PEM，可选；配置后验签）
 * @returns {{ valid: boolean, count?: number, brokenAt?: number, reason?: string, checkedSignatures?: number }}
 */
function verifyEntries(entries, opts = {}) {
  const { publicKey = null } = opts;
  if (!Array.isArray(entries)) return { valid: false, reason: 'not_array' };

  let prevHash = GENESIS_HASH;
  let checkedSignatures = 0;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];

    // 1. 哈希链连续性
    if (e.prev_hash !== prevHash) {
      return { valid: false, brokenAt: i, reason: 'hash_chain_broken' };
    }

    // 2. 本条 hash 与内容一致
    const content = canonicalContent(e);
    const computed = crypto.createHash('sha256').update(content).digest('hex');
    if (computed !== e.hash) {
      return { valid: false, brokenAt: i, reason: 'entry_tampered' };
    }

    // 3. 可选：Ed25519 签名验证
    if (publicKey && e.signature) {
      // KeyObject 直接透传（crypto.verify 原生支持）；JWK/PEM 则构造公钥
      const pub = publicKey instanceof crypto.KeyObject
        ? publicKey
        : (publicKey.kty
            ? crypto.createPublicKey({ key: publicKey, format: 'jwk' })
            : crypto.createPublicKey(publicKey));
      const ok = crypto.verify(null, Buffer.from(content), pub, Buffer.from(e.signature, 'base64'));
      if (!ok) {
        return { valid: false, brokenAt: i, reason: 'bad_signature' };
      }
      checkedSignatures++;
    }

    prevHash = e.hash;
  }

  return { valid: true, count: entries.length, checkedSignatures };
}

/**
 * 对落盘审计文件做完整性校验
 * @param {string} logPath 审计文件路径（JSON 数组或每行一条 JSON）
 * @param {Object} [opts] 同 verifyEntries
 * @returns {{ valid: boolean, count?: number, brokenAt?: number, reason?: string, file?: string }}
 */
function checkAuditFile(logPath, opts = {}) {
  if (!fs.existsSync(logPath)) {
    return { valid: false, reason: 'file_not_found', file: logPath };
  }
  let raw;
  try {
    raw = fs.readFileSync(logPath, 'utf8');
  } catch (e) {
    return { valid: false, reason: 'read_failed', file: logPath, error: e.message };
  }

  let entries;
  try {
    const trimmed = raw.trim();
    if (trimmed.startsWith('[')) {
      entries = JSON.parse(raw);
    } else {
      // 每行一条 JSON（NDJSON）
      entries = raw.split('\n').filter(Boolean).map((line) => JSON.parse(line));
    }
  } catch (e) {
    return { valid: false, reason: 'parse_failed', file: logPath, error: e.message };
  }

  const result = verifyEntries(entries, opts);
  return { ...result, file: logPath };
}

/**
 * 生成人类可读的校验报告
 * @param {Array<Object>} entries 审计记录
 * @param {Object} [opts] 同 verifyEntries
 * @returns {string} 报告文本
 */
function report(entries, opts = {}) {
  const result = verifyEntries(entries, opts);
  const lines = [];
  lines.push('══════════════════════════════════════');
  lines.push('🛡️  CSB-Security 审计完整性校验报告');
  lines.push('══════════════════════════════════════');
  if (result.valid) {
    lines.push(`✅ 校验通过: ${result.count} 条记录，哈希链完整`);
    if (result.checkedSignatures > 0) {
      lines.push(`🔏 签名验证: ${result.checkedSignatures}/${result.count} 条已验签`);
    } else {
      lines.push('ℹ️  未配置公钥，跳过签名验证（仅哈希链）');
    }
  } else {
    lines.push(`❌ 校验失败: ${result.reason}`);
    if (result.brokenAt !== undefined) {
      lines.push(`   断裂位置: 第 ${result.brokenAt} 条 (seq=${entries[result.brokenAt]?.seq ?? '?'})`);
    }
    if (result.error) lines.push(`   错误: ${result.error}`);
  }
  lines.push('══════════════════════════════════════');
  return lines.join('\n');
}

module.exports = {
  GENESIS_HASH,
  canonicalContent,
  verifyEntries,
  checkAuditFile,
  report,
};
