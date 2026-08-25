#!/usr/bin/env node
/**
 * test-tamper-check.js — 审计完整性校验测试（Layer 5, P2 补齐）
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { AuditLog } = require('../lib/audit/audit-log');
const { verifyEntries, checkAuditFile, report, canonicalContent } = require('../lib/audit/tamper-check');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (e) {
    failed++;
    console.log(`  ❌ ${name}: ${e.message}`);
  }
}

console.log('=== 审计完整性校验测试 ===\n');

function makeLog({ count = 5, sign = false } = {}) {
  const { privateKey, publicKey } = sign
    ? (() => { const k = crypto.generateKeyPairSync('ed25519'); return { privateKey: k.privateKey, publicKey: k.publicKey }; })()
    : {};
  const log = new AuditLog({ privateKey, publicKey });
  for (let i = 0; i < count; i++) {
    log.append({ event_type: 'test', caller_id: 'caller', callee_id: 'callee', result: 'ok', seq_hint: i });
  }
  return { log, publicKey };
}

// ---------- verifyEntries ----------
test('完整链校验通过', () => {
  const { log } = makeLog({ count: 5 });
  const r = verifyEntries(log.entries);
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.count, 5);
});

test('篡改单条记录 → entry_tampered', () => {
  const { log } = makeLog({ count: 5 });
  log.entries[2] = { ...log.entries[2], result: 'evil' };
  const r = verifyEntries(log.entries);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'entry_tampered');
  assert.strictEqual(r.brokenAt, 2);
});

test('断链（改 prev_hash）→ hash_chain_broken', () => {
  const { log } = makeLog({ count: 5 });
  log.entries[3].prev_hash = 'deadbeef';
  const r = verifyEntries(log.entries);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'hash_chain_broken');
});

test('删除中间一条 → 断链检出', () => {
  const { log } = makeLog({ count: 5 });
  const entries = [...log.entries.slice(0, 2), ...log.entries.slice(3)];
  const r = verifyEntries(entries);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'hash_chain_broken');
});

test('空数组 → valid（0 条）', () => {
  const r = verifyEntries([]);
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.count, 0);
});

test('非数组 → not_array', () => {
  const r = verifyEntries('nope');
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'not_array');
});

test('签名链校验：伪签必检出', () => {
  const { log, publicKey } = makeLog({ count: 5, sign: true });
  // 用另一个密钥伪造一条签名
  const evil = crypto.generateKeyPairSync('ed25519');
  const content = canonicalContent(log.entries[1]);
  log.entries[1].signature = crypto.sign(null, Buffer.from(content), evil.privateKey).toString('base64');
  const r = verifyEntries(log.entries, { publicKey });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'bad_signature');
});

test('签名链校验：正确签名通过', () => {
  const { log, publicKey } = makeLog({ count: 5, sign: true });
  const r = verifyEntries(log.entries, { publicKey });
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.checkedSignatures, 5);
});

// ---------- checkAuditFile ----------
test('文件校验：正常文件通过', () => {
  const { log } = makeLog({ count: 3 });
  const tmp = path.join(os.tmpdir(), `audit-test-${Date.now()}.json`);
  fs.writeFileSync(tmp, JSON.stringify(log.entries));
  const r = checkAuditFile(tmp);
  assert.strictEqual(r.valid, true);
  fs.unlinkSync(tmp);
});

test('文件校验：篡改文件检出', () => {
  const { log } = makeLog({ count: 3 });
  const tmp = path.join(os.tmpdir(), `audit-test-${Date.now()}.json`);
  const entries = JSON.parse(JSON.stringify(log.entries));
  entries[1].result = 'hacked';
  fs.writeFileSync(tmp, JSON.stringify(entries));
  const r = checkAuditFile(tmp);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'entry_tampered');
  fs.unlinkSync(tmp);
});

test('文件不存在 → file_not_found', () => {
  const r = checkAuditFile('/nonexistent/audit.json');
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'file_not_found');
});

// ---------- report ----------
test('report 输出人类可读报告', () => {
  const { log } = makeLog({ count: 3 });
  const text = report(log.entries);
  assert.ok(text.includes('审计完整性校验报告'));
  assert.ok(text.includes('校验通过'));
});

test('report 失败时标注断裂位置', () => {
  const { log } = makeLog({ count: 3 });
  log.entries[1].hash = 'bad';
  const text = report(log.entries);
  assert.ok(text.includes('校验失败'));
  assert.ok(text.includes('断裂位置'));
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
