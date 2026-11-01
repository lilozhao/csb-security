#!/usr/bin/env node
/**
 * P0-0b 验收：信任账本规范化盲区修复
 *
 * 判据：
 *   1. v2 条目：改 subject.name → 必报篡改（旧口径会漏）
 *   2. v2 条目：改 evidence.ref → 必报篡改
 *   3. v2 条目：改扁平字段 → 必报篡改（不能为了修嵌套把平的丢了）
 *   4. 历史 v1 条目：仍可验通过（不做硬纪元切换 → 不销毁证据）
 *   5. verifyChain 必须诚实暴露 legacy 条数与 legacyTamperable
 *   6. v2 与 audit-log.js 的规范化一致（全仓单一口径）
 *
 * 运行：node csb-security/test/test-ledger-canon-v2.js
 */

const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const { EvidenceLedger, sha256, canonicalContent, canonicalContentV1, canonicalContentV2 } =
  require(path.join(ROOT, 'lib/trust/evidence-ledger.js'));

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✅ ${name}`); pass++; }
  catch (e) { console.log(`  ❌ ${name}\n     ${e.message}`); fail++; }
}

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'p0-0b-'));
const LEDGER = path.join(TMP, 'ledger.jsonl');

console.log('[ledger-canon] P0-0b 验收\n');

// ── 建 v2 账 ──
const led = new EvidenceLedger({ ledgerPath: LEDGER });
led.append({ subject: { name: '若兰', aid: 'aid-x', url: 'http://h:3100' }, action: 'message_ok', evidence: { ref: 'task-1', detail: 'ok' }, actor: 'test' });
led.append({ subject: { name: '阿轩' }, action: 'delegate_completed', evidence: { ref: 'task-2' }, actor: 'test' });

t('v2 条目自带 canon_version', () => {
  const e = JSON.parse(fs.readFileSync(LEDGER, 'utf8').split('\n').filter(Boolean)[0]);
  assert.strictEqual(e.canon_version, 'v2');
});

t('v2 与 audit-log.js 规范化完全一致（单一口径）', () => {
  const rec = { seq: 1, ts: 1, subject: { name: 'x' }, prev_hash: 'GENESIS' };
  const aepStyle = (r => { const { hash, signature, ...rest } = r; return JSON.stringify(rest); })(rec);
  assert.strictEqual(canonicalContentV2(rec), aepStyle);
});

function tamper(fn) {
  const lines = fs.readFileSync(LEDGER, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  fn(lines[0]);
  const p = path.join(TMP, `t-${crypto.randomBytes(4).toString('hex')}.jsonl`);
  fs.writeFileSync(p, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
  return new EvidenceLedger({ ledgerPath: p }).verifyChain();
}

t('JUDGE: 改 subject.name → 必报篡改（v1 会漏！）', () => {
  const v = tamper((e) => { e.subject = { ...e.subject, name: 'ATTACKER' }; });
  assert.strictEqual(v.ok, false, `应报篡改，实际 ${JSON.stringify(v)}`);
  assert.match(v.reason, /篡改/);
});

t('JUDGE: 改 subject.aid → 必报篡改', () => {
  const v = tamper((e) => { e.subject = { ...e.subject, aid: 'aid-evil' }; });
  assert.strictEqual(v.ok, false);
});

t('JUDGE: 改 evidence.ref → 必报篡改（证据指针不可改）', () => {
  const v = tamper((e) => { e.evidence = { ...e.evidence, ref: 'FORGED' }; });
  assert.strictEqual(v.ok, false);
});

t('JUDGE: 改扁平字段 action → 必报篡改（没为修嵌套丢扁平的）', () => {
  const v = tamper((e) => { e.action = 'delegate_completed'; });
  assert.strictEqual(v.ok, false);
});

t('对照：旧口径 v1 对 subject 篡改确实漏检（证明修复有意义）', () => {
  const e = {
    seq: 1, ts: 1, canon_version: 'v1', subject: { name: 'A', aid: 'x' }, action: 'message_ok', prev_hash: 'GENESIS',
  };
  const original = { ...e, subject: { name: 'A', aid: 'x' } };
  const attacked = { ...e, subject: { name: 'ATTACKER', aid: 'evil' } };
  assert.strictEqual(canonicalContentV1(original), canonicalContentV1(attacked), 'v1 口径下两者应字节相同（漏检）');
});

// ── 历史兼容：v1 条目仍能验 ──
t('JUDGE: 历史 v1 条目仍可验通过（不硬切换、不销毁证据）', () => {
  const p = path.join(TMP, 'mixed.jsonl');
  // 手工造一条 v1（无 canon_version）+ 一条 v2，链要接上
  const r1 = {
    seq: 1, ts: 1, subject: { name: '旧', aid: null, url: null }, subjectId: '旧',
    kind: 'interaction', action: 'message_ok', polarity: 1, weight: 1,
    evidence: { ref: 'r1' }, actor: 't', note: null, prev_hash: 'GENESIS',
  };
  r1.hash = sha256(canonicalContentV1(r1));
  const r2 = {
    seq: 2, ts: 2, canon_version: 'v2', subject: { name: '新', aid: null, url: null }, subjectId: '新',
    kind: 'interaction', action: 'message_ok', polarity: 1, weight: 1,
    evidence: { ref: 'r2' }, actor: 't', note: null, prev_hash: r1.hash,
  };
  r2.hash = sha256(canonicalContentV2(r2));
  fs.writeFileSync(p, [r1, r2].map((x) => JSON.stringify(x)).join('\n') + '\n');
  const v = new EvidenceLedger({ ledgerPath: p }).verifyChain();
  assert.strictEqual(v.ok, true, `混合账应验通过，实际 ${JSON.stringify(v)}`);
  assert.strictEqual(v.legacyEntries, 1, '应识别 1 条 v1 历史条目');
  assert.deepStrictEqual(v.canonVersions, { v1: 1, v2: 1 });
});

t('JUDGE: verifyChain 诚实暴露 legacyTamperable', () => {
  const v = new EvidenceLedger({ ledgerPath: LEDGER }).verifyChain();
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.legacyTamperable, v.legacyEntries > 0, '必须与 legacyEntries 一致');
});

t('签名口径随 canon_version 走（v2 条目签名也护嵌套）', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const p = path.join(TMP, 'signed.jsonl');
  const l = new EvidenceLedger({ ledgerPath: p, privateKey, publicKey });
  l.append({ subject: { name: '签名测试' }, action: 'message_ok', actor: 't' });
  assert.strictEqual(new EvidenceLedger({ ledgerPath: p, publicKey }).verifyChain().ok, true, '原账应验通过');
  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  lines[0].subject = { name: 'ATTACKER', aid: null, url: null };
  const p2 = path.join(TMP, 'signed-bad.jsonl');
  fs.writeFileSync(p2, lines.map((x) => JSON.stringify(x)).join('\n') + '\n');
  assert.strictEqual(new EvidenceLedger({ ledgerPath: p2, publicKey }).verifyChain().ok, false, '篡改后验签必须失败');
});

try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {}
// 输出格式必须与 run-all-tests.js 的解析器一致（两项分两行），
// 否则用例会被静默计 0 —— 「跑了但没人算」和「没跑」一样坏。
console.log(`\n通过: ${pass}`);
console.log(`失败: ${fail}`);
process.exit(fail === 0 ? 0 : 1);
