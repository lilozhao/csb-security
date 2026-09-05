#!/usr/bin/env node
/**
 * test-verif-log.js — P0-3 D1 验证记录上链存证测试
 * 协议: P0-3 REV-2026-09-05 D1（验证记录须可追溯存证 · 不可篡改）
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const aid = require('../lib/identity/aid');
const { signVerification, sigHash } = require('../lib/verify/verify-signature');
const { VerifLog } = require('../lib/verify/verif-log');
const { GENESIS_HASH } = require('../lib/audit/audit-log');

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

console.log('=== verif-log (P0-3 D1 上链存证) 测试 ===\n');

// 生产者（作者）与验证者是不同 Agent（防自证前提）
const producer = aid.generateKeyPair('key-producer-vlog');
const producerAid = aid.generateAID({
  agentId: 'xiaxia@172.28.0.12:3100',
  name: '小虾',
  endpoint: 'http://172.28.0.12:3100/a2a/json-rpc',
  publicJwk: producer.publicJwk
}, producer.privateKey);

const validator = aid.generateKeyPair('key-validator-vlog');
const validatorAid = aid.generateAID({
  agentId: 'siyuan@172.28.0.44:3601',
  name: '思源',
  endpoint: 'http://172.28.0.44:3601/a2a/json-rpc',
  publicJwk: validator.publicJwk
}, validator.privateKey);

const secondValidator = aid.generateKeyPair('key-validator-vlog-2');
const secondValidatorAid = aid.generateAID({
  agentId: 'axuan@172.28.0.5:3100',
  name: '阿轩',
  endpoint: 'http://172.28.0.5:3100/a2a/json-rpc',
  publicJwk: secondValidator.publicJwk
}, secondValidator.privateKey);

function baseClaim(overrides = {}) {
  return {
    csb_version: '1.0',
    type: 'verification',
    subject_id: 'skill/verify-command/sample-001',
    producer_id: producerAid.agent_id,
    validator_id: validatorAid.agent_id,
    verdict: 'passed',
    ts: '2026-09-05T06:00:00.000Z',
    ...overrides
  };
}

function makeVerification(claimOverrides = {}, key = validator.privateKey) {
  return signVerification(baseClaim(claimOverrides), key);
}

// 用第二位验证者（阿轩）签发：claim.validator_id 与私钥必须配套
function makeVerificationBySecond(claimOverrides = {}) {
  return signVerification(
    baseClaim({ validator_id: secondValidatorAid.agent_id, ...claimOverrides }),
    secondValidator.privateKey
  );
}

// ---------- 正向：上链 ----------
test('验证记录上链成功：seq=1、prev_hash=GENESIS、含 verification 全量', () => {
  const log = new VerifLog();
  const rec = log.append(makeVerification(), validatorAid);
  assert.strictEqual(rec.seq, 1);
  assert.strictEqual(rec.prev_hash, GENESIS_HASH);
  assert.ok(rec.hash && rec.hash.length === 64, '应有 sha256 hash');
  assert.strictEqual(rec.event_type, 'verification');
  assert.ok(rec.verification.claim && rec.verification.signature, '应存全量验证记录');
  assert.strictEqual(rec.verification.sig_hash, sigHash(rec.verification.claim), 'sig_hash 锚点一致');
});

test('多条上链后链完整性 valid（哈希链连续）', () => {
  const log = new VerifLog();
  log.append(makeVerification(), validatorAid);
  log.append(makeVerification({ subject_id: 'skill/verify-command/sample-002' }), validatorAid);
  log.append(makeVerificationBySecond({ subject_id: 'skill/verify-command/sample-003' }), secondValidatorAid);
  const r = log.verifyIntegrity();
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.count, 3);
});

test('上链记录 prev_hash 与上一条 hash 衔接', () => {
  const log = new VerifLog();
  const r1 = log.append(makeVerification(), validatorAid);
  const r2 = log.append(makeVerification({ subject_id: 'skill/verify-command/sample-002' }), validatorAid);
  assert.strictEqual(r2.prev_hash, r1.hash);
});

// ---------- 防自证（双保险：verify-signature 层 + 上链前验签） ----------
test('author === validator 的记录被拒上链（self_verification）', () => {
  const log = new VerifLog();
  // 绕过签发端防自证检查，手工构造「作者给自己背书」的签名记录，直测上链端拦截
  const crypto = require('crypto');
  const { canonicalize } = require('../lib/verify/verify-signature');
  const selfClaim = baseClaim({ validator_id: producerAid.agent_id, producer_id: producerAid.agent_id });
  const sig = crypto.sign(null, Buffer.from(canonicalize(selfClaim), 'utf8'), producer.privateKey).toString('base64');
  assert.throws(() => log.append({ claim: selfClaim, signature: sig }, producerAid), /self_verification/);
  assert.strictEqual(log.audit.entries.length, 0, '不应有任何记录上链');
});

// ---------- 防伪 / 防篡改 ----------
test('伪造签名（非 validator 私钥签发）→ 拒绝上链', () => {
  const log = new VerifLog();
  const attacker = aid.generateKeyPair('key-attacker-vlog');
  const forged = signVerification(baseClaim(), attacker.privateKey); // 攻击者私钥签
  assert.throws(() => log.append(forged, validatorAid), /signature_invalid/);
  assert.strictEqual(log.audit.entries.length, 0);
});

test('篡改 claim 内容（verdict 翻转）→ 拒绝上链', () => {
  const log = new VerifLog();
  const v = makeVerification();
  const tampered = { ...v, claim: { ...v.claim, verdict: 'failed' } }; // 改了 claim 但没重签
  assert.throws(() => log.append(tampered, validatorAid), /signature_invalid/);
  assert.strictEqual(log.audit.entries.length, 0);
});

test('sig_hash 与 claim 不一致 → 拒绝上链（存证锚点防脱节）', () => {
  const log = new VerifLog();
  const v = makeVerification();
  const mismatched = { ...v, sig_hash: 'AAAA' };
  assert.throws(() => log.append(mismatched, validatorAid), /sig_hash_mismatch/);
});

test('非法结构（缺 claim / 缺 signature）→ 拒绝上链', () => {
  const log = new VerifLog();
  assert.throws(() => log.append(null, validatorAid), /invalid_record/);
  assert.throws(() => log.append({ claim: baseClaim() }, validatorAid), /invalid_record/);
  assert.strictEqual(log.audit.entries.length, 0);
});

// ---------- 追溯存证（D1 可追溯要求） ----------
test('queryBySubject：按验证对象追溯', () => {
  const log = new VerifLog();
  log.append(makeVerification(), validatorAid);
  log.append(makeVerification({ subject_id: 'skill/verify-command/sample-002' }), validatorAid);
  const hits = log.queryBySubject('skill/verify-command/sample-001');
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].verification.claim.subject_id, 'skill/verify-command/sample-001');
});

test('queryByValidator：按验证者追溯（D4 信誉数据源）', () => {
  const log = new VerifLog();
  log.append(makeVerification(), validatorAid);
  log.append(makeVerification({ subject_id: 'skill/verify-command/sample-002' }), validatorAid);
  log.append(makeVerificationBySecond({ subject_id: 'skill/verify-command/sample-003' }), secondValidatorAid);
  const hits = log.queryByValidator(validatorAid.agent_id);
  assert.strictEqual(hits.length, 2);
  assert.ok(hits.every((e) => e.caller_id === validatorAid.agent_id));
});

test('queryByProducer：按作者追溯（防自证审计：谁验证了某作者的产出）', () => {
  const log = new VerifLog();
  log.append(makeVerification(), validatorAid);
  const hits = log.queryByProducer(producerAid.agent_id);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].callee_id, producerAid.agent_id);
});

// ---------- 不可篡改（哈希链） ----------
test('篡改已上链记录（改 verdict）→ verifyIntegrity 检出断链', () => {
  const log = new VerifLog();
  log.append(makeVerification(), validatorAid);
  log.append(makeVerification({ subject_id: 'skill/verify-command/sample-002' }), validatorAid);
  // 直接篡改内存条目
  log.audit.entries[0].verification.claim.verdict = 'failed';
  const r = log.verifyIntegrity();
  assert.strictEqual(r.valid, false);
  assert.ok(r.reason === 'entry_tampered' || r.reason === 'hash_chain_broken', `检出: ${r.reason}`);
});

// ---------- 文件落盘持久化 ----------
test('文件落盘：reopen 后链仍完整、记录可追溯', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'veriflog-'));
  const logPath = path.join(tmp, 'verif-log.jsonl');
  const log = new VerifLog({ logPath });
  log.append(makeVerification(), validatorAid);
  log.append(makeVerification({ subject_id: 'skill/verify-command/sample-002' }), validatorAid);

  const reopened = new VerifLog({ logPath });
  const r = reopened.verifyIntegrity();
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.count, 2);
  assert.strictEqual(reopened.queryBySubject('skill/verify-command/sample-002').length, 1);
  fs.rmSync(tmp, { recursive: true, force: true });
});

// ---------- failed 记录也存证 ----------
test('verdict=failed 的记录同样上链存证（失败也要留痕）', () => {
  const log = new VerifLog();
  const rec = log.append(makeVerification({ verdict: 'failed' }), validatorAid);
  assert.strictEqual(rec.result, 'failed');
  assert.strictEqual(log.summary().byVerdict.failed, 1);
});

// ---------- 摘要 ----------
test('summary：总数 + verdict 分布 + 链状态', () => {
  const log = new VerifLog();
  log.append(makeVerification(), validatorAid);
  log.append(makeVerification({ verdict: 'failed', subject_id: 'skill/verify-command/sample-002' }), validatorAid);
  const s = log.summary();
  assert.strictEqual(s.total, 2);
  assert.strictEqual(s.byVerdict.passed, 1);
  assert.strictEqual(s.byVerdict.failed, 1);
  assert.strictEqual(s.chainValid, true);
});

// ---------- 链签名（配置时） ----------
test('配置链私钥后：每条上链记录带 Ed25519 签名，verifyIntegrity 验签通过', () => {
  const { privateKey, publicKey } = (() => {
    const k = require('crypto').generateKeyPairSync('ed25519');
    return { privateKey: k.privateKey, publicKey: k.publicKey };
  })();
  const log = new VerifLog({ chainPrivateKey: privateKey, chainPublicKey: publicKey });
  log.append(makeVerification(), validatorAid);
  assert.ok(log.audit.entries[0].signature, '上链记录应有链签名');
  const r = log.verifyIntegrity();
  assert.strictEqual(r.valid, true);
});

// ---------- 汇总 ----------
console.log(`\n通过: ${passed}`);
console.log(`失败: ${failed}`);
if (failed > 0) process.exit(1);
