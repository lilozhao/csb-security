#!/usr/bin/env node
/**
 * test-verify-signature.js — P0-3 D1 验证签名测试
 * 协议: P0-3 REV-2026-09-05 D1（约束-验证分离 · author ≠ validator）
 */

const assert = require('assert');
const aid = require('../lib/identity/aid');
const {
  canonicalize,
  sigHash,
  signVerification,
  verifyVerificationRecord
} = require('../lib/verify/verify-signature');

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

console.log('=== verify-signature (P0-3 D1) 测试 ===\n');

// 生产侧：作者（producer）与验证者（validator）是不同 Agent
const producer = aid.generateKeyPair('key-producer-test');
const producerAid = aid.generateAID({
  agentId: 'xiaxia@172.28.0.12:3100',
  name: '小虾',
  endpoint: 'http://172.28.0.12:3100/a2a/json-rpc',
  publicJwk: producer.publicJwk
}, producer.privateKey);

const validator = aid.generateKeyPair('key-validator-test');
const validatorAid = aid.generateAID({
  agentId: 'siyuan@172.28.0.44:3601',
  name: '思源',
  endpoint: 'http://172.28.0.44:3601/a2a/json-rpc',
  publicJwk: validator.publicJwk
}, validator.privateKey);

function baseClaim(overrides = {}) {
  return {
    csb_version: '1.0',
    type: 'verification',
    subject_id: 'skill/verify-command/sample-001',
    producer_id: producerAid.agent_id,      // 作者
    validator_id: validatorAid.agent_id,    // 验证者 ≠ 作者
    verdict: 'passed',
    ts: '2026-09-05T06:00:00.000Z',
    ...overrides
  };
}

// ---------- canonicalize ----------
test('canonicalize：key 顺序不影响序列化结果', () => {
  const a = canonicalize({ b: 1, a: { d: 2, c: 3 } });
  const b = canonicalize({ a: { c: 3, d: 2 }, b: 1 });
  assert.strictEqual(a, b);
});

test('canonicalize：无空白、紧凑序列化', () => {
  const s = canonicalize({ a: 'x', b: 1 });
  assert.ok(!s.includes(' '), '不应含空白');
  assert.strictEqual(s, '{"a":"x","b":1}');
});

// ---------- sign + verify 正向 ----------
test('签名后能通过校验（valid=true）', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const r = verifyVerificationRecord(claim, signature, validatorAid);
  assert.strictEqual(r.valid, true);
  assert.strictEqual(r.validator_id, validatorAid.agent_id);
  assert.strictEqual(r.subject_id, claim.subject_id);
});

test('verify 对 claim 内部 key 顺序鲁棒（规范化一致）', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  // 打乱 key 顺序的等义对象
  const shuffled = {
    ts: claim.ts,
    subject_id: claim.subject_id,
    csb_version: claim.csb_version,
    verdict: claim.verdict,
    validator_id: claim.validator_id,
    producer_id: claim.producer_id,
    type: claim.type
  };
  const r = verifyVerificationRecord(shuffled, signature, validatorAid);
  assert.strictEqual(r.valid, true);
});

// ---------- 防篡改 / 防伪造 ----------
test('篡改 claim（改 verdict）→ signature_invalid', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const tampered = { ...claim, verdict: 'failed' };
  const r = verifyVerificationRecord(tampered, signature, validatorAid);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'signature_invalid');
});

test('篡改 subject_id → signature_invalid', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const tampered = { ...claim, subject_id: 'skill/other-999' };
  const r = verifyVerificationRecord(tampered, signature, validatorAid);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'signature_invalid');
});

test('用错误的公钥（非本 validator）验签 → signature_invalid', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const attacker = aid.generateKeyPair('key-attacker-test');
  const fakeAid = {
    agent_id: 'evil@1.2.3.4:3100',
    name: '冒名者',
    public_key: attacker.publicJwk
  };
  const r = verifyVerificationRecord(claim, signature, fakeAid);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'signature_invalid');
});

// ---------- 防自证（P0-2/P0-3 核心） ----------
test('author === validator 时签发直接拒绝（self_verification）', () => {
  const claim = baseClaim({ validator_id: producerAid.agent_id });
  assert.throws(() => signVerification(claim, validator.privateKey), /self_verification/);
});

test('author === validator 的伪造签名被 verify 识破（self_verification）', () => {
  // 作者拿自己私钥给自己的 skill 签验证
  const selfClaim = baseClaim({ validator_id: producerAid.agent_id });
  const { signature } = signVerification(
    { ...selfClaim, producer_id: 'someone-else@x' }, // 先骗过签发，绕开自证
    producer.privateKey
  );
  // 但用真实 claim（author=validator）去验 → 结构上即拒绝
  const r = verifyVerificationRecord(selfClaim, signature, producerAid);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'self_verification');
});

// ---------- AID 严格度 ----------
test('伪造的 AID 自签被识破（invalid_aid）', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const forged = {
    ...validatorAid,
    signature: Buffer.alloc(64).toString('base64') // 假签名
  };
  const r = verifyVerificationRecord(claim, signature, forged);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'invalid_aid');
});

test('requireAid 严格模式：无 AID 自签的轻量公钥被拒（missing_aid_signature）', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const light = { agent_id: validatorAid.agent_id, name: '思源', public_key: validator.publicJwk };
  const r = verifyVerificationRecord(claim, signature, light, { requireAid: true });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'missing_aid_signature');
});

test('轻量公钥（无 AID 自签）+ verifyAid 关闭 → 正常验签', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const light = { agent_id: validatorAid.agent_id, name: '思源', public_key: validator.publicJwk };
  const r = verifyVerificationRecord(claim, signature, light, { verifyAid: false });
  assert.strictEqual(r.valid, true);
});

test('无效公钥结构 → bad_public_key', () => {
  const claim = baseClaim();
  const { signature } = signVerification(claim, validator.privateKey);
  const r = verifyVerificationRecord(claim, signature, { agent_id: 'x', public_key: { x: '!' } });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'bad_public_key');
});

// ---------- 时效 ----------
test('超过 maxAgeMs → expired', () => {
  const old = baseClaim({ ts: new Date(Date.now() - 10 * 24 * 3600 * 1000).toISOString() });
  const { signature } = signVerification(old, validator.privateKey);
  const r = verifyVerificationRecord(old, signature, validatorAid, { maxAgeMs: 7 * 24 * 3600 * 1000 });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'expired');
});

test('maxAgeMs 内 → 仍有效', () => {
  const claim = baseClaim({ ts: new Date().toISOString() });
  const { signature } = signVerification(claim, validator.privateKey);
  const r = verifyVerificationRecord(claim, signature, validatorAid, { maxAgeMs: 7 * 24 * 3600 * 1000 });
  assert.strictEqual(r.valid, true);
});

// ---------- 结构 / sig_hash ----------
test('缺必填字段 → invalid_claim', () => {
  const { subject_id, ...missing } = baseClaim();
  const { signature } = signVerification(baseClaim(), validator.privateKey);
  const r = verifyVerificationRecord(missing, signature, validatorAid);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.error, 'invalid_claim');
});

test('sig_hash 稳定且随内容变化', () => {
  const c1 = baseClaim();
  const c2 = baseClaim({ verdict: 'failed' });
  const shuffled = { ...c1 };
  const keys = Object.keys(shuffled);
  // 反向顺序不影响
  const reordered = Object.fromEntries(keys.reverse().map((k) => [k, shuffled[k]]));
  assert.strictEqual(sigHash(c1), sigHash(reordered));
  assert.notStrictEqual(sigHash(c1), sigHash(c2));
});

test('签名往返签名与 sig_hash 一致（供 verif-log 存证）', () => {
  const claim = baseClaim();
  const out = signVerification(claim, validator.privateKey);
  assert.strictEqual(out.sig_hash, sigHash(claim));
  const r = verifyVerificationRecord(claim, out.signature, validatorAid);
  assert.strictEqual(r.valid, true);
});

console.log(`\n通过: ${passed}`);
console.log(`失败: ${failed}`);
if (failed > 0) process.exit(1);
