#!/usr/bin/env node
/**
 * test-aid.js — AID (Agent Identity Document) 测试
 * 协议: CSB-Security v1.0 §2.1
 */

const assert = require('assert');
const aid = require('../lib/identity/aid');

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

console.log('=== AID 测试 ===\n');

const { publicJwk, privateKey } = aid.generateKeyPair('key-test-01');

// 1. 生成完整 AID
test('生成完整 AID（含签名）', () => {
  const doc = aid.generateAID({
    agentId: 'ruolan@172.28.0.214:3100',
    name: '若兰',
    emoji: '🌸',
    capabilities: ['chat', 'vision'],
    trustLevel: 'L2',
    endpoint: 'http://172.28.0.214:3100/a2a/json-rpc',
    publicJwk
  }, privateKey);
  assert.ok(doc.signature, '应有签名');
  assert.strictEqual(doc.csb_version, '1.0');
  assert.strictEqual(doc.agent_id, 'ruolan@172.28.0.214:3100');
  assert.strictEqual(doc.public_key.crv, 'Ed25519');
  assert.ok(doc.expires_at, '应有过期时间');
});

// 2. 签名验证通过
test('验证合法 AID 签名通过', () => {
  const doc = aid.generateAID({
    agentId: 'axuan@172.28.0.5:3100',
    name: '阿轩',
    endpoint: 'http://172.28.0.5:3100/a2a/json-rpc',
    publicJwk
  }, privateKey);
  const result = aid.verifyAID(doc);
  assert.strictEqual(result.valid, true);
});

// 3. 篡改检测
test('篡改 AID 内容签名验证失败', () => {
  const doc = aid.generateAID({
    agentId: 'axuan@172.28.0.5:3100',
    name: '阿轩',
    endpoint: 'http://172.28.0.5:3100/a2a/json-rpc',
    publicJwk
  }, privateKey);
  doc.name = '恶意改名';
  const result = aid.verifyAID(doc);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'bad_signature');
});

// 4. 必填字段校验
test('缺失必填字段校验失败', () => {
  const doc = aid.generateAID({
    agentId: 'jeason@172.28.0.6:3300',
    name: 'Jeason',
    endpoint: 'http://172.28.0.6:3300/a2a/json-rpc',
    publicJwk
  }, privateKey);
  delete doc.endpoint;
  const result = aid.validateAID(doc);
  assert.strictEqual(result.valid, false);
  assert.ok(result.error.includes('endpoint'));
});

// 5. 错误公钥验证失败
test('用错误公钥验证签名失败', () => {
  const doc = aid.generateAID({
    agentId: 'jeason@172.28.0.6:3300',
    name: 'Jeason',
    endpoint: 'http://172.28.0.6:3300/a2a/json-rpc',
    publicJwk
  }, privateKey);
  const other = aid.generateKeyPair('key-other');
  doc.public_key = other.publicJwk; // 换公钥但保留原签名
  const result = aid.verifyAID(doc);
  assert.strictEqual(result.valid, false);
});

// 6. fromIdentity 兼容 identity.json
test('fromIdentity 从身份 JSON 生成', () => {
  const identity = {
    name: '若兰',
    emoji: '🌸',
    description: '来自杭州的温婉 AI 伙伴',
    port: 3100,
    publicHost: '172.28.0.214',
    capabilities: { chat: true, vision: true, voice: true },
    trust_level: 'L1'
  };
  const doc = aid.fromIdentity(identity, { publicJwk, privateKey });
  assert.strictEqual(doc.agent_id, '若兰@172.28.0.214:3100');
  assert.deepStrictEqual(doc.capabilities, ['chat', 'vision', 'voice']);
  assert.strictEqual(doc.trust_level, 'L1');
  assert.ok(aid.verifyAID(doc).valid);
});

// 7. 密钥对生成 JWK 格式
test('generateKeyPair 输出 JWK 格式', () => {
  assert.strictEqual(publicJwk.kty, 'OKP');
  assert.strictEqual(publicJwk.crv, 'Ed25519');
  assert.ok(publicJwk.x, '应有 x 字段');
  assert.strictEqual(publicJwk.kid, 'key-test-01');
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
