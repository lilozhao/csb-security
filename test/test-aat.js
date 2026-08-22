#!/usr/bin/env node
/**
 * test-aat.js — AAT (Agent Attestation Token) 测试
 * 协议: CSB-Security v1.0 §2.2
 */

const assert = require('assert');
const aat = require('../lib/identity/aat');
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

console.log('=== AAT 测试 ===\n');

const { publicJwk, privateKey } = aid.generateKeyPair('key-test-02');
const ISSUER = 'ruolan@172.28.0.214:3100';
const AUDIENCE = 'axuan@172.28.0.5:3100';

// 1. 签发 AAT
test('签发 AAT 返回 JWT 三段式', () => {
  const token = aat.createAAT({
    privateKey, issuer: ISSUER, audience: AUDIENCE,
    capabilities: ['chat', 'memory:read']
  });
  assert.strictEqual(token.split('.').length, 3);
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  assert.strictEqual(header.alg, 'EdDSA');
  assert.strictEqual(header.typ, 'JWT');
});

// 2. 验证通过
test('验证合法 AAT 通过', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE });
  const result = aat.verifyAAT(token, { publicKey: publicJwk, expectedAudience: AUDIENCE });
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.payload.iss, ISSUER);
  assert.strictEqual(result.payload.aud, AUDIENCE);
});

// 3. 过期拒绝
test('过期 AAT 拒绝', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE, ttl: 5 });
  // 模拟 10 分钟后验证
  const result = aat.verifyAAT(token, {
    publicKey: publicJwk, expectedAudience: AUDIENCE,
    now: Date.now() + 10 * 60 * 1000
  });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'expired');
});

// 4. aud 不匹配拒绝
test('aud 不匹配拒绝', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE });
  const result = aat.verifyAAT(token, {
    publicKey: publicJwk, expectedAudience: 'jeason@172.28.0.6:3300'
  });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'audience_mismatch');
});

// 5. iat 漂移拒绝
test('iat 时间漂移拒绝', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE });
  // 模拟 10 分钟前签发，现在验证（漂移 > 5 分钟）
  const result = aat.verifyAAT(token, {
    publicKey: publicJwk, expectedAudience: AUDIENCE,
    now: Date.now() + 10 * 60 * 1000
  });
  // 此时 exp(5min) 已过期，先命中 expired 也 OK；单独测漂移用 ttl 长的
  if (result.valid !== false) throw new Error('应拒绝');
});

test('iat 漂移拒绝（ttl 足够长时命中 time_drift）', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE, ttl: 3600 });
  const result = aat.verifyAAT(token, {
    publicKey: publicJwk, expectedAudience: AUDIENCE,
    now: Date.now() + 10 * 60 * 1000
  });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'time_drift');
});

// 6. 签名篡改拒绝
test('签名篡改拒绝', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE });
  const parts = token.split('.');
  const tampered = `${parts[0]}.${parts[1]}.${Buffer.from('tampered').toString('base64url')}`;
  const result = aat.verifyAAT(tampered, { publicKey: publicJwk, expectedAudience: AUDIENCE });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'bad_signature');
});

// 7. payload 篡改拒绝（改 aud）
test('payload 篡改拒绝', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE });
  const [h, p] = token.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  payload.aud = 'jeason@172.28.0.6:3300';
  const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${token.split('.')[2]}`;
  const result = aat.verifyAAT(tampered, { publicKey: publicJwk, expectedAudience: AUDIENCE });
  assert.strictEqual(result.valid, false);
});

// 8. jti 重放拒绝
test('jti 重放拒绝', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE });
  const jtiCache = new Set();
  const first = aat.verifyAAT(token, { publicKey: publicJwk, expectedAudience: AUDIENCE, jtiCache });
  assert.strictEqual(first.valid, true);
  const replay = aat.verifyAAT(token, { publicKey: publicJwk, expectedAudience: AUDIENCE, jtiCache });
  assert.strictEqual(replay.valid, false);
  assert.strictEqual(replay.error, 'replay_detected');
});

// 9. 错误公钥拒绝
test('错误公钥验证拒绝', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE });
  const other = aid.generateKeyPair('key-other');
  const result = aat.verifyAAT(token, { publicKey: other.publicJwk, expectedAudience: AUDIENCE });
  assert.strictEqual(result.valid, false);
});

// 10. 通配符 aud
test('aud 通配符 * 接受', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: '*' });
  const result = aat.verifyAAT(token, { publicKey: publicJwk, expectedAudience: AUDIENCE });
  assert.strictEqual(result.valid, true);
});

// 11. nonce 支持
test('AAT 支持 nonce 挑战', () => {
  const token = aat.createAAT({ privateKey, issuer: ISSUER, audience: AUDIENCE, nonce: 'challenge-abc123' });
  const result = aat.verifyAAT(token, { publicKey: publicJwk, expectedAudience: AUDIENCE });
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.payload.nonce, 'challenge-abc123');
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
