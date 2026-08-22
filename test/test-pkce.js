#!/usr/bin/env node
/**
 * test-pkce.js — PKCE 测试（协议 §4.4 / RFC 7636）
 */

const assert = require('assert');
const pkce = require('../lib/transport/pkce');

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

console.log('=== PKCE 测试 ===\n');

// 1. 生成 verifier（43-128 字符）
test('verifier 长度合规（43-128）', () => {
  const v = pkce.generateVerifier();
  assert.ok(v.length >= 43 && v.length <= 128);
  assert.strictEqual(v.length, pkce.VERIFIER_LENGTH);
});

// 2. challenge S256 正确性（RFC 7636 官方示例向量）
test('S256 challenge 符合 RFC 7636 示例', () => {
  // RFC 7636 附录 B 示例
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const challenge = pkce.generateChallenge(verifier);
  // 期望值来自 RFC 7636 附录 B
  assert.strictEqual(challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

// 3. verifyChallenge 匹配
test('正确 verifier 验证通过', () => {
  const { verifier, challenge } = pkce.generatePKCEPair();
  assert.strictEqual(pkce.verifyChallenge(verifier, challenge), true);
});

// 4. 错误 verifier 拒绝
test('错误 verifier 拒绝', () => {
  const { challenge } = pkce.generatePKCEPair();
  assert.strictEqual(pkce.verifyChallenge('wrong-verifier-1234567890', challenge), false);
});

// 5. state 高熵（≥128 位）
test('state 至少 128 位熵', () => {
  const { state } = pkce.generatePKCEPair();
  assert.ok(Buffer.from(state, 'base64url').length >= 16); // 128 位
});

// 6. 仅支持 S256
test('仅支持 S256 方法', () => {
  assert.throws(() => pkce.generateChallenge('verifier', 'plain'), /only S256/);
});

// 7. verifier 长度边界
test('verifier 长度边界校验', () => {
  assert.throws(() => pkce.generateVerifier(10), /43-128/);
  assert.throws(() => pkce.generateVerifier(200), /43-128/);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
