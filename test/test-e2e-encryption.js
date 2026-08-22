#!/usr/bin/env node
/**
 * test-e2e-encryption.js — E2E 加密测试（收编自 A2A-021）
 * 协议: CSB-Security v1.0 §4
 */

const assert = require('assert');
const { E2EEncryption } = require('../lib/transport/e2e-encryption');
const { generateEphemeralKeyPair, computeSharedSecret, deriveSessionKey } = require('../lib/transport/session-keys');

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

console.log('=== E2E 加密测试 ===\n');

const MASTER_KEY = 'test-master-key-2026';

// 1. PSK 加解密往返
test('PSK 模式加解密往返', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const encrypted = e2e.encrypt('你好，若兰', 'axuan@172.28.0.5:3100');
  assert.strictEqual(encrypted.encrypted, true);
  const plain = e2e.decrypt(encrypted, 'axuan@172.28.0.5:3100');
  assert.strictEqual(plain, '你好，若兰');
});

// 2. 篡改密文检测失败
test('篡改密文解密失败', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const encrypted = e2e.encrypt('秘密消息', 'ruolan@172.28.0.214:3100');
  encrypted.ciphertext = encrypted.ciphertext.slice(0, -2) + 'AA'; // 篡改
  const plain = e2e.decrypt(encrypted, 'ruolan@172.28.0.214:3100');
  assert.strictEqual(plain, null);
});

// 3. 篡改 tag 检测失败
test('篡改 auth tag 解密失败', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const encrypted = e2e.encrypt('秘密消息', 'ruolan@172.28.0.214:3100');
  encrypted.tag = Buffer.from('tampered-tag').toString('base64');
  const plain = e2e.decrypt(encrypted, 'ruolan@172.28.0.214:3100');
  assert.strictEqual(plain, null);
});

// 4. 错误 Agent 密钥解密失败（HKDF 隔离）
test('错误 Agent 密钥解密失败（HKDF 隔离）', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const encrypted = e2e.encrypt('给阿轩的消息', 'axuan@172.28.0.5:3100');
  const plain = e2e.decrypt(encrypted, 'jeason@172.28.0.6:3300'); // 用错 agentId
  assert.strictEqual(plain, null);
});

// 5. 未配置密钥时明文直通
test('未配置密钥时明文直通', () => {
  const e2e = new E2EEncryption();
  const result = e2e.encrypt('hello', 'a@1.2.3.4:3100');
  assert.strictEqual(result.encrypted, false);
  assert.strictEqual(result.plaintext, 'hello');
});

// 6. ECDH 会话密钥加解密
test('ECDH 会话密钥加解密', () => {
  const caller = generateEphemeralKeyPair();
  const callee = generateEphemeralKeyPair();
  // 双方各自计算共享密钥
  const s1 = computeSharedSecret(caller.privateKey, callee.publicKey);
  const s2 = computeSharedSecret(callee.privateKey, caller.publicKey);
  assert.ok(s1.equals(s2), '共享密钥应一致');
  const key = deriveSessionKey(s1, 'nonce-a', 'nonce-b');

  const e2e = new E2EEncryption({ masterKey: 'unused' });
  const encrypted = e2e.encryptWithKey('加密会话消息', key);
  const plain = e2e.decryptWithKey(encrypted, key);
  assert.strictEqual(plain, '加密会话消息');
});

// 7. HMAC 签名与验证
test('HMAC 签名与 timing-safe 验证', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const sig = e2e.signMessage('payload');
  assert.ok(sig);
  assert.strictEqual(e2e.verifySignature('payload', sig), true);
  assert.strictEqual(e2e.verifySignature('payload2', sig), false);
});

// 8. 信封加解密（兼容 envelope 格式）
test('信封加解密（envelope 兼容）', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const envelope = { sender: 'ruolan@172.28.0.214:3100', payload: { msg: 'hi' } };
  const enc = e2e.encryptEnvelope(envelope, 'ruolan@172.28.0.214:3100');
  assert.strictEqual(enc.encryption.encrypted, true);
  const dec = e2e.decryptEnvelope(enc, 'ruolan@172.28.0.214:3100');
  assert.deepStrictEqual(dec.payload, { msg: 'hi' });
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
