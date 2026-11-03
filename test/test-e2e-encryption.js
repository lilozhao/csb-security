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

// ══════════════════════════════════════════════════════════════════════
// [2026-11-03 · P0-4「A2A E2E 加密：真做，或诚实降级」]
// 下面这组测试锁的是一个**曾经存在、且没人发现的假绿**：
//   出站只置 obj.encrypted=true（没加密一个字节）· /health 按 enabled 报绿
//   · 无密钥时 verifySignature 直接 return true（签名形同虚设）。
// 三条都是「外观正常，判断不可信」，所以每条都要有机械判据。
// ══════════════════════════════════════════════════════════════════════

// 9. 三态：无密钥 = disabled + 明确 reason
test('三态：无主密钥 → disabled（reason: no_master_key）', () => {
  const e2e = new E2EEncryption({ masterKey: null });
  const st = e2e.getStatus();
  assert.strictEqual(st.status, 'disabled');
  assert.strictEqual(st.reason, 'no_master_key');
});

// 10. 三态：有密钥但出站未真加密 = degraded（不是 enabled）
test('三态：有密钥但出站未真加密 → degraded（reason: not_implemented）', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const st = e2e.getStatus();
  assert.strictEqual(st.status, 'degraded');
  assert.strictEqual(st.reason, 'not_implemented');
});

// 11. 三态：只有真声明出站已加密才是 enabled
test('三态：显式声明 outboundEncrypted 且有密钥 → enabled', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY, outboundEncrypted: true });
  const st = e2e.getStatus();
  assert.strictEqual(st.status, 'enabled');
  assert.strictEqual(st.reason, null);
});

// 12. 反向自测：不允许「声明加密却没密钥」（那会让 enabled 再次变假绿）
test('反向：outboundEncrypted=true 但无主密钥 → 直接抛错', () => {
  assert.throws(
    () => new E2EEncryption({ masterKey: null, outboundEncrypted: true }),
    /outboundEncrypted/,
    '声明出站已加密却没有主密钥，必须拒启而不是静默降级'
  );
});

// 13. 关键不变量：degraded / disabled 都必须带 reason（不许空口说降级）
test('不变量：非 enabled 状态必须带非空 reason', () => {
  for (const opts of [{ masterKey: null }, { masterKey: MASTER_KEY }]) {
    const st = new E2EEncryption(opts).getStatus();
    if (st.status !== 'enabled') {
      assert.ok(st.reason && st.reason.length > 0, `${st.status} 缺 reason —— 降级必须说清为什么`);
    }
  }
});

// 14. 假绿消除：getStats 里的 enabled 语义收紧为「有主密钥」，状态看 status
test('假绿消除：getStats 同时给出 status 与收紧后的 enabled', () => {
  const degraded = new E2EEncryption({ masterKey: MASTER_KEY }).getStats();
  assert.strictEqual(degraded.status, 'degraded');
  assert.strictEqual(degraded.enabled, true,        // 兼容字段：有主密钥
    'enabled=true 只表示「有主密钥」，不代表出站已加密');
  assert.strictEqual(degraded.outboundEncrypted, false);

  const disabled = new E2EEncryption({ masterKey: null }).getStats();
  assert.strictEqual(disabled.status, 'disabled');
  assert.strictEqual(disabled.enabled, false);
});

// 15. 关键修复：无密钥时验签不再默认通过
test('假绿消除：无主密钥时验签必须失败（原来直接 return true）', () => {
  const e2e = new E2EEncryption({ masterKey: null });
  assert.strictEqual(e2e.verifySignature('payload', 'any-signature'), false,
    '没配密钥时任何签名都算通过 = 签名形同虚设');
  const d = e2e.verifySignatureDetailed('payload', 'any-signature');
  assert.strictEqual(d.valid, false);
  assert.strictEqual(d.reason, 'no_master_key');
});

// 16. 无签名同样不算通过
test('假绿消除：无签名时验签必须失败（reason: signature_missing）', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  assert.strictEqual(e2e.verifySignature('payload', null), false);
  assert.strictEqual(e2e.verifySignatureDetailed('payload', null).reason, 'signature_missing');
});

// 17. 正常路径未受影响（有密钥 + 有签名 → 通过；内容不符 → 失败）
test('回归：有密钥时正常验签行为不变', () => {
  const e2e = new E2EEncryption({ masterKey: MASTER_KEY });
  const sig = e2e.signMessage('payload');
  assert.strictEqual(e2e.verifySignature('payload', sig), true);
  assert.strictEqual(e2e.verifySignature('payload2', sig), false);
  assert.strictEqual(e2e.verifySignatureDetailed('payload2', sig).reason, 'signature_mismatch');
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
