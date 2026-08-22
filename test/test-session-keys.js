#!/usr/bin/env node
/**
 * test-session-keys.js — 会话密钥协商测试（ECDH-P256）
 * 协议: CSB-Security v1.0 §4.2
 */

const assert = require('assert');
const {
  generateEphemeralKeyPair,
  computeSharedSecret,
  deriveSessionKey,
  SessionKeyNegotiator,
  buildConfirm,
  processConfirmV2,
  encodePublicKey
} = require('../lib/transport/session-keys');

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

console.log('=== 会话密钥协商测试 ===\n');

const CALLER = 'ruolan@172.28.0.214:3100';
const CALLEE = 'axuan@172.28.0.5:3100';

// 1. 完整协商流程（双方密钥一致）
test('完整 ECDH 协商双方密钥一致', () => {
  const callerKp = generateEphemeralKeyPair();
  const calleeKp = generateEphemeralKeyPair();
  const neg = new SessionKeyNegotiator();

  const request = neg.initiate({ callerId: CALLER, calleeId: CALLEE, callerKeyPair: callerKp });
  const response = neg.processRequest(request, { calleeKeyPair: calleeKp });
  const { confirm, sessionKey: callerKey } = neg.processResponse(request, response, { callerKeyPair: callerKp });
  const { sessionKey: calleeKey } = processConfirmV2(confirm, calleeKp);

  assert.ok(callerKey.equals(calleeKey), '双方会话密钥应一致');
  assert.strictEqual(callerKey.length, 32);
});

// 2. 会话密钥确定性（相同输入相同输出）
test('会话密钥 HKDF 确定性', () => {
  const kp1 = generateEphemeralKeyPair();
  const kp2 = generateEphemeralKeyPair();
  const shared = computeSharedSecret(kp1.privateKey, kp2.publicKey);
  const k1 = deriveSessionKey(shared, 'nonce-a', 'nonce-b');
  const k2 = deriveSessionKey(shared, 'nonce-a', 'nonce-b');
  assert.ok(k1.equals(k2));
  // 不同 nonce → 不同密钥
  const k3 = deriveSessionKey(shared, 'nonce-a', 'nonce-c');
  assert.ok(!k1.equals(k3));
});

// 3. sign_nonce_a 伪造拒绝
test('sign_nonce_a 伪造拒绝', () => {
  const callerKp = generateEphemeralKeyPair();
  const attackerKp = generateEphemeralKeyPair();
  const calleeKp = generateEphemeralKeyPair();
  const neg = new SessionKeyNegotiator();

  const request = neg.initiate({ callerId: CALLER, calleeId: CALLEE, callerKeyPair: callerKp });
  // 攻击者响应：声称自己是 callee（公钥换成合法 callee 的），但签名用攻击者私钥
  const response = neg.processRequest(request, { calleeKeyPair: attackerKp });
  response.callee_pubkey = encodePublicKey(calleeKp.publicJwk);
  assert.throws(() => neg.processResponse(request, response, { callerKeyPair: callerKp }),
    /sign_nonce_a verification failed/);
});

// 4. sign_nonce_b 伪造拒绝
test('sign_nonce_b 伪造拒绝', () => {
  const callerKp = generateEphemeralKeyPair();
  const calleeKp = generateEphemeralKeyPair();
  const neg = new SessionKeyNegotiator();

  const request = neg.initiate({ callerId: CALLER, calleeId: CALLEE, callerKeyPair: callerKp });
  const response = neg.processRequest(request, { calleeKeyPair: calleeKp });
  const { confirm } = neg.processResponse(request, response, { callerKeyPair: callerKp });

  // 篡改 sign_nonce_b（用攻击者密钥重签）
  const attackerKp = generateEphemeralKeyPair();
  const { signNonce } = require('../lib/transport/session-keys');
  confirm.sign_nonce_b = signNonce(response.nonce_b, attackerKp.privateKey);
  assert.throws(() => processConfirmV2(confirm, calleeKp),
    /sign_nonce_b verification failed/);
});

// 5. 中间人：不同密钥对 → 不同会话密钥
test('不同密钥对推导出不同会话密钥', () => {
  const callerKp = generateEphemeralKeyPair();
  const calleeKp1 = generateEphemeralKeyPair();
  const calleeKp2 = generateEphemeralKeyPair();
  const shared1 = computeSharedSecret(callerKp.privateKey, calleeKp1.publicKey);
  const shared2 = computeSharedSecret(callerKp.privateKey, calleeKp2.publicKey);
  assert.ok(!shared1.equals(shared2));
  const k1 = deriveSessionKey(shared1, 'a', 'b');
  const k2 = deriveSessionKey(shared2, 'a', 'b');
  assert.ok(!k1.equals(k2));
});

// 6. 会话密钥实际用于加解密
test('会话密钥用于 AES-GCM 加解密', () => {
  const callerKp = generateEphemeralKeyPair();
  const calleeKp = generateEphemeralKeyPair();
  const neg = new SessionKeyNegotiator();
  const request = neg.initiate({ callerId: CALLER, calleeId: CALLEE, callerKeyPair: callerKp });
  const response = neg.processRequest(request, { calleeKeyPair: calleeKp });
  const { confirm, sessionKey: callerKey } = neg.processResponse(request, response, { callerKeyPair: callerKp });
  const { sessionKey: calleeKey } = processConfirmV2(confirm, calleeKp);

  const { E2EEncryption } = require('../lib/transport/e2e-encryption');
  const e2e = new E2EEncryption({ masterKey: 'x' });
  const enc = e2e.encryptWithKey('会话建立后的秘密消息', callerKey);
  const plain = e2e.decryptWithKey(enc, calleeKey);
  assert.strictEqual(plain, '会话建立后的秘密消息');
});

// 7. nonce 重放防护
test('key_exchange_request nonce 重放拒绝', () => {
  const neg = new SessionKeyNegotiator();
  const callerKp = generateEphemeralKeyPair();
  const request = neg.initiate({ callerId: CALLER, calleeId: CALLEE, callerKeyPair: callerKp });
  neg.processRequest(request, { calleeKeyPair: generateEphemeralKeyPair() });
  assert.throws(() => neg.processRequest(request, { calleeKeyPair: generateEphemeralKeyPair() }),
    /nonce replay detected/);
});

// 8. confirm nonce_b 重放防护
test('confirm nonce_b 重放拒绝', () => {
  const callerKp = generateEphemeralKeyPair();
  const calleeKp = generateEphemeralKeyPair();
  const neg = new SessionKeyNegotiator();
  const request = neg.initiate({ callerId: CALLER, calleeId: CALLEE, callerKeyPair: callerKp });
  const response = neg.processRequest(request, { calleeKeyPair: calleeKp });
  const { confirm } = neg.processResponse(request, response, { callerKeyPair: callerKp });

  const seen = new Set();
  processConfirmV2(confirm, calleeKp, { seenNonces: seen });
  assert.throws(() => processConfirmV2(confirm, calleeKp, { seenNonces: seen }),
    /nonce replay detected/);
});

// 9. 消息类型校验
test('错误消息类型拒绝', () => {
  const neg = new SessionKeyNegotiator();
  assert.throws(() => neg.processRequest({ type: 'evil' }, {}), /expected key_exchange_request/);
  assert.throws(() => neg.processResponse({}, { type: 'evil' }, {}), /expected key_exchange_response/);
  assert.throws(() => processConfirmV2({ type: 'evil' }, generateEphemeralKeyPair()), /expected key_exchange_confirm/);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
