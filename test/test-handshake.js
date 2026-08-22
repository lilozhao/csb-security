#!/usr/bin/env node
/**
 * test-handshake.js — 五步对等握手测试
 * 协议: CSB-Security v1.0 §7
 */

const assert = require('assert');
const { HandshakeManager, HandshakeError, SECURITY_LEVEL } = require('../lib/handshake/handshake');
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

console.log('=== 五步握手测试 ===\n');

// 测试环境：caller 若兰 ↔ callee 阿轩
const callerKey = aid.generateKeyPair('caller-key');
const calleeKey = aid.generateKeyPair('callee-key');
const userKey = aid.generateKeyPair('user-key');

const CALLER = 'ruolan@172.28.0.214:3100';
const CALLEE = 'axuan@172.28.0.5:3100';

const callerAID = aid.generateAID({
  agentId: CALLER, name: '若兰',
  endpoint: 'http://172.28.0.214:3100/a2a/json-rpc',
  publicJwk: callerKey.publicJwk
}, callerKey.privateKey);

const calleeAID = aid.generateAID({
  agentId: CALLEE, name: '阿轩',
  endpoint: 'http://172.28.0.5:3100/a2a/json-rpc',
  publicJwk: calleeKey.publicJwk
}, calleeKey.privateKey);

function runFullHandshake(level = SECURITY_LEVEL.LIGHT, options = {}) {
  const mgr = new HandshakeManager();
  const scopes = ['chat', 'memory:read'];

  // Step 1: caller 发起
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: scopes, securityLevel: level,
    callerPrivateKey: callerKey.privateKey, callerAID
  });

  // Step 2: callee 挑战
  const challenge = mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat', 'memory:read', 'forum:post']
  });

  // Step 3: caller 证明
  const proof = mgr.processChallenge(init, challenge, {
    callerPrivateKey: callerKey.privateKey, callerAID, calleeAID,
    userPrivateKey: userKey.privateKey, userId: 'user-yilan@csb'
  });

  // Step 4: callee 审批
  const approval = mgr.processProof(challenge, proof, {
    callerAID, userPublicKey: userKey.publicJwk,
    calleeAllowedScopes: ['chat', 'memory:read', 'forum:post'],
    ...options
  });

  return { mgr, init, challenge, proof, approval };
}

// 1. Level 1 完整流程（init→approval）
test('Level 1 握手完整流程（init→approval）', () => {
  const { approval } = runFullHandshake(SECURITY_LEVEL.LIGHT);
  assert.strictEqual(approval.type, 'handshake_approval');
  assert.strictEqual(approval.approved, true);
  assert.deepStrictEqual(approval.scopes_granted, ['chat', 'memory:read']);
  assert.ok(approval.session_id.startsWith('sess-'));
});

// 2. Level 2 完整流程（+complete → session）
test('Level 2 握手完整流程（+complete）', () => {
  const { mgr, proof, approval } = runFullHandshake(SECURITY_LEVEL.FULL);
  const result = mgr.processApproval(proof, approval, {
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  assert.strictEqual(result.approved, true);
  assert.ok(result.complete);
  assert.strictEqual(result.complete.type, 'handshake_complete');
  assert.strictEqual(result.complete.session_id, approval.session_id);
  assert.ok(result.complete.access_token);

  // callee 收尾建会话
  const done = mgr.processComplete(approval, result.complete);
  assert.strictEqual(done.session.caller_id, CALLER);
  assert.strictEqual(done.session.callee_id, CALLEE);
  assert.deepStrictEqual(done.session.scopes_granted, ['chat', 'memory:read']);
});

// 3. Level 1 caller 侧收尾建会话
test('Level 1 caller 直接建会话', () => {
  const { mgr, proof, approval } = runFullHandshake(SECURITY_LEVEL.LIGHT);
  const result = mgr.processApproval(proof, approval, {
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  assert.strictEqual(result.approved, true);
  assert.ok(result.session);
  assert.strictEqual(result.session.security_level, SECURITY_LEVEL.LIGHT);
});

// 4. Level 0 直接会话
test('Level 0 无握手直接会话', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.NONE
  });
  assert.ok(init.directSession);
  assert.strictEqual(init.directSession.security_level, SECURITY_LEVEL.NONE);
});

// 5. Level 3 需要用户实时确认
test('Level 3 用户拒绝时 approval denied', () => {
  const { approval } = runFullHandshake(SECURITY_LEVEL.USER_CONFIRM, {
    userConfirm: () => false
  });
  assert.strictEqual(approval.approved, false);
  assert.deepStrictEqual(approval.scopes_denied, [{ scope: '*', reason: 'user_denied_realtime' }]);
});

test('Level 3 用户确认后通过', () => {
  const { approval } = runFullHandshake(SECURITY_LEVEL.USER_CONFIRM, {
    userConfirm: () => true
  });
  assert.strictEqual(approval.approved, true);
});

// 6. caller AAT 无效拒绝
test('caller AAT 无效拒绝', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  init.caller_attestation = init.caller_attestation.split('.').slice(0, 2).join('.') + '.Zm9v'; // 篡改签名
  assert.throws(() => mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  }), (e) => e.code === 'caller_aat_invalid');
});

// 7. callee AAT 无效拒绝
test('callee AAT 无效拒绝', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  const challenge = mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  });
  challenge.callee_attestation = challenge.callee_attestation.split('.').slice(0, 2).join('.') + '.YmFk';
  assert.throws(() => mgr.processChallenge(init, challenge, {
    callerPrivateKey: callerKey.privateKey, callerAID, calleeAID,
    userPrivateKey: userKey.privateKey, userId: 'user-yilan@csb'
  }), (e) => e.code === 'callee_aat_invalid');
});

// 8. nonce 签名验证失败拒绝
test('sign_nonce_a 伪造拒绝', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  const challenge = mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  });
  // 篡改 sign_nonce_a（用 attacker 密钥重签）
  const attacker = aid.generateKeyPair('attacker');
  const { signNonce } = require('../lib/handshake/handshake');
  challenge.sign_nonce_a = signNonce(init.nonce_a, attacker.privateKey);
  assert.throws(() => mgr.processChallenge(init, challenge, {
    callerPrivateKey: callerKey.privateKey, callerAID, calleeAID,
    userPrivateKey: userKey.privateKey, userId: 'user-yilan@csb'
  }), (e) => e.code === 'challenge_bad_signature');
});

// 9. UAC 无效拒绝
test('UAC 无效拒绝', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  const challenge = mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  });
  const proof = mgr.processChallenge(init, challenge, {
    callerPrivateKey: callerKey.privateKey, callerAID, calleeAID,
    userPrivateKey: userKey.privateKey, userId: 'user-yilan@csb'
  });
  proof.user_auth_credential = proof.user_auth_credential.split('.').slice(0, 2).join('.') + '.YmFk';
  assert.throws(() => mgr.processProof(challenge, proof, {
    callerAID, userPublicKey: userKey.publicJwk, calleeAllowedScopes: ['chat']
  }), (e) => e.code === 'uac_invalid');
});

// 10. UAC scope 不足 → 权限交集拒绝
test('UAC scope 不足时 approval 部分拒绝', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat', 'admin'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  const challenge = mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat', 'admin']
  });
  const proof = mgr.processChallenge(init, challenge, {
    callerPrivateKey: callerKey.privateKey, callerAID, calleeAID,
    userPrivateKey: userKey.privateKey, userId: 'user-yilan@csb',
    uacScopes: ['chat'] // 用户只授权了 chat
  });
  const approval = mgr.processProof(challenge, proof, {
    callerAID, userPublicKey: userKey.publicJwk, calleeAllowedScopes: ['chat', 'admin']
  });
  assert.strictEqual(approval.approved, true);
  assert.deepStrictEqual(approval.scopes_granted, ['chat']);
  assert.deepStrictEqual(approval.scopes_denied, [{ scope: 'admin', reason: 'user_policy' }]);
});

// 11. 交集为空 → denied
test('交集为空时 approved=false', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['memory:write'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  const challenge = mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat'] // callee 不允许 memory:write
  });
  const proof = mgr.processChallenge(init, challenge, {
    callerPrivateKey: callerKey.privateKey, callerAID, calleeAID,
    userPrivateKey: userKey.privateKey, userId: 'user-yilan@csb'
  });
  const approval = mgr.processProof(challenge, proof, {
    callerAID, userPublicKey: userKey.publicJwk, calleeAllowedScopes: ['chat']
  });
  assert.strictEqual(approval.approved, false);
});

// 12. 信任等级限制
test('信任等级限制（minTrustLevel=L2 时 L0 拒绝）', () => {
  const { TrustLevelManager } = require('../lib/authz/trust-level');
  const trustManager = new TrustLevelManager();
  const mgr = new HandshakeManager({ trustManager });
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  const challenge = mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  });
  const proof = mgr.processChallenge(init, challenge, {
    callerPrivateKey: callerKey.privateKey, callerAID, calleeAID,
    userPrivateKey: userKey.privateKey, userId: 'user-yilan@csb'
  });
  const approval = mgr.processProof(challenge, proof, {
    callerAID, userPublicKey: userKey.publicJwk, calleeAllowedScopes: ['chat'],
    minTrustLevel: 'L2' // caller 是 L0
  });
  assert.strictEqual(approval.approved, false);
  assert.ok(approval.scopes_denied[0].reason.includes('trust_level'));
});

// 13. nonce 重放防护
test('nonce 重放拒绝', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  });
  // 重放同一个 init（nonce_a 已见）
  assert.throws(() => mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  }), (e) => e.code === 'nonce_replay');
});

// 14. session_id 不匹配拒绝
test('complete session_id 不匹配拒绝', () => {
  const { mgr, proof, approval } = runFullHandshake(SECURITY_LEVEL.FULL);
  const result = mgr.processApproval(proof, approval, {
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  result.complete.session_id = 'sess-evil';
  assert.throws(() => mgr.processComplete(approval, result.complete),
    (e) => e.code === 'session_mismatch');
});

// 15. 时间戳漂移拒绝
test('时间戳漂移 > 5 分钟拒绝', () => {
  const mgr = new HandshakeManager();
  const init = mgr.initiate({
    callerId: CALLER, calleeId: CALLEE,
    requestedScopes: ['chat'], securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: callerKey.privateKey, callerAID
  });
  init.timestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 分钟前
  assert.throws(() => mgr.processInit(init, {
    calleePrivateKey: calleeKey.privateKey, calleeAID, callerAID,
    calleeAllowedScopes: ['chat']
  }), (e) => e.code === 'time_drift');
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
