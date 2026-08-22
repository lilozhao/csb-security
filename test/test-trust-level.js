#!/usr/bin/env node
/**
 * test-trust-level.js — 信任等级管理测试（收编自 A2A-010 trust-manager.js）
 * 协议: CSB-Security v1.0 §3.4
 */

const assert = require('assert');
const {
  TRUST_LEVELS,
  TrustLevelManager,
  TrustChainVerifier,
  WoTCertifier,
  ReputationStore
} = require('../lib/authz/trust-level');

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

console.log('=== 信任等级测试 ===\n');

// 1. 初始等级 L0
test('新 Agent 默认 L0', () => {
  const mgr = new TrustLevelManager();
  const record = mgr.getTrustLevel('new-agent@1.2.3.4:3100');
  assert.strictEqual(record.trustLevel, 'L0');
});

// 2. L0→L1 需身份验证
test('L0→L1 需要身份验证', () => {
  const mgr = new TrustLevelManager();
  const r1 = mgr.upgrade('a@1.2.3.4:3100', 'L1', {});
  assert.strictEqual(r1.success, false);
  assert.ok(r1.error.includes('identity'));
  const r2 = mgr.upgrade('a@1.2.3.4:3100', 'L1', { identityVerified: true });
  assert.strictEqual(r2.success, true);
  assert.strictEqual(r2.newLevel, 'L1');
});

// 3. 不能跳级
test('不能跳级（L0→L2 拒绝）', () => {
  const mgr = new TrustLevelManager();
  const r = mgr.upgrade('b@1.2.3.4:3100', 'L2', { identityVerified: true });
  assert.strictEqual(r.success, false);
  assert.ok(r.error.includes('skip'));
});

// 4. L1→L2 需 10 次正向无负向（协议规则）
test('L1→L2 需 ≥10 次正向且无负向', () => {
  const mgr = new TrustLevelManager();
  const id = 'c@1.2.3.4:3100';
  mgr.upgrade(id, 'L1', { identityVerified: true });
  // 9 次正向 → 失败
  for (let i = 0; i < 9; i++) mgr.recordInteraction(id, true);
  const r1 = mgr.upgrade(id, 'L2', {});
  assert.strictEqual(r1.success, false);
  // 第 10 次正向 → 成功
  mgr.recordInteraction(id, true);
  const r2 = mgr.upgrade(id, 'L2', {});
  assert.strictEqual(r2.success, true);
});

test('L1→L2 有负向记录拒绝', () => {
  const mgr = new TrustLevelManager();
  const id = 'd@1.2.3.4:3100';
  mgr.upgrade(id, 'L1', { identityVerified: true });
  for (let i = 0; i < 10; i++) mgr.recordInteraction(id, true);
  mgr.recordInteraction(id, false); // 1 次负向
  const r = mgr.upgrade(id, 'L2', {});
  assert.strictEqual(r.success, false);
});

// 5. L2→L3 需用户授权 + 声誉 ≥0.9（协议规则）
test('L2→L3 需要用户授权', () => {
  const mgr = new TrustLevelManager();
  const id = 'e@1.2.3.4:3100';
  mgr.upgrade(id, 'L1', { identityVerified: true });
  for (let i = 0; i < 10; i++) mgr.recordInteraction(id, true);
  mgr.upgrade(id, 'L2', {});
  const r = mgr.upgrade(id, 'L3', {});
  assert.strictEqual(r.success, false);
  assert.ok(r.error.includes('user authorization'));
});

test('L2→L3 声誉不足拒绝', () => {
  const mgr = new TrustLevelManager();
  const id = 'f@1.2.3.4:3100';
  mgr.upgrade(id, 'L1', { identityVerified: true });
  for (let i = 0; i < 10; i++) mgr.recordInteraction(id, true);
  mgr.upgrade(id, 'L2', {}); // 先升到 L2（10 正向 0 负向）
  mgr.recordInteraction(id, false);
  mgr.recordInteraction(id, false); // 拉低声誉到 10/12 < 0.9
  const r = mgr.upgrade(id, 'L3', { userAuthorized: true });
  assert.strictEqual(r.success, false);
  assert.ok(r.error.includes('reputation'));
});

test('L2→L3 用户授权 + 高声誉成功', () => {
  const mgr = new TrustLevelManager();
  const id = 'g@1.2.3.4:3100';
  mgr.upgrade(id, 'L1', { identityVerified: true });
  for (let i = 0; i < 10; i++) mgr.recordInteraction(id, true);
  mgr.upgrade(id, 'L2', {});
  const r = mgr.upgrade(id, 'L3', { userAuthorized: true });
  assert.strictEqual(r.success, true);
  assert.strictEqual(r.newLevel, 'L3');
});

// 6. 降级
test('降级到更低等级', () => {
  const mgr = new TrustLevelManager();
  const id = 'h@1.2.3.4:3100';
  mgr.upgrade(id, 'L1', { identityVerified: true });
  const r = mgr.downgrade(id, 'L0', 'misbehavior');
  assert.strictEqual(r.success, true);
  assert.strictEqual(mgr.getTrustLevel(id).trustLevel, 'L0');
});

// 7. 权限映射（协议 §3.4）
test('权限映射符合协议', () => {
  assert.deepStrictEqual(TRUST_LEVELS.L0.permissions, ['chat']);
  assert.ok(TRUST_LEVELS.L1.permissions.includes('memory:read'));
  assert.ok(TRUST_LEVELS.L2.permissions.includes('delegate'));
  assert.deepStrictEqual(TRUST_LEVELS.L3.permissions, ['*']);
  const mgr = new TrustLevelManager();
  assert.strictEqual(mgr.hasPermission('L2', 'forum:post'), true);
  assert.strictEqual(mgr.hasPermission('L1', 'forum:post'), false);
  assert.strictEqual(mgr.hasPermission('L3', 'anything'), true); // 通配
});

// 8. 声誉衰减
test('声誉衰减（24h 后每 24h -0.05）', () => {
  const store = new ReputationStore();
  store.recordInteraction('i@1.2.3.4:3100', true);
  const now = Date.now();
  // 模拟 3 天前最后一次交互
  const record = store.store.get('i@1.2.3.4:3100');
  record.history[0].timestamp = now - 3 * 24 * 60 * 60 * 1000;
  const decayed = store.getDecayedScore('i@1.2.3.4:3100');
  assert.strictEqual(decayed, 0.85); // 1.0 - 3*0.05 = 0.85
});

// 9. 信任链验证
test('信任链直接信任与传递衰减', () => {
  const mgr = new TrustLevelManager();
  const alice = 'alice@1.2.3.4:3100';
  const bob = 'bob@1.2.3.4:3100';
  mgr.upgrade(bob, 'L1', { identityVerified: true });
  const verifier = new TrustChainVerifier(mgr);
  const direct = verifier.verifyChain(alice, bob, 'L1');
  assert.strictEqual(direct.valid, true);
  assert.strictEqual(direct.reason, 'direct_trust');
});

// 10. WoT 交叉见证
test('WoT 见证签名（见证人需 ≥L1）', () => {
  const mgr = new TrustLevelManager();
  const witness = 'w@1.2.3.4:3100';
  const target = 't@1.2.3.4:3100';
  const wot = new WoTCertifier(mgr);
  // 见证人 L0 → 拒绝
  const r1 = wot.addWitnessSignature({ witnessId: witness, targetAgentId: target });
  assert.strictEqual(r1.success, false);
  // 见证人升到 L1 → 成功
  mgr.upgrade(witness, 'L1', { identityVerified: true });
  const r2 = wot.addWitnessSignature({ witnessId: witness, targetAgentId: target });
  assert.strictEqual(r2.success, true);
  assert.strictEqual(r2.witnessCount, 1);
});

// 11. 重复见证检测（原实现 detectLoop 语义：target 已被 witness 见证过则拒绝）
test('重复见证被拒绝', () => {
  const mgr = new TrustLevelManager();
  const a = 'a@1.2.3.4:3100';
  const b = 'b@1.2.3.4:3100';
  mgr.upgrade(a, 'L1', { identityVerified: true });
  mgr.upgrade(b, 'L1', { identityVerified: true });
  const wot = new WoTCertifier(mgr);
  const r1 = wot.addWitnessSignature({ witnessId: a, targetAgentId: b });
  assert.strictEqual(r1.success, true);
  // a 再次见证 b → 环路/重复见证拒绝
  const r2 = wot.addWitnessSignature({ witnessId: a, targetAgentId: b });
  assert.strictEqual(r2.success, false);
  assert.ok(r2.error.includes('loop'));
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
