#!/usr/bin/env node
/**
 * test-replay-guard.js — 重放防护测试
 * 协议: CSB-Security v1.0 §5.1
 */

const assert = require('assert');
const { ReplayGuard } = require('../lib/defense/replay-guard');

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

console.log('=== 重放防护测试 ===\n');

// 1. nonce 首次通过，重放拒绝
test('nonce 重放拒绝', () => {
  const guard = new ReplayGuard();
  assert.strictEqual(guard.checkNonce('nonce-1').allowed, true);
  const replay = guard.checkNonce('nonce-1');
  assert.strictEqual(replay.allowed, false);
  assert.strictEqual(replay.error, 'nonce_replay');
});

// 2. jti 重放拒绝
test('jti 重放拒绝', () => {
  const guard = new ReplayGuard();
  assert.strictEqual(guard.checkJti('jti-abc').allowed, true);
  assert.strictEqual(guard.checkJti('jti-abc').allowed, false);
});

// 3. 时间戳漂移拒绝
test('时间戳漂移 > 5 分钟拒绝', () => {
  const guard = new ReplayGuard();
  const old = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const r = guard.checkTimestamp(old);
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.error, 'time_drift');
  // 正常时间戳通过
  assert.strictEqual(guard.checkTimestamp(new Date().toISOString()).allowed, true);
});

// 4. 序列号单调递增
test('序列号单调递增检测', () => {
  const guard = new ReplayGuard();
  assert.strictEqual(guard.checkSequence('agent-a', 1).allowed, true);
  assert.strictEqual(guard.checkSequence('agent-a', 2).allowed, true);
  const replay = guard.checkSequence('agent-a', 2);
  assert.strictEqual(replay.allowed, false);
  assert.strictEqual(replay.error, 'sequence_replay');
  assert.strictEqual(guard.checkSequence('agent-a', 1).allowed, false); // 倒退
});

// 5. TTL 过期后 nonce 可复用
test('TTL 过期后 nonce 释放', () => {
  let now = 1000000;
  const guard = new ReplayGuard({ ttlMs: 60000, now: () => now });
  guard.checkNonce('n1');
  now += 61000; // 61 秒后
  assert.strictEqual(guard.checkNonce('n1').allowed, true);
});

// 6. cleanup 清理过期
test('cleanup 清理过期条目', () => {
  let now = 1000000;
  const guard = new ReplayGuard({ ttlMs: 60000, now: () => now });
  guard.checkNonce('n1');
  guard.checkJti('j1');
  assert.strictEqual(guard.stats().nonces, 1);
  now += 61000;
  guard.cleanup();
  assert.strictEqual(guard.stats().nonces, 0);
  assert.strictEqual(guard.stats().jtis, 0);
});

// 7. 缺字段拒绝
test('缺失 nonce/jti 拒绝', () => {
  const guard = new ReplayGuard();
  assert.strictEqual(guard.checkNonce(null).allowed, false);
  assert.strictEqual(guard.checkNonce('').allowed, false);
  assert.strictEqual(guard.checkJti(null).allowed, false);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
