#!/usr/bin/env node
/**
 * test-scope-intersection.js — 权限交集计算测试
 * 协议: CSB-Security v1.0 §3.3
 */

const assert = require('assert');
const {
  computeScopeIntersection,
  canGrant,
  mergeDenials
} = require('../lib/authz/scope-intersection');

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

console.log('=== 权限交集测试 ===\n');

// 1. 全通过
test('三方都允许时全部授予', () => {
  const r = computeScopeIntersection(
    ['chat', 'memory:read'],
    ['chat', 'memory:read', 'forum:post'],
    ['chat', 'memory:read']
  );
  assert.deepStrictEqual(r.granted, ['chat', 'memory:read']);
  assert.deepStrictEqual(r.denied, []);
  assert.strictEqual(canGrant(r), true);
});

// 2. callee 策略拒绝
test('callee 策略拒绝部分 scope', () => {
  const r = computeScopeIntersection(
    ['chat', 'memory:write'],
    ['chat', 'memory:write'],
    ['chat'] // callee 不允许 memory:write
  );
  assert.deepStrictEqual(r.granted, ['chat']);
  assert.deepStrictEqual(r.denied, [{ scope: 'memory:write', reason: 'callee_policy' }]);
});

// 3. 用户 scope 缺失拒绝
test('用户授权缺失拒绝', () => {
  const r = computeScopeIntersection(
    ['chat', 'admin'],
    ['chat'], // 用户没授权 admin
    ['chat', 'admin']
  );
  assert.deepStrictEqual(r.granted, ['chat']);
  assert.deepStrictEqual(r.denied, [{ scope: 'admin', reason: 'user_policy' }]);
});

// 4. 交集为空不可发放
test('交集为空不可发放', () => {
  const r = computeScopeIntersection(
    ['memory:write'],
    ['chat'],
    ['chat', 'memory:write']
  );
  assert.deepStrictEqual(r.granted, []);
  assert.strictEqual(canGrant(r), false);
});

// 5. 双方同时拒绝合并原因
test('双方都拒绝时合并原因', () => {
  const r = computeScopeIntersection(
    ['delegate'],
    ['chat'],       // 用户没授权 delegate
    ['chat', 'forum:post'] // callee 也不允许 delegate
  );
  assert.deepStrictEqual(r.granted, []);
  assert.strictEqual(r.denied[0].reason, 'user_policy');
});

// 6. mergeDenials 去重合并
test('mergeDenials 合并去重', () => {
  const merged = mergeDenials(
    [{ scope: 'a', reason: 'user_policy' }],
    [{ scope: 'a', reason: 'callee_policy' }, { scope: 'b', reason: 'callee_policy' }]
  );
  assert.strictEqual(merged.length, 2);
  const a = merged.find(d => d.scope === 'a');
  assert.ok(a.reason.includes('user_policy'));
  assert.ok(a.reason.includes('callee_policy'));
});

// 7. 空请求
test('空请求返回空结果', () => {
  const r = computeScopeIntersection([], ['chat'], ['chat']);
  assert.deepStrictEqual(r.granted, []);
  assert.deepStrictEqual(r.denied, []);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
