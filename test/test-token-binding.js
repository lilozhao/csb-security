#!/usr/bin/env node
/**
 * test-token-binding.js — Token 绑定测试
 * 协议: CSB-Security v1.0 §4.3
 */

const assert = require('assert');
const { bindToken, verifyBinding, createBoundToken } = require('../lib/transport/token-binding');
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

console.log('=== Token 绑定测试 ===\n');

const BINDING = {
  callerId: 'ruolan@172.28.0.214:3100',
  userId: 'user-yilan@csb',
  calleeId: 'axuan@172.28.0.5:3100',
  scopes: ['chat', 'memory:read']
};

// 1. 绑定标识确定性
test('绑定标识确定性（同元组同结果）', () => {
  const b1 = bindToken(BINDING);
  const b2 = bindToken({ ...BINDING });
  assert.strictEqual(b1, b2);
});

// 2. 匹配验证通过
test('匹配元组验证通过', () => {
  const token = bindToken(BINDING);
  assert.strictEqual(verifyBinding(token, BINDING).valid, true);
});

// 3. caller 不同拒绝（Token 不能被别的 Agent 用）
test('caller 不同拒绝', () => {
  const token = bindToken(BINDING);
  const r = verifyBinding(token, { ...BINDING, callerId: 'axuan@172.28.0.5:3100' });
  assert.strictEqual(r.valid, false);
});

// 4. callee 不同拒绝
test('callee 不同拒绝', () => {
  const token = bindToken(BINDING);
  const r = verifyBinding(token, { ...BINDING, calleeId: 'jeason@172.28.0.6:3300' });
  assert.strictEqual(r.valid, false);
});

// 5. user 不同拒绝（Token 不能被别的用户用）
test('user 不同拒绝', () => {
  const token = bindToken(BINDING);
  const r = verifyBinding(token, { ...BINDING, userId: 'user-other@csb' });
  assert.strictEqual(r.valid, false);
});

// 6. scopes 不同拒绝
test('scopes 不同拒绝', () => {
  const token = bindToken(BINDING);
  const r = verifyBinding(token, { ...BINDING, scopes: ['chat', 'forum:post'] });
  assert.strictEqual(r.valid, false);
});

// 7. scopes 顺序无关（排序规范化）
test('scopes 顺序无关', () => {
  const t1 = bindToken({ ...BINDING, scopes: ['chat', 'memory:read'] });
  const t2 = bindToken({ ...BINDING, scopes: ['memory:read', 'chat'] });
  assert.strictEqual(t1, t2);
});

// 8. createBoundToken 含元数据
test('createBoundToken 含绑定元数据', () => {
  const t = createBoundToken(BINDING);
  assert.ok(t.binding);
  assert.strictEqual(t.bound_to.caller_id, BINDING.callerId);
  assert.deepStrictEqual(t.bound_to.scopes, ['chat', 'memory:read']);
});

// 9. 必填字段校验
test('缺少必填字段拒绝', () => {
  assert.throws(() => bindToken({ callerId: 'a', calleeId: 'b' }), /required/);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
