#!/usr/bin/env node
/**
 * test-rate-limiter.js — 速率限制 + 异常检测测试
 * 协议: CSB-Security v1.0 §5.3
 */

const assert = require('assert');
const { RateLimiter, DEFAULT_LIMITS } = require('../lib/defense/rate-limiter');

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

console.log('=== 速率限制测试 ===\n');

// 1. 单 Agent 限流（60/min）
test('单 Agent 限流（60/min）', () => {
  const limiter = new RateLimiter();
  for (let i = 0; i < 60; i++) {
    const r = limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' });
    assert.strictEqual(r.allowed, true, `第 ${i + 1} 次应放行`);
  }
  const over = limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' });
  assert.strictEqual(over.allowed, false);
  assert.strictEqual(over.reason, 'agent_rate_limited');
  assert.ok(over.retryAfterMs > 0);
});

// 2. 不同 Agent 互不影响
test('不同 Agent 互不影响', () => {
  const limiter = new RateLimiter();
  for (let i = 0; i < 60; i++) limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' });
  const other = limiter.check({ agentId: 'b@1.2.3.4:3100', ip: '10.0.0.1' });
  assert.strictEqual(other.allowed, true);
});

// 3. 单 IP 限流（200/min）
test('单 IP 限流（200/min）', () => {
  const limiter = new RateLimiter({ limits: { agent: 10000 } }); // 放大 agent 限制
  for (let i = 0; i < 200; i++) {
    limiter.check({ agentId: `agent-${i % 10}@1.2.3.4:3100`, ip: '10.0.0.1' });
  }
  const over = limiter.check({ agentId: 'another@1.2.3.4:3100', ip: '10.0.0.1' });
  assert.strictEqual(over.allowed, false);
  assert.strictEqual(over.reason, 'ip_rate_limited');
});

// 4. 全局限流（1000/min）
test('全局限流（1000/min）', () => {
  const limiter = new RateLimiter({ limits: { agent: 100000, ip: 100000 } });
  for (let i = 0; i < 1000; i++) {
    limiter.check({ agentId: `agent-${i}@1.2.3.4:3100`, ip: `10.0.${i % 100}.1` });
  }
  const over = limiter.check({ agentId: 'last@1.2.3.4:3100', ip: '10.9.9.9' });
  assert.strictEqual(over.allowed, false);
  assert.strictEqual(over.reason, 'global_rate_limited');
});

// 5. 滑动窗口：窗口过期后恢复
test('窗口过期后恢复', () => {
  let now = 1000000;
  const limiter = new RateLimiter({ limits: { agent: 3 }, windowMs: 60000, now: () => now });
  limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' });
  limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' });
  limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' });
  assert.strictEqual(limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' }).allowed, false);
  now += 61000; // 61 秒后
  assert.strictEqual(limiter.check({ agentId: 'a@1.2.3.4:3100', ip: '10.0.0.1' }).allowed, true);
});

// 6. 连续失败自动暂停
test('连续失败自动暂停（10 次）', () => {
  const limiter = new RateLimiter();
  let suspended = false;
  for (let i = 0; i < 10; i++) {
    const r = limiter.recordFailure('evil@1.2.3.4:3100');
    if (r.suspended) suspended = true;
  }
  assert.strictEqual(suspended, true);
  assert.strictEqual(limiter.isSuspended('evil@1.2.3.4:3100'), true);
  // 暂停期间请求被拒
  const r = limiter.check({ agentId: 'evil@1.2.3.4:3100', ip: '10.0.0.1' });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, 'agent_suspended');
});

// 7. 成功重置失败计数
test('成功请求重置失败计数', () => {
  const limiter = new RateLimiter();
  for (let i = 0; i < 9; i++) limiter.recordFailure('ok@1.2.3.4:3100');
  limiter.recordSuccess('ok@1.2.3.4:3100');
  // 重置后：再来 9 次失败不暂停（若未重置，累计 18 次早已暂停）
  for (let i = 0; i < 9; i++) {
    const r = limiter.recordFailure('ok@1.2.3.4:3100');
    assert.strictEqual(r.suspended, false, `第 ${i + 1} 次不应暂停`);
  }
  assert.strictEqual(limiter.isSuspended('ok@1.2.3.4:3100'), false);
});

// 8. 同一 IP 多 Agent 可疑标记
test('同一 IP 多 Agent 标记可疑', () => {
  const limiter = new RateLimiter({ limits: { agent: 1000, ip: 1000, global: 10000 } });
  let suspicious = false;
  for (let i = 0; i < 6; i++) {
    const r = limiter.check({ agentId: `agent-${i}@1.2.3.4:3100`, ip: '10.0.0.66' });
    if (r.suspicious) suspicious = true;
  }
  assert.strictEqual(suspicious, true);
  const stats = limiter.stats();
  assert.ok(stats.suspiciousIps.includes('10.0.0.66'));
});

// 9. 默认限制符合协议
test('默认限制符合协议 §5.3', () => {
  assert.strictEqual(DEFAULT_LIMITS.agent, 60);
  assert.strictEqual(DEFAULT_LIMITS.ip, 200);
  assert.strictEqual(DEFAULT_LIMITS.global, 1000);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
