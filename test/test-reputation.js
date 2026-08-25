#!/usr/bin/env node
/**
 * test-reputation.js — 声誉模块测试（Layer 2, P2 补齐）
 */
const assert = require('assert');
const { ReputationStore, calcScore, decayScore, DEFAULT_WEIGHTS, SCORE_LEVELS } = require('../lib/authz/reputation');
const trust = require('../lib/authz/trust-level');

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

console.log('=== 声誉模块测试 ===\n');

// ---------- ReputationStore ----------
test('新 Agent 默认中性分 0.5', () => {
  const rs = new ReputationStore();
  assert.strictEqual(rs.getReputationScore('agent-x'), 0.5);
});

test('recordInteraction 正向累计', () => {
  const rs = new ReputationStore();
  rs.recordInteraction('agent-x', true);
  rs.recordInteraction('agent-x', true);
  rs.recordInteraction('agent-x', false);
  assert.strictEqual(rs.getReputationScore('agent-x'), 2 / 3);
});

test('getStats 返回完整统计', () => {
  const rs = new ReputationStore();
  rs.recordInteraction('agent-x', true);
  const stats = rs.getStats('agent-x');
  assert.strictEqual(stats.positive, 1);
  assert.strictEqual(stats.negative, 0);
  assert.strictEqual(stats.total, 1);
  assert.strictEqual(stats.historyCount, 1);
});

test('历史保留最近 50 条', () => {
  const rs = new ReputationStore();
  for (let i = 0; i < 60; i++) rs.recordInteraction('agent-x', true);
  assert.strictEqual(rs.getStats('agent-x').historyCount, 50);
});

test('24 小时内无衰减', () => {
  const rs = new ReputationStore();
  rs.recordInteraction('agent-x', true);
  assert.strictEqual(rs.getDecayedScore('agent-x'), 1);
});

test('衰减后最低 0.1', () => {
  const rs = new ReputationStore();
  rs.recordInteraction('agent-x', true, { timestamp: Date.now() - 100 * 24 * 3600 * 1000 });
  // 手动构造历史时间戳
  const record = rs.store.get('agent-x');
  record.history[0].timestamp = Date.now() - 100 * 24 * 3600 * 1000;
  const score = rs.getDecayedScore('agent-x');
  assert.ok(score >= 0.1 && score < 1);
});

test('cleanup 清理超 TTL 记录', () => {
  const rs = new ReputationStore({ ttl: 1000 });
  rs.recordInteraction('old-agent', true, { timestamp: Date.now() - 5000 });
  const record = rs.store.get('old-agent');
  record.history[0].timestamp = Date.now() - 5000;
  const removed = rs.cleanup();
  assert.ok(removed >= 1);
  assert.strictEqual(rs.store.has('old-agent'), false);
});

test('trust-level.js 仍可访问 ReputationStore（向后兼容）', () => {
  assert.strictEqual(typeof trust.ReputationStore, 'function');
  const rs = new trust.ReputationStore();
  rs.recordInteraction('agent-x', true);
  assert.strictEqual(rs.getReputationScore('agent-x'), 1);
});

// ---------- calcScore ----------
test('calcScore 权重计算（满分）', () => {
  const r = calcScore({ identity: 1, history: 1, audit: 1, community: 1 });
  assert.strictEqual(r.score, 1);
  assert.strictEqual(r.level, 'complete');
});

test('calcScore 中等分 → medium', () => {
  const r = calcScore({ identity: 0.6, history: 0.5, audit: 0.4, community: 0.5 });
  assert.strictEqual(r.level, 'medium');
});

test('calcScore 低分 → untrusted', () => {
  const r = calcScore({ identity: 0.1, history: 0.1, audit: 0.1, community: 0.1 });
  assert.strictEqual(r.level, 'untrusted');
  assert.strictEqual(r.default_perm, 'deny');
});

test('calcScore 自定义权重', () => {
  const r = calcScore({ identity: 1, history: 0, audit: 0, community: 0 }, { identity: 1, history: 0, audit: 0, community: 0 });
  assert.strictEqual(r.score, 1);
});

// ---------- decayScore ----------
test('decayScore 时间衰减', () => {
  const d = decayScore(1, 30);
  assert.ok(d < 1 && d >= 0.2);
});

test('decayScore 最低阈值', () => {
  const d = decayScore(1, 3650);
  assert.strictEqual(d, 0.2);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
