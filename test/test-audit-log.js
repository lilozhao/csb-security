#!/usr/bin/env node
/**
 * test-audit-log.js — 审计日志（哈希链）测试
 * 协议: CSB-Security v1.0 §6
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { AuditLog } = require('../lib/audit/audit-log');
const { AuditQuery } = require('../lib/audit/audit-query');
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

console.log('=== 审计日志测试 ===\n');

const keyPair = aid.generateKeyPair('audit-key');

function makeEntry(overrides = {}) {
  return {
    event_type: 'handshake_complete',
    caller_id: 'ruolan@172.28.0.214:3100',
    callee_id: 'axuan@172.28.0.5:3100',
    user_id: 'user-yilan@csb',
    scopes_requested: ['chat', 'memory:read'],
    scopes_granted: ['chat'],
    scopes_denied: [{ scope: 'memory:read', reason: 'callee_policy' }],
    trust_level: 'L2',
    session_id: 'sess-abc123',
    ip_address: '172.28.0.214',
    result: 'success',
    ...overrides
  };
}

// 1. 追加记录（哈希链 + 自增 seq）
test('追加记录形成哈希链', () => {
  const log = new AuditLog();
  const r1 = log.append(makeEntry());
  const r2 = log.append(makeEntry({ event_type: 'message_sent' }));
  assert.strictEqual(r1.seq, 1);
  assert.strictEqual(r2.seq, 2);
  assert.strictEqual(r1.prev_hash, 'GENESIS');
  assert.strictEqual(r2.prev_hash, r1.hash);
  assert.ok(r1.hash && r1.hash.length === 64);
});

// 2. 哈希链校验通过
test('哈希链完整性校验通过', () => {
  const log = new AuditLog();
  for (let i = 0; i < 5; i++) log.append(makeEntry({ event_type: `event_${i}` }));
  const result = log.verifyChain();
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.count, 5);
});

// 3. 篡改检出（改中间一条）
test('篡改中间记录必检出', () => {
  const log = new AuditLog();
  log.append(makeEntry());
  log.append(makeEntry());
  log.append(makeEntry());
  // 篡改第二条的 result
  log.entries[1].result = 'hacked';
  const result = log.verifyChain();
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.brokenAt, 1);
  assert.strictEqual(result.reason, 'entry_tampered');
});

// 4. 哈希链断裂检出（改 prev_hash）
test('哈希链断裂必检出', () => {
  const log = new AuditLog();
  log.append(makeEntry());
  log.append(makeEntry());
  log.entries[1].prev_hash = 'deadbeef';
  const result = log.verifyChain();
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.reason, 'hash_chain_broken');
});

// 5. 签名审计（Ed25519 签名每条记录）
test('签名审计 + 签名篡改检出', () => {
  const log = new AuditLog({
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey
  });
  log.append(makeEntry());
  log.append(makeEntry());
  const result = log.verifyChain();
  assert.strictEqual(result.valid, true);
  // 篡改签名
  log.entries[1].signature = Buffer.from('bad').toString('base64');
  const tampered = log.verifyChain();
  assert.strictEqual(tampered.valid, false);
  assert.strictEqual(tampered.reason, 'signature_invalid');
});

// 6. 查询：按 Agent
test('按 Agent 查询', () => {
  const log = new AuditLog();
  log.append(makeEntry({ caller_id: 'a@1.2.3.4:3100' }));
  log.append(makeEntry({ caller_id: 'b@1.2.3.4:3100' }));
  const results = log.query({ agentId: 'a@1.2.3.4:3100' });
  assert.strictEqual(results.length, 1);
});

// 7. 查询：按事件类型 / 时间范围 / scope
test('按事件类型/时间范围/scope 查询', () => {
  const log = new AuditLog();
  log.append(makeEntry({ event_type: 'handshake_complete' }));
  log.append(makeEntry({ event_type: 'message_sent', scopes_granted: ['chat'] }));
  const byEvent = log.query({ eventType: 'message_sent' });
  assert.strictEqual(byEvent.length, 1);
  const byScope = log.query({ scope: 'chat' });
  assert.strictEqual(byScope.length, 2);
  const byTime = log.query({ from: new Date(Date.now() - 1000).toISOString() });
  assert.strictEqual(byTime.length, 2);
});

// 8. AuditQuery 便捷查询 + agentTimeline
test('AuditQuery agentTimeline 与 securitySummary', () => {
  const log = new AuditLog();
  log.append(makeEntry({ caller_id: 'ruolan@1.2.3.4:3100' }));
  log.append(makeEntry({ caller_id: 'ruolan@1.2.3.4:3100', result: 'failed' }));
  log.append(makeEntry({ caller_id: 'other@1.2.3.4:3100' }));
  const q = new AuditQuery(log);
  const timeline = q.agentTimeline('ruolan@1.2.3.4:3100');
  assert.strictEqual(timeline.length, 2);
  assert.strictEqual(timeline[0].direction, 'outbound');
  const summary = q.securitySummary('ruolan@1.2.3.4:3100');
  assert.strictEqual(summary.failed, 1);
});

// 9. 文件落盘模式（追加 + 重载）
test('文件落盘模式：重载后链仍有效', () => {
  const logPath = path.join(os.tmpdir(), `csb-audit-${Date.now()}.log`);
  const log = new AuditLog({ logPath });
  log.append(makeEntry());
  log.append(makeEntry());

  // 重新加载
  const reloaded = new AuditLog({ logPath });
  assert.strictEqual(reloaded.entries.length, 2);
  assert.strictEqual(reloaded.verifyChain().valid, true);
  fs.unlinkSync(logPath);
});

// 10. summary 统计
test('summary 统计', () => {
  const log = new AuditLog();
  log.append(makeEntry());
  log.append(makeEntry({ result: 'failed' }));
  const s = log.summary();
  assert.strictEqual(s.total, 2);
  assert.strictEqual(s.byResult.success, 1);
  assert.strictEqual(s.byResult.failed, 1);
  assert.strictEqual(s.chainValid, true);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
