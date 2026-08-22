#!/usr/bin/env node
/**
 * test-anomaly-detector.js — 异常检测规则引擎测试
 * 协议: CSB-Security v1.0 §5.3 异常模式检测
 */

const assert = require('assert');
const { AnomalyDetector, DEFAULT_RULES } = require('../lib/defense/anomaly-detector');

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

console.log('=== 异常检测测试 ===\n');

// 1. 规则①: 连续失败触发暂停 + 告警
test('规则① 连续失败 10 次 → 暂停 + 告警', () => {
  const detector = new AnomalyDetector();
  let alerts = [];
  detector.onAlert = a => alerts.push(a);

  for (let i = 0; i < 10; i++) {
    detector.recordFailure('evil@1.2.3.4:3100', '10.0.0.1');
  }
  assert.strictEqual(detector.isSuspended('evil@1.2.3.4:3100'), true);
  assert.ok(alerts.some(a => a.rule === 'rapid_failures'));
  const alert = alerts.find(a => a.rule === 'rapid_failures');
  assert.strictEqual(alert.severity, 'high');
  assert.strictEqual(alert.count, 10);
});

// 2. 成功请求重置失败计数
test('成功请求重置失败计数（9 次失败 + 1 次成功不暂停）', () => {
  const detector = new AnomalyDetector();
  for (let i = 0; i < 9; i++) detector.recordFailure('ok@1.2.3.4:3100', '10.0.0.2');
  detector.recordSuccess('ok@1.2.3.4:3100');
  // 重置后：再来 9 次失败不暂停（若未重置，累计 18 次早已触发）
  for (let i = 0; i < 9; i++) detector.recordFailure('ok@1.2.3.4:3100', '10.0.0.2');
  assert.strictEqual(detector.isSuspended('ok@1.2.3.4:3100'), false);
  assert.strictEqual(detector.suspendedUntil('ok@1.2.3.4:3100'), 0);
});

// 3. 规则②: 同一 IP 多 Agent 可疑
test('规则② 同一 IP 5+ Agent → 可疑标记', () => {
  const detector = new AnomalyDetector();
  let suspicious = false;
  detector.onAlert = a => { if (a.rule === 'many_agents_single_ip') suspicious = true; };

  for (let i = 0; i < 5; i++) {
    detector.recordFailure(`agent-${i}@1.2.3.4:3100`, '10.0.0.66');
  }
  assert.strictEqual(suspicious, true);
  assert.ok(detector.suspiciousIps().includes('10.0.0.66'));
  const stats = detector.stats();
  assert.ok(stats.suspiciousIps.includes('10.0.0.66'));
});

// 4. 规则③: 高频 AID 注册
test('规则③ 高频 AID 注册 5 次/min → 告警', () => {
  const detector = new AnomalyDetector();
  let triggered = false;
  detector.onAlert = a => { if (a.rule === 'rapid_aid_registration') triggered = true; };

  for (let i = 0; i < 5; i++) {
    detector.recordAidRegistration('spammer@1.2.3.4:3100', '10.0.0.3', { aid: `aid-${i}` });
  }
  assert.strictEqual(triggered, true);
  const alert = detector.alerts.find(a => a.rule === 'rapid_aid_registration');
  assert.strictEqual(alert.severity, 'high');
});

// 5. 规则④: 高频密钥轮换
test('规则④ 密钥轮换 3 次/min → 告警', () => {
  const detector = new AnomalyDetector();
  for (let i = 0; i < 3; i++) {
    detector.recordKeyRotation('flappy@1.2.3.4:3100', '10.0.0.4', { keyId: `k-${i}` });
  }
  const alert = detector.alerts.find(a => a.rule === 'rapid_key_rotation');
  assert.ok(alert, '应触发密钥轮换告警');
  assert.strictEqual(alert.severity, 'medium');
});

// 6. 规则⑤: 审计篡改单次即触发 critical
test('规则⑤ 审计篡改单次 → critical 告警', () => {
  const detector = new AnomalyDetector();
  detector.recordAuditTamper('ruolan@172.28.0.214:3100', 'block 42 prev_hash mismatch');
  const alert = detector.alerts.find(a => a.rule === 'audit_tamper');
  assert.ok(alert, '应触发篡改告警');
  assert.strictEqual(alert.severity, 'critical');
  assert.strictEqual(alert.detail, 'block 42 prev_hash mismatch');
});

// 7. 滑动窗口过期后计数重置
test('窗口过期后计数重置', () => {
  let now = 1000000;
  const detector = new AnomalyDetector({ now: () => now });
  for (let i = 0; i < 9; i++) detector.recordFailure('a@1.2.3.4:3100', '10.0.0.5');
  assert.strictEqual(detector.isSuspended('a@1.2.3.4:3100'), false);
  now += 61000; // 61 秒后窗口过期
  for (let i = 0; i < 9; i++) detector.recordFailure('a@1.2.3.4:3100', '10.0.0.5');
  assert.strictEqual(detector.isSuspended('a@1.2.3.4:3100'), false, '窗口过期后应从零计数');
  detector.recordFailure('a@1.2.3.4:3100', '10.0.0.5'); // 第 10 次（新窗口内）
  assert.strictEqual(detector.isSuspended('a@1.2.3.4:3100'), true);
});

// 8. 自定义规则阈值
test('自定义规则阈值覆盖', () => {
  const detector = new AnomalyDetector({
    rules: { rapid_failures: { threshold: 3, windowMs: 60000, suspendMs: 5000 } }
  });
  for (let i = 0; i < 3; i++) detector.recordFailure('fast@1.2.3.4:3100', '10.0.0.6');
  assert.strictEqual(detector.isSuspended('fast@1.2.3.4:3100'), true);
  assert.strictEqual(DEFAULT_RULES.rapid_failures.threshold, 10, '默认规则不应被污染');
});

// 9. onAlert 回调收到结构化告警
test('onAlert 回调收到结构化告警', () => {
  let received = null;
  const detector = new AnomalyDetector({ onAlert: a => { received = a; } });
  detector.recordAuditTamper('x@1.2.3.4:3100', 'tamper');
  assert.ok(received, '回调应被调用');
  assert.strictEqual(received.rule, 'audit_tamper');
  assert.strictEqual(received.severity, 'critical');
  assert.ok(typeof received.timestamp === 'number');
});

// 10. 触发后窗口清空，避免窗口内重复告警
test('触发后窗口清空（不重复告警）', () => {
  const detector = new AnomalyDetector({ rules: { rapid_failures: { threshold: 5 } } });
  for (let i = 0; i < 5; i++) detector.recordFailure('rep@1.2.3.4:3100', '10.0.0.7');
  const countAfterTrigger = detector.alerts.filter(a => a.rule === 'rapid_failures').length;
  // 再补 5 次失败（同窗口内），不应重复触发
  for (let i = 0; i < 5; i++) detector.recordFailure('rep@1.2.3.4:3100', '10.0.0.7');
  const countAfterMore = detector.alerts.filter(a => a.rule === 'rapid_failures').length;
  assert.strictEqual(countAfterTrigger, 1);
  assert.strictEqual(countAfterMore, 1, '窗口内不应重复触发');
});

// 11. unsuspend 手动解除
test('unsuspend 手动解除暂停', () => {
  const detector = new AnomalyDetector();
  for (let i = 0; i < 10; i++) detector.recordFailure('u@1.2.3.4:3100', '10.0.0.8');
  assert.strictEqual(detector.isSuspended('u@1.2.3.4:3100'), true);
  detector.unsuspend('u@1.2.3.4:3100');
  assert.strictEqual(detector.isSuspended('u@1.2.3.4:3100'), false);
});

// 12. suspendFn 注入动作
test('suspendFn 注入暂停动作', () => {
  let injected = null;
  const detector = new AnomalyDetector({ suspendFn: (agentId, until) => { injected = { agentId, until }; } });
  for (let i = 0; i < 10; i++) detector.recordFailure('inj@1.2.3.4:3100', '10.0.0.9');
  assert.ok(injected, '注入函数应被调用');
  assert.strictEqual(injected.agentId, 'inj@1.2.3.4:3100');
  assert.ok(injected.until > 0);
});

// 13. 事件统计 + 暂停自动过期
test('暂停到期自动解除', () => {
  let now = 2000000;
  const detector = new AnomalyDetector({ now: () => now, rules: { rapid_failures: { suspendMs: 5000 } } });
  for (let i = 0; i < 10; i++) detector.recordFailure('exp@1.2.3.4:3100', '10.0.0.10');
  assert.strictEqual(detector.isSuspended('exp@1.2.3.4:3100'), true);
  now += 6000;
  assert.strictEqual(detector.isSuspended('exp@1.2.3.4:3100'), false);
  assert.strictEqual(detector.suspendedUntil('exp@1.2.3.4:3100'), 0);
});

// 14. 默认规则符合协议
test('默认规则配置正确', () => {
  assert.strictEqual(DEFAULT_RULES.rapid_failures.threshold, 10);
  assert.strictEqual(DEFAULT_RULES.many_agents_single_ip.threshold, 5);
  assert.strictEqual(DEFAULT_RULES.rapid_aid_registration.threshold, 5);
  assert.strictEqual(DEFAULT_RULES.rapid_key_rotation.threshold, 3);
  assert.strictEqual(DEFAULT_RULES.audit_tamper.severity, 'critical');
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
