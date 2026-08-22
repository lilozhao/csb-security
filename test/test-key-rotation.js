#!/usr/bin/env node
/**
 * test-key-rotation.js — 密钥轮换与 AID 缓存测试
 * 协议: CSB-Security v1.0 §2.3 / §2.4
 */

const assert = require('assert');
const { KeyRotationManager } = require('../lib/identity/key-rotation');
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

console.log('=== 密钥轮换与 AID 缓存测试 ===\n');

function makeAID(agentId, keyPair) {
  return aid.generateAID({
    agentId,
    name: agentId.split('@')[0],
    endpoint: `http://${agentId.split('@')[1]}/a2a/json-rpc`,
    publicJwk: keyPair.publicJwk
  }, keyPair.privateKey);
}

// 1. 缓存命中（fetcher 只调用一次）
test('AID 缓存命中（fetcher 只调一次）', async () => {
  const kp = aid.generateKeyPair();
  let fetchCount = 0;
  const mgr = new KeyRotationManager({
    aidFetcher: async (id) => { fetchCount++; return makeAID(id, kp); }
  });
  const a1 = await mgr.getAID('ruolan@172.28.0.214:3100');
  const a2 = await mgr.getAID('ruolan@172.28.0.214:3100');
  assert.strictEqual(fetchCount, 1);
  assert.strictEqual(a1.agent_id, a2.agent_id);
});

// 2. 密钥轮换后 force 重新获取
test('密钥轮换后 force 获取新 AID', async () => {
  const kp1 = aid.generateKeyPair();
  const kp2 = aid.generateKeyPair();
  let current = kp1;
  const mgr = new KeyRotationManager({
    aidFetcher: async (id) => makeAID(id, current)
  });
  const old = await mgr.getAID('axuan@172.28.0.5:3100');
  current = kp2; // 轮换密钥
  const fresh = await mgr.refetch('axuan@172.28.0.5:3100');
  assert.notStrictEqual(fresh.public_key.x, old.public_key.x, '公钥应已更新');
});

// 3. 防滥用：1 分钟内重复 refetch 限流
test('refetch 频率限制（1/min）', async () => {
  const kp = aid.generateKeyPair();
  const mgr = new KeyRotationManager({
    aidFetcher: async (id) => makeAID(id, kp)
  });
  await mgr.getAID('jeason@172.28.0.6:3300');
  await mgr.refetch('jeason@172.28.0.6:3300'); // 第一次 OK
  await assert.rejects(
    () => mgr.refetch('jeason@172.28.0.6:3300'), // 第二次应限流
    (err) => err.code === 'REFETCH_RATE_LIMITED'
  );
});

// 4. invalidate 清除缓存
test('invalidate 后重新获取', async () => {
  const kp = aid.generateKeyPair();
  let fetchCount = 0;
  const mgr = new KeyRotationManager({
    aidFetcher: async (id) => { fetchCount++; return makeAID(id, kp); }
  });
  await mgr.getAID('moqiu@172.28.0.7:3100');
  mgr.invalidate('moqiu@172.28.0.7:3100');
  await mgr.getAID('moqiu@172.28.0.7:3100');
  assert.strictEqual(fetchCount, 2);
});

// 5. 缓存 TTL 过期自动重新获取
test('缓存 TTL 过期自动重新获取', async () => {
  const kp = aid.generateKeyPair();
  let fetchCount = 0;
  const mgr = new KeyRotationManager({
    aidFetcher: async (id) => { fetchCount++; return makeAID(id, kp); },
    cacheTtlMs: 50 // 50ms 极短 TTL
  });
  await mgr.getAID('zhouji@172.28.0.27:3100');
  await new Promise(r => setTimeout(r, 80));
  await mgr.getAID('zhouji@172.28.0.27:3100');
  assert.strictEqual(fetchCount, 2);
});

// 6. stats 诊断
test('stats 返回缓存状态', async () => {
  const kp = aid.generateKeyPair();
  const mgr = new KeyRotationManager({
    aidFetcher: async (id) => makeAID(id, kp)
  });
  await mgr.getAID('qingyi@106.12.36.177:3100');
  const stats = mgr.stats();
  assert.ok(stats.cachedAgents.includes('qingyi@106.12.36.177:3100'));
  assert.strictEqual(stats.fresh, 1);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
