#!/usr/bin/env node
/**
 * test-uac.js — UAC (User Authorization Credential) 测试
 * 协议: CSB-Security v1.0 §3.2
 */

const assert = require('assert');
const uac = require('../lib/authz/uac');
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

console.log('=== UAC 测试 ===\n');

const userKey = aid.generateKeyPair('user-key-01');
const USER = 'user-yilan@csb';
const AGENT = 'ruolan@172.28.0.214:3100';

// 1. 签发 UAC
test('签发 UAC 返回 JWT 三段式', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey,
    userId: USER,
    agentId: AGENT,
    scopes: ['chat', 'memory:read', 'forum:post']
  });
  assert.strictEqual(token.split('.').length, 3);
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  assert.strictEqual(payload.iss, USER);
  assert.strictEqual(payload.sub, AGENT);
  assert.deepStrictEqual(payload.scopes, ['chat', 'memory:read', 'forum:post']);
});

// 2. 验证通过
test('验证合法 UAC 通过', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey,
    userId: USER,
    agentId: AGENT,
    scopes: ['chat']
  });
  const result = uac.verifyUAC(token, { userPublicKey: userKey.publicJwk, expectedAgentId: AGENT });
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.payload.sub, AGENT);
});

// 3. 过期拒绝
test('过期 UAC 拒绝', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey,
    userId: USER,
    agentId: AGENT,
    scopes: ['chat'],
    ttl: 5
  });
  const result = uac.verifyUAC(token, {
    userPublicKey: userKey.publicJwk, expectedAgentId: AGENT,
    now: Date.now() + 10 * 60 * 1000
  });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'expired');
});

// 4. 签名篡改拒绝
test('签名篡改拒绝', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey, userId: USER, agentId: AGENT, scopes: ['chat']
  });
  const parts = token.split('.');
  const tampered = `${parts[0]}.${parts[1]}.${Buffer.from('bad').toString('base64url')}`;
  const result = uac.verifyUAC(tampered, { userPublicKey: userKey.publicJwk, expectedAgentId: AGENT });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'bad_signature');
});

// 5. sub 不匹配（Token 绑定：别的 Agent 不能用）
test('sub 不匹配拒绝（Token 绑定）', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey, userId: USER, agentId: AGENT, scopes: ['chat']
  });
  const result = uac.verifyUAC(token, {
    userPublicKey: userKey.publicJwk, expectedAgentId: 'axuan@172.28.0.5:3100'
  });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'agent_mismatch');
});

// 6. jti 重放拒绝
test('jti 重放拒绝', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey, userId: USER, agentId: AGENT, scopes: ['chat']
  });
  const jtiCache = new Set();
  assert.strictEqual(uac.verifyUAC(token, { userPublicKey: userKey.publicJwk, expectedAgentId: AGENT, jtiCache }).valid, true);
  const replay = uac.verifyUAC(token, { userPublicKey: userKey.publicJwk, expectedAgentId: AGENT, jtiCache });
  assert.strictEqual(replay.valid, false);
  assert.strictEqual(replay.error, 'replay_detected');
});

// 7. restrictions 解析
test('restrictions 携带与解析', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey,
    userId: USER,
    agentId: AGENT,
    scopes: ['chat'],
    restrictions: {
      ip_whitelist: [],
      rate_limit: '100/minute',
      allowed_agents: ['axuan@172.28.0.5:3100', 'jeason@172.28.0.6:3300']
    }
  });
  const result = uac.verifyUAC(token, { userPublicKey: userKey.publicJwk, expectedAgentId: AGENT });
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.payload.restrictions.rate_limit, '100/minute');
  // allowsAgent 检查
  assert.strictEqual(uac.allowsAgent(result.payload, 'axuan@172.28.0.5:3100'), true);
  assert.strictEqual(uac.allowsAgent(result.payload, 'unknown@1.2.3.4:3100'), false);
});

// 8. coversScopes 检查
test('coversScopes 覆盖检查', () => {
  const token = uac.createUAC({
    userPrivateKey: userKey.privateKey, userId: USER, agentId: AGENT,
    scopes: ['chat', 'memory:read']
  });
  const result = uac.verifyUAC(token, { userPublicKey: userKey.publicJwk, expectedAgentId: AGENT });
  assert.strictEqual(uac.coversScopes(result.payload, ['chat']), true);
  assert.strictEqual(uac.coversScopes(result.payload, ['chat', 'forum:post']), false);
});

// 9. TTL 常量
test('UAC_TTL 时间窗口常量', () => {
  assert.strictEqual(uac.UAC_TTL.ONCE, 300);       // 5 分钟
  assert.strictEqual(uac.UAC_TTL.SHORT_TERM, 3600); // 1 小时
  assert.strictEqual(uac.UAC_TTL.DAILY, 86400);     // 24 小时
  assert.strictEqual(uac.UAC_TTL.LONG_TERM, 604800); // 7 天
  assert.strictEqual(uac.UAC_TTL.PERMANENT, 31536000); // 365 天
});

// 10. 空 scopes 拒绝
test('空 scopes 签发拒绝', () => {
  assert.throws(() => uac.createUAC({
    userPrivateKey: userKey.privateKey, userId: USER, agentId: AGENT, scopes: []
  }), /scopes cannot be empty/);
});

console.log(`\n通过: ${passed}\n失败: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
