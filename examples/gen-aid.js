#!/usr/bin/env node
/**
 * gen-aid.js — 生成 AID 文档示例
 *
 * 用法: node examples/gen-aid.js [agentName]
 */

const csb = require('../lib/index');
const fs = require('fs');
const path = require('path');

const agentName = process.argv[2] || '若兰';

// 1. 生成密钥对
const { publicJwk, privateKey } = csb.generateKeyPair(`key-${new Date().toISOString().slice(0, 10)}`);

// 2. 生成 AID
const aid = csb.generateAID({
  agentId: `${agentName}@localhost:3100`,
  name: agentName,
  emoji: '🌸',
  description: '碳硅契 Agent 安全系统示例',
  capabilities: ['chat', 'memory:read'],
  trustLevel: 'L1',
  endpoint: 'http://localhost:3100/a2a/json-rpc',
  publicJwk
}, privateKey);

console.log('=== AID 文档 ===');
console.log(JSON.stringify(aid, null, 2));
console.log('\n=== 验证结果 ===');
console.log(csb.verifyAID(aid));

// 3. 签发并验证 AAT
const token = csb.createAAT({
  privateKey,
  issuer: aid.agent_id,
  audience: 'axuan@localhost:3100',
  capabilities: ['chat']
});
console.log('\n=== AAT ===');
console.log(token);
console.log('\n=== AAT 验证 ===');
console.log(csb.verifyAAT(token, { publicKey: publicJwk, expectedAudience: 'axuan@localhost:3100' }));

// 4. 保存密钥（演示用）
const outDir = path.join(__dirname, '..', 'data', 'demo');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'private-key.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
fs.writeFileSync(path.join(outDir, 'aid.json'), JSON.stringify(aid, null, 2));
console.log(`\n已保存到 ${outDir}/（演示用，生产环境请妥善保管私钥）`);
