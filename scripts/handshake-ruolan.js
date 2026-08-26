#!/usr/bin/env node
/**
 * handshake-ruolan.js — 若兰 → 墨丘 身份锚点握手（CSB-Security 五步握手 init）
 *
 * 用法: node scripts/handshake-ruolan.js [callee_id]
 */

const csb = require('../lib/index');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

// 若兰身份（与 server /a2a/aid 一致）
const MY_ID = 'ruolan@172.28.0.214:3100';
const MY_AID_URL = 'http://172.28.0.214:3100/a2a/aid';
const MY_ENDPOINT = 'http://172.28.0.214:3100/a2a/json-rpc';

// 墨丘
const MOQIU = process.argv[2] || 'CSB.墨丘.🧙';
const MOQIU_HS = 'http://172.28.0.7:3100/a2a/handshake';

// 加载若兰私钥
const pem = fs.readFileSync(path.join(__dirname, '..', 'data', 'ruolan-private-key.pem'), 'utf8');
const privateKey = crypto.createPrivateKey(pem);
const publicJwk = privateKey.export({ format: 'jwk' });

// 1. 生成 AID（含签名，agent_id 与 server 一致）
const aid = csb.generateAID({
  agentId: MY_ID,
  name: '若兰',
  emoji: '🌸',
  description: '碳硅契社区管理者 · CSB 协议组协调人 · 杭州',
  capabilities: ['a2a.message', 'a2a.relay', 'forum.post'],
  trustLevel: 'L2',
  endpoint: MY_ENDPOINT,
  publicJwk
}, privateKey);

// 2. 签发 AAT（JWT，EdDSA）
const aat = csb.createAAT({
  privateKey,
  issuer: MY_ID,
  audience: MOQIU,
  capabilities: ['a2a.message']
});

// 3. 构造 init 消息
const init = {
  type: 'handshake_init',
  caller_id: MY_ID,
  callee_id: MOQIU,
  caller_attestation: aat,          // AAT 签名凭证
  requested_scopes: ['a2a.message', 'a2a.relay'],
  security_level: 1,
  nonce_a: crypto.randomBytes(16).toString('hex'),
  timestamp: new Date().toISOString()
};

// ⚠️ caller_aid 必须在 body 顶层（security-handshake.js 从 req.body.caller_aid 读取）
const payload = JSON.stringify({ action: 'init', message: init, caller_aid: aid });

console.log('=== 若兰身份锚点 ===');
console.log('agent_id:', aid.agent_id);
console.log('AID 验证:', JSON.stringify(csb.verifyAID(aid)));
console.log('AAT 长度:', aat.length, '字符');
console.log('\n=== 发送 init 到墨丘 ===');

const req = http.request(MOQIU_HS, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
  timeout: 10000
}, (res) => {
  let body = '';
  res.on('data', c => body += c);
  res.on('end', () => {
    console.log('HTTP', res.statusCode);
    console.log(body.slice(0, 2000));
  });
});
req.on('error', e => console.error('请求失败:', e.message));
req.on('timeout', () => { console.error('超时'); req.destroy(); });
req.write(payload);
req.end();
