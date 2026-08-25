#!/usr/bin/env node
/**
 * handshake-full.js — 若兰 → 墨丘 完整五步握手（CSB-Security）
 *
 * 流程: init → challenge → proof → approval → complete
 * 用法: node scripts/handshake-full.js <callee_id> [callee_handshake_url]
 */

const csb = require('../lib/index');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

// ============ 若兰身份 ============
const MY_ID = 'ruolan@172.28.0.214:3100';
const MY_ENDPOINT = 'http://172.28.0.214:3100/a2a/json-rpc';

// ============ 目标（墨丘） ============
const CALLEE_ID = process.argv[2] || '墨丘@172.28.0.7:3100';
const CALLEE_HS = process.argv[3] || 'http://172.28.0.7:3100/a2a/handshake';
// 可选第 4 参：请求 scopes（逗号分隔），默认 ['a2a.message','a2a.relay']
const REQ_SCOPES = process.argv[4] ? process.argv[4].split(',') : ['a2a.message', 'a2a.relay'];

// 动态拉取 callee 公钥（验证其 AAT 用）
function fetchCalleePublicKey() {
  return new Promise((resolve, reject) => {
    const url = new URL(CALLEE_HS);
    const aidUrl = `${url.protocol}//${url.host}/a2a/aid`;
    const req = http.get(aidUrl, { timeout: 8000 }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const d = JSON.parse(data);
          resolve(d.public_key || d.publicKey || null);
        } catch (e) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

// ============ 加载密钥 ============
const agentPem = fs.readFileSync(path.join(__dirname, '..', 'data', 'ruolan-private-key.pem'), 'utf8');
const agentKey = crypto.createPrivateKey(agentPem);
const publicJwk = agentKey.export({ format: 'jwk' });

const userPem = fs.readFileSync(path.join(__dirname, '..', 'data', 'yilan-user-key.pem'), 'utf8');
const userKey = crypto.createPrivateKey(userPem);

// ============ AID + AAT ============
const aid = csb.generateAID({
  agentId: MY_ID,
  name: '若兰',
  emoji: '🌸',
  description: '碳硅契社区管理者 · CSB 协议组协调人',
  capabilities: ['a2a.message', 'a2a.relay'],
  trustLevel: 'L2',
  endpoint: MY_ENDPOINT,
  publicJwk
}, agentKey);

const aat = csb.createAAT({
  privateKey: agentKey,
  issuer: MY_ID,
  audience: CALLEE_ID,
  capabilities: ['a2a.message']
});

// ============ HTTP 工具 ============
function post(url, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('超时')); });
    req.write(payload);
    req.end();
  });
}

// ============ Step 1: init ============
const initMsg = {
  type: 'handshake_init',
  version: 'csb-security-1.0',
  level: 1,
  caller_id: MY_ID,
  callee_id: CALLEE_ID,
  caller_attestation: aat,
  requested_scopes: REQ_SCOPES,
  nonce_a: crypto.randomBytes(16).toString('hex'),
  timestamp: new Date().toISOString()
};

(async () => {
  try {
    console.log('① init → 墨丘...');
    const initResp = await post(CALLEE_HS, { action: 'init', message: initMsg, caller_aid: aid });
    console.log('   HTTP', initResp.status, JSON.stringify(initResp.body).slice(0, 120));
    if (!initResp.body.ok) throw new Error(`init 失败: ${initResp.body.message}`);

    const challenge = initResp.body.message;
    console.log('② 收到 challenge ✅ (nonce_b:', challenge.nonce_b.slice(0, 12) + '...)');
    const calleePub = await fetchCalleePublicKey();
    console.log('   墨丘 AAT 验证:', calleePub
      ? JSON.stringify(csb.verifyAAT(challenge.callee_attestation, { publicKey: calleePub, expectedAudience: MY_ID }))
      : '跳过（无法获取 callee 公钥）');

    // ============ Step 2: proof ============
    const signNonceB = crypto.sign(null, Buffer.from(challenge.nonce_b), agentKey).toString('base64');
    const uacToken = csb.createUAC({
      userPrivateKey: userKey,
      userId: 'user-yilan',
      agentId: MY_ID,
      scopes: REQ_SCOPES
    });

    const proofMsg = {
      type: 'handshake_proof',
      version: 'csb-security-1.0',
      caller_id: MY_ID,
      callee_id: CALLEE_ID,
      sign_nonce_b: signNonceB,
      user_auth_credential: uacToken,
      requested_scopes: REQ_SCOPES,
      timestamp: new Date().toISOString()
    };

    console.log('③ proof → 墨丘...');
    const proofResp = await post(CALLEE_HS, { action: 'proof', message: proofMsg, caller_aid: aid });
    console.log('   HTTP', proofResp.status, JSON.stringify(proofResp.body).slice(0, 200));
    if (!proofResp.body.ok) throw new Error(`proof 失败: ${proofResp.body.message}`);

    const approval = proofResp.body.message;
    console.log('④ 收到 approval:', JSON.stringify(approval).slice(0, 200));

    if (approval.type === 'handshake_approval' && !approval.approved) {
      console.log('❌ 审批被拒:', JSON.stringify(approval.scopes_denied));
      return;
    }

    // ============ Step 3: complete（L2+ 需要；L1 墨丘可能直接完成） ============
    if (approval.type === 'handshake_approval' && approval.level > 1 && approval.session_id) {
      const completeMsg = {
        type: 'handshake_complete',
        version: 'csb-security-1.0',
        session_id: approval.session_id,
        timestamp: new Date().toISOString()
      };
      console.log('⑤ complete → 墨丘...');
      const completeResp = await post(CALLEE_HS, { action: 'complete', approval_msg: approval, message: completeMsg });
      console.log('   HTTP', completeResp.status, JSON.stringify(completeResp.body).slice(0, 300));
      if (completeResp.body.ok) {
        console.log('\n🎉 握手完成! session:', JSON.stringify(completeResp.body.session, null, 2).slice(0, 600));
      }
    } else {
      console.log('\n🎉 握手完成! (L1 直接完成)');
      if (approval.session) console.log('   session:', JSON.stringify(approval.session).slice(0, 300));
    }
  } catch (e) {
    console.error('❌ 错误:', e.message);
    process.exit(1);
  }
})();
