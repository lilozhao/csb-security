#!/usr/bin/env node
/**
 * 若兰 → 明德 跨网络握手验证（内网→公网，带外 AID 交换方案）
 * init → challenge → proof → approval → complete
 */
const fs = require('fs');
const path = require('path');
const http = require('http');

const { HandshakeManager, SECURITY_LEVEL } = require('/home/node/.openclaw/workspace/csb-security/lib/handshake/handshake');

const DATA = '/home/node/.openclaw/workspace/csb-security/data';
const CALLER_AID = JSON.parse(fs.readFileSync(path.join(DATA, 'ruolan-aid.json'), 'utf8'));
const CALLER_KEY = fs.readFileSync(path.join(DATA, 'ruolan-private-key.pem'), 'utf8');
const CALLEE_AID = JSON.parse(fs.readFileSync(path.join(DATA, 'mingde-aid.json'), 'utf8'));
const USER_KEY = fs.readFileSync(path.join(DATA, 'yilan-user-key.pem'), 'utf8');
const USER_ID = 'user-yilan@csb';

const CALLER_ID = 'ruolan@172.28.0.214:3100';
const CALLEE_ID = 'mingde@47.121.28.125:3100';
const CALLEE_ENDPOINT = 'http://47.121.28.125:3100/a2a/handshake';
const SCOPES = ['a2a:send'];  // 明德的 allowedScopes 只有 a2a:send

function post(url, body, timeout = 20000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = JSON.stringify(body);
    const req = http.request({
      hostname: u.hostname, port: u.port || 80, path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve(data); } });
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(payload); req.end();
  });
}

async function main() {
  console.log('🌉 若兰(内网) → 明德(公网) 跨网络握手验证\n');
  const mgr = new HandshakeManager();

  // Step 1: init
  console.log('1️⃣ init...');
  const init = mgr.initiate({
    callerId: CALLER_ID, calleeId: CALLEE_ID,
    requestedScopes: SCOPES, securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: CALLER_KEY, callerAID: CALLER_AID
  });
  const initResp = await post(CALLEE_ENDPOINT, { action: 'init', message: init, caller_aid: CALLER_AID });
  console.log('   响应:', JSON.stringify(initResp).slice(0, 220));

  if (!initResp.ok) {
    console.log('❌ init 失败:', initResp.message || initResp.error);
    return;
  }
  if (initResp.directSession) {
    console.log('🎉 直接会话:', JSON.stringify(initResp.directSession).slice(0, 200));
    return;
  }

  const challengeMsg = initResp.message;
  console.log('2️⃣ challenge 收到:', challengeMsg?.type, '| callee:', challengeMsg?.callee_id);
  console.log('   scopes:', JSON.stringify(challengeMsg?.allowed_scopes || []).slice(0, 120));
  console.log('   📄 明德 AID 已加载:', CALLEE_AID.agent_id);

  // Step 3: proof
  try {
    const proofMsg = mgr.processChallenge(init, challengeMsg, {
      callerPrivateKey: CALLER_KEY, callerAID: CALLER_AID, calleeAID: CALLEE_AID,
      userPrivateKey: USER_KEY, userId: USER_ID
    });
    console.log('3️⃣ proof 生成:', proofMsg.type);
    const proofResp = await post(CALLEE_ENDPOINT, { action: 'proof', message: proofMsg, caller_aid: CALLER_AID });
    console.log('   proof 响应:', JSON.stringify(proofResp).slice(0, 250));

    if (proofResp.ok) {
      const approvalMsg = proofResp.message;
      if (approvalMsg && approvalMsg.type === 'handshake_approval') {
        console.log('4️⃣ approval 收到:', approvalMsg.approved ? '✅ approved' : '❌ denied');
        console.log('   scopes_granted:', JSON.stringify(approvalMsg.scopes_granted || []));
        const completeMsg = mgr.processApproval(proofMsg, approvalMsg, {
          callerPrivateKey: CALLER_KEY, callerAID: CALLER_AID
        });
        console.log('5️⃣ complete 处理:', completeMsg.approved ? '✅' : '❌');
        if (completeMsg.approved) {
          console.log('\n🎉🎉 跨网络握手完成!');
          console.log('   会话:', JSON.stringify(completeMsg.session || '').slice(0, 250));
        }
      } else {
        console.log('   响应类型:', approvalMsg?.type, '|', JSON.stringify(proofResp).slice(0, 200));
      }
    } else {
      console.log('❌ proof 失败:', proofResp.message || proofResp.error);
    }
  } catch (e) {
    console.log('❌ 本地处理错误:', e.message);
  }
}

main().catch(e => console.error('❌ 错误:', e.message));
