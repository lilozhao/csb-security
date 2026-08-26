#!/usr/bin/env node
/**
 * 若兰 → 阿轩 完整五步握手验证（阿轩 PEM 修复后重测）
 * init → challenge → proof → complete
 */
const fs = require('fs');
const path = require('path');
const http = require('http');

const { HandshakeManager, SECURITY_LEVEL } = require('/home/node/.openclaw/workspace/csb-security/lib/handshake/handshake');
const aid = require('/home/node/.openclaw/workspace/csb-security/lib/identity/aid');

const DATA = '/home/node/.openclaw/workspace/csb-security/data';
const CALLER_AID = JSON.parse(fs.readFileSync(path.join(DATA, 'ruolan-aid.json'), 'utf8'));
const CALLER_KEY = fs.readFileSync(path.join(DATA, 'ruolan-private-key.pem'), 'utf8');
const CALLEE_AID = JSON.parse(fs.readFileSync(path.join(DATA, 'axuan-aid.json'), 'utf8'));
const USER_KEY = fs.readFileSync(path.join(DATA, 'yilan-user-key.pem'), 'utf8');
const USER_ID = 'user-yilan@csb';

const CALLER_ID = 'ruolan@172.28.0.214:3100';
const CALLEE_ID = 'axuan@172.28.0.5:3100';
const CALLEE_ENDPOINT = 'http://172.28.0.5:3100/a2a/handshake';
const SCOPES = ['a2a.route', 'a2a.delegate', 'a2a.status', 'memory.query'];

function post(url, body) {
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
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(payload); req.end();
  });
}

async function main() {
  console.log('🌉 若兰 → 阿轩 完整握手验证（第 2 轮）\n');
  const mgr = new HandshakeManager();

  // Step 1: init
  console.log('1️⃣ init...');
  const init = mgr.initiate({
    callerId: CALLER_ID, calleeId: CALLEE_ID,
    requestedScopes: SCOPES, securityLevel: SECURITY_LEVEL.LIGHT,
    callerPrivateKey: CALLER_KEY, callerAID: CALLER_AID
  });
  const initResp = await post(CALLEE_ENDPOINT, { action: 'init', message: init, caller_aid: CALLER_AID });
  console.log('   响应:', JSON.stringify(initResp).slice(0, 250));

  if (!initResp.ok) {
    console.log('❌ init 失败:', initResp.message || initResp.error);
    return;
  }

  // Level 0 直接会话？
  if (initResp.directSession) {
    console.log('🎉 直接会话:', JSON.stringify(initResp.directSession).slice(0, 200));
    return;
  }

  const challengeMsg = initResp.message;
  console.log('2️⃣ challenge 收到:', challengeMsg?.type, '| callee:', challengeMsg?.callee_id);
  console.log('   allowed_scopes:', JSON.stringify(challengeMsg?.allowed_scopes || '无').slice(0, 120));

  // 用阿轩的 AID 验证 challenge（从 GET /a2a/aid 拉取并存本地）
  const calleeAID = CALLEE_AID;
  console.log('   📄 阿轩 AID 已加载:', calleeAID.agent_id);

  try {
    const proofMsg = mgr.processChallenge(init, challengeMsg, {
      callerPrivateKey: CALLER_KEY, callerAID: CALLER_AID, calleeAID,
      userPrivateKey: USER_KEY, userId: USER_ID
    });
    console.log('3️⃣ proof 生成:', proofMsg.type, '| level:', proofMsg.level);

    const proofResp = await post(CALLEE_ENDPOINT, { action: 'proof', message: proofMsg, caller_aid: CALLER_AID });
    console.log('   proof 响应:', JSON.stringify(proofResp).slice(0, 250));

    if (proofResp.ok) {
      const approvalMsg = proofResp.message;
      if (approvalMsg && approvalMsg.type === 'handshake_approval') {
        console.log('4️⃣ approval 收到，complete...');
        const completeMsg = mgr.processApproval(proofMsg, approvalMsg, {
          callerPrivateKey: CALLER_KEY, callerAID: CALLER_AID
        });
        console.log('   complete 处理:', JSON.stringify(completeMsg).slice(0, 250));
        // 通知阿轩握手完成（complete 通常由 callee 端在 approval 时已建立会话）
        if (completeMsg.approved) {
          console.log('\n🎉🎉 握手完成!');
          console.log('   会话:', JSON.stringify(completeMsg.session || '').slice(0, 300));
        } else {
          console.log('   ⚠️ 审批未通过:', JSON.stringify(completeMsg).slice(0, 200));
        }
      } else {
        console.log('   响应类型:', approvalMsg?.type, '| 内容:', JSON.stringify(proofResp).slice(0, 200));
      }
    } else {
      console.log('❌ proof 失败:', proofResp.message || proofResp.error);
    }
  } catch (e) {
    console.log('❌ 本地处理错误:', e.message);
    console.log('   （可能是 callee AID 缺失导致 AAT 验证失败——这是预期内，需阿轩提供 AID 文档）');
  }
}

main().catch(e => console.error('❌ 错误:', e.message));
