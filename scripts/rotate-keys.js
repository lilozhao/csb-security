#!/usr/bin/env node
/**
 * CSB-Security 密钥轮换 CLI（协议 §2.3 / §2.4）
 *
 * 用法:
 *   node scripts/rotate-keys.js \
 *     --aid csb-security/data/ruolan-aid.json \
 *     --key csb-security/data/ruolan-private-key.pem \
 *     --name 若兰 \
 *     --agent-id ruolan@172.28.0.214:3100 \
 *     --endpoint http://172.28.0.214:3100/a2a/json-rpc
 *
 * 行为:
 *   1. 读取现有 AID（保留 agent_id/endpoint/capabilities，若未传 --agent-id/--endpoint）
 *   2. 生成新 Ed25519 密钥对 + 新 AID（新 kid 带时间戳、expires_at = now + 365d）
 *   3. 备份旧 AID/私钥（.bak-YYYYMMDDHHMMSS）
 *   4. 写新文件（AID 自动签名）
 *   5. 打印后续步骤提示（更新环境变量 + 重新分发 AID）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-25 (P2 补齐)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const aid = require(path.join(ROOT, 'lib/identity/aid'));

// ---------- 参数解析 ----------
function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, '');
    args[key] = argv[i + 1];
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const aidPath = args.aid;
const keyPath = args.key;

if (!aidPath || !keyPath) {
  console.error('❌ 用法: node scripts/rotate-keys.js --aid <aid.json> --key <private-key.pem> [--name 名字] [--agent-id id] [--endpoint url]');
  process.exit(1);
}

// ---------- 读取现有 AID（若存在） ----------
let oldAID = null;
try {
  oldAID = JSON.parse(fs.readFileSync(path.resolve(ROOT, aidPath), 'utf8'));
  console.log('📄 现有 AID:', oldAID.agent_id, '| kid:', oldAID.public_key?.kid, '| expires:', oldAID.expires_at);
} catch {
  console.log('ℹ️  未找到现有 AID，将全新生成');
}

// ---------- 生成新密钥对 + 新 AID ----------
const kid = `${(args.name || oldAID?.name || 'agent').replace(/\s/g, '-')}-${new Date().toISOString().slice(0, 10)}-rot${Date.now().toString(36)}`;
const keyPair = aid.generateKeyPair(kid);

const agentId = args.agentId || oldAID?.agent_id;
const endpoint = args.endpoint || oldAID?.endpoint;
if (!agentId || !endpoint) {
  console.error('❌ 缺少 agent_id 或 endpoint（无法从旧 AID 继承且未通过参数提供）');
  process.exit(1);
}

const newAID = aid.generateAID({
  agentId,
  name: args.name || oldAID?.name || '',
  endpoint,
  publicJwk: keyPair.publicJwk,
  capabilities: oldAID?.capabilities || [],
}, keyPair.privateKey);
newAID.public_key.kid = kid;

// ---------- 备份旧文件 ----------
const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
if (fs.existsSync(path.resolve(ROOT, aidPath))) {
  const bak = `${aidPath}.bak-${stamp}`;
  fs.copyFileSync(path.resolve(ROOT, aidPath), path.resolve(ROOT, bak));
  console.log(`🗂️  已备份旧 AID → ${bak}`);
}
if (fs.existsSync(path.resolve(ROOT, keyPath))) {
  const bak = `${keyPath}.bak-${stamp}`;
  fs.copyFileSync(path.resolve(ROOT, keyPath), path.resolve(ROOT, bak));
  console.log(`🗂️  已备份旧私钥 → ${bak}`);
}

// ---------- 写新文件 ----------
fs.writeFileSync(path.resolve(ROOT, aidPath), JSON.stringify(newAID, null, 2));
const pem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
fs.writeFileSync(path.resolve(ROOT, keyPath), pem);

console.log('');
console.log('🎉 密钥轮换完成');
console.log('   AID :', aidPath, `(kid: ${kid})`);
console.log('   KEY :', keyPath, '(PEM pkcs8)');
console.log('   agent_id :', agentId);
console.log('   expires  :', newAID.expires_at);
console.log('');
console.log('⚠️  后续步骤（必须做）:');
console.log('   1. 更新启动环境变量指向新文件（若路径没变则无需改）');
console.log('   2. 重启 A2A server 使新密钥生效');
console.log('   3. 向网络重新分发新 AID（curl http://你IP:3100/a2a/aid 自动暴露新公钥）');
console.log('   4. 通知对端 Agent 重新拉取你的 AID（旧公钥签名的 AAT 将验证失败 → 触发 §2.3 紧急轮换路径）');
console.log('   5. 旧私钥文件（.bak-*）妥善保管或销毁，勿外传');
