#!/usr/bin/env node
/**
 * test-rotate-and-pin-conflict.js — A-1 第①②件的可复跑证据
 * ------------------------------------------------------------------
 * 演练清单 `docs/key-rotation-drill.md` 的第 2 步与第 4 步，以前只能靠人手跑一遍、
 * 把输出贴进文档。贴一次的输出无法复算 —— 下次谁也不知道那条结论还成不成立。
 * 这个脚本把两件事变成断言：
 *
 *   第 2 步（dry-run）：不动文件 + **必须打印候选指纹 F1**，且 F1 ≠ F0
 *   第 ①件（字段透传）：真轮换后 covenant / description / emoji / created_at 不丢，
 *                      covenant 用新钥重签并能验过（旧实现是整片丢弃）
 *   第 4 步（冲突构造）：同 issuer 不同指纹且未声明轮换 → **必须非 0 退出**、pin 表不许动；
 *                      声明 --rotate → 通过，旧钥进 aidKeyHistory 不删除
 *
 * 安全性：全程在临时目录里跑，`AAT_KEYS_LOCAL` 指向副本。
 *        生产 `csb-security/data/*` 与 `config/agents.local.json` **一个字节都不碰**（末尾会核）。
 *
 * 用法: node csb-security/test/test-rotate-and-pin-conflict.js
 * 维护: 若兰 🌸 | 2026-10-30
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const WS = path.resolve(__dirname, '..', '..');
const ROTATE = path.join(WS, 'csb-security', 'scripts', 'rotate-keys.js');
const AAT_KEYS = path.join(WS, 'csb-a2a-aip', 'scripts', 'aat-keys.js');
const PROD_AID = path.join(WS, 'csb-security', 'data', 'ruolan-aid.json');
const PROD_KEY = path.join(WS, 'csb-security', 'data', 'ruolan-private-key.pem');
const PROD_PIN = path.join(WS, 'csb-a2a-aip', 'config', 'agents.local.json');

const TMP = path.join(WS, '.openclaw', 'tmp', 'rot-test-' + Date.now());

let pass = 0, fail = 0;
function ok(name, cond, detail = '') {
  if (cond) { console.log(`  ✅ ${name}`); pass++; }
  else { console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`); fail++; }
}
const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

/** 跑子进程，返回 {code, out} —— 不因非 0 退出抛异常 */
function run(cmd, args, env = {}) {
  try {
    const out = execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status == null ? -1 : e.status, out: String(e.stdout || '') + String(e.stderr || '') };
  }
}

function mkJwkFile(name) {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const p = path.join(TMP, name);
  fs.writeFileSync(p, JSON.stringify(jwk));
  return { path: p, x: jwk.x };
}

console.log('🧪 A-1 演练断言（临时目录，不碰生产）\n');

// 生产基线：跑完必须一模一样
const prodBefore = { aid: sha(PROD_AID), key: sha(PROD_KEY), pin: sha(PROD_PIN) };

fs.mkdirSync(TMP, { recursive: true });
const aidCopy = path.join(TMP, 'aid.json');
const keyCopy = path.join(TMP, 'key.pem');
fs.copyFileSync(PROD_AID, aidCopy);
fs.copyFileSync(PROD_KEY, keyCopy);

// ---------- 第 2 步：dry-run 不动文件、且打印候选指纹 ----------
console.log('第 2 步 · dry-run');
const shaBefore = sha(aidCopy);
const dr1 = run(process.execPath, [ROTATE, '--aid', aidCopy, '--key', keyCopy, '--name', '若兰', '--dry-run']);
const dr2 = run(process.execPath, [ROTATE, '--aid', aidCopy, '--key', keyCopy, '--name', '若兰', '--dry-run']);
ok('dry-run 退出 0', dr1.code === 0, dr1.out.slice(-300));
ok('dry-run 未改 AID 文件', sha(aidCopy) === shaBefore);
const fpOf = (out) => (out.match(/候选（本次）:\s*([0-9a-f]{64})/) || [])[1] || null;
const F1a = fpOf(dr1.out), F1b = fpOf(dr2.out);
const F0 = (dr1.out.match(/旧（服役中）:\s*([0-9a-f]{64})/) || [])[1] || null;
ok('dry-run 打印了候选指纹 F1', !!F1a, '旧版这里一个指纹都不打，判据 F1≠F0 无法执行');
ok('F1 ≠ F0', !!F1a && !!F0 && F1a !== F0);
ok('两次 dry-run 的候选钥不同（一次性候选，不落盘）', !!F1a && !!F1b && F1a !== F1b);
ok('F0 与 aat-doctor 基线一致 aa09625e…', !!F0 && F0.startsWith('aa09625e'), String(F0));
ok('dry-run 明确声明会重签契约', /契约\s*:\s*✅ 保留 version\/hash/.test(dr1.out));

// ---------- 第 ①件：真轮换（在副本上）后字段不丢 ----------
console.log('\n第 ①件 · 字段透传 + 契约重签（在副本上真跑）');
const oldAID = JSON.parse(fs.readFileSync(aidCopy, 'utf8'));
const rot = run(process.execPath, [ROTATE, '--aid', aidCopy, '--key', keyCopy, '--name', '若兰']);
ok('轮换退出 0', rot.code === 0, rot.out.slice(-300));
const newAID = JSON.parse(fs.readFileSync(aidCopy, 'utf8'));

ok('covenant 未丢', !!newAID.covenant, '旧实现实测会把整个 covenant 丢掉 → /aat/issue 回 covenant_unsigned');
ok('covenant.version/hash 原样保留',
  newAID.covenant?.version === oldAID.covenant.version && newAID.covenant?.hash === oldAID.covenant.hash);
ok('covenant.sig 已用新钥重签（≠旧签名）', newAID.covenant?.sig !== oldAID.covenant.sig);
for (const f of ['emoji', 'created_at', 'trust_level', 'agent_id', 'endpoint']) {
  ok(`${f} 原样保留`, JSON.stringify(newAID[f]) === JSON.stringify(oldAID[f]));
}
ok('没有新增空字段（description 空串不写入文档）', !('description' in newAID) || newAID.description !== '');
ok('公钥已换', newAID.public_key.x !== oldAID.public_key.x);

// 三方独立验签（不信任脚本自检）
const pubNew = crypto.createPublicKey({ key: newAID.public_key, format: 'jwk' });
const { signature, ...unsigned } = newAID;
ok('新 AID 签名可验（registry 口径 JSON.stringify）',
  crypto.verify(null, Buffer.from(JSON.stringify(unsigned)), pubNew, Buffer.from(signature, 'base64')));
const core = require(path.join(WS, 'csb-a2a-aip', 'csb-identity', 'core.js'));
ok('新契约签名可验（用新公钥）',
  core.verifyCovenant({
    agent_id: newAID.agent_id,
    covenant_version: newAID.covenant.version,
    covenant_hash: newAID.covenant.hash,
    covenant_sig: newAID.covenant.sig,
  }, pubNew).valid);
const keyPem = crypto.createPrivateKey(fs.readFileSync(keyCopy, 'utf8'));
ok('落盘私钥与 AID 公钥配对',
  crypto.createHash('sha256').update(crypto.createPublicKey(keyPem).export({ type: 'spki', format: 'der' })).digest('hex')
  === crypto.createHash('sha256').update(pubNew.export({ type: 'spki', format: 'der' })).digest('hex'));

// ---------- 第 4 步：同 issuer 多钥冲突必拒 ----------
console.log('\n第 4 步 · 同 issuer 多钥冲突');
const pinCfg = path.join(TMP, 'agents.local.json');
const cfg = JSON.parse(fs.readFileSync(PROD_PIN, 'utf8'));
cfg.agents = cfg.agents || {};
cfg.agents.testprobe = { name: '测试探针', host: '127.0.0.1', port: 9999, trust: 1 };
fs.writeFileSync(pinCfg, JSON.stringify(cfg, null, 2));
const env = { AAT_KEYS_LOCAL: pinCfg };
const k1 = mkJwkFile('k1.json');
const k2 = mkJwkFile('k2.json');

const t1 = run(process.execPath, [AAT_KEYS, 'pin', 'testprobe', k1.path], env);
ok('T1 首次 pin 成功（exit 0）', t1.code === 0, t1.out.slice(-200));
const t2 = run(process.execPath, [AAT_KEYS, 'pin', 'testprobe', k1.path], env);
ok('T2 同钥重复 pin 幂等（exit 0）', t2.code === 0 && /无需变更/.test(t2.out));

const pinShaBefore = sha(pinCfg);
const t3 = run(process.execPath, [AAT_KEYS, 'pin', 'testprobe', k2.path], env);
ok('T3 换钥未声明轮换 → **非 0 退出**', t3.code !== 0, `exit=${t3.code}（旧实现是静默覆盖）`);
ok('T3 报错把新旧指纹都打出来', /已固定\s*:\s*[0-9a-f]{64}/.test(t3.out) && /待固定\s*:\s*[0-9a-f]{64}/.test(t3.out));
ok('T3 拒绝后 pin 表一个字节没变', sha(pinCfg) === pinShaBefore);

const t4 = run(process.execPath, [AAT_KEYS, 'pin', 'testprobe', k2.path, '--rotate', '--reason', '演练'], env);
ok('T4 声明轮换 → 通过（exit 0）', t4.code === 0, t4.out.slice(-200));
const after = JSON.parse(fs.readFileSync(pinCfg, 'utf8')).agents.testprobe;
ok('T4 现用钥 = 新钥', after.aidPublicKey.x === k2.x);
ok("T4 旧钥进 aidKeyHistory（不删除）", Array.isArray(after.aidKeyHistory) && after.aidKeyHistory.length === 1 && after.aidKeyHistory[0].publicKey.x === k1.x);
ok('T4 记录了 keyRotatedAt / reason', !!after.keyRotatedAt && after.aidKeyHistory[0].reason === '演练');


// ---------- 生产未被触碰 ----------
console.log('\n生产文件核对');
ok('生产 AID 未变', sha(PROD_AID) === prodBefore.aid);
ok('生产私钥未变', sha(PROD_KEY) === prodBefore.key);
ok('生产 pin 表未变', sha(PROD_PIN) === prodBefore.pin);

console.log(`\n${fail === 0 ? '✅ 全部通过' : '❌ 有失败项'} · ${pass} passed, ${fail} failed`);
console.log(`临时目录: ${TMP}`);
process.exit(fail === 0 ? 0 : 1);
