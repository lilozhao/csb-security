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

// [2026-10-30 · A-1 第①②件]
// jcs 与契约签名必须与 csb-identity 逐字一致，否则重签出来的 covenant 验不过。
// 直接复用 core.js 的实现（只取两个纯函数，加载无副作用），**不再复制第四份 jcs**。
// 读不到也不致命：轮换仍可做，只是不重签契约（并明确告警，不静默）。
let jcs = null;
let verifyCovenant = null;
try {
  const core = require(path.join(ROOT, '..', 'csb-a2a-aip', 'csb-identity', 'core.js'));
  jcs = core.jcs;
  verifyCovenant = core.verifyCovenant;
} catch (e) {
  console.warn('⚠️  读不到 csb-identity/core.js（' + e.message + '）');
  console.warn('   → 契约将无法重签，轮换后 AID 里的 covenant 会被移除（会明确写进输出）。');
}

/** 公钥指纹：SPKI DER 的 sha256（与 aat-keys.js / aat-doctor.js 同口径） */
function spkiFingerprint(jwk) {
  const der = crypto
    .createPublicKey({ key: jwk, format: 'jwk' })
    .export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// ---------- 参数解析 ----------
// [2026-10-24 · 明德实测反馈]
// 旧实现对 key 只做 `replace(/^--/,'')` 直取，因此：
//   · 文档/usage 里写的是 `--agent-id`，代码读的是 `args.agentId`（驼峰）→ 永远读不到
//   · 更糟的是**静默失败**：有旧 AID 时 `args.agentId || oldAID.agent_id` 会回退到旧值，
//     用户以为改了 endpoint/agent_id，实际没改，且不报任何错。
//     （违反 CSB P1「拒绝要计分」——不认识的参数不该被默默忽略）
// 新实现：驼峰与短横线两种写法都接受；未知参数直接报错退出。
const KNOWN_KEYS = new Set([
  'aid', 'key', 'name', 'endpoint',
  'agentId', 'agent-id', 'agent_id',
]);
// 开关型参数（不带取值，出现即 true）
const FLAG_KEYS = new Set(['new', 'dry-run', 'dryRun']);

/** 把 --agent-id / --agent_id / --agentId 统一成 agentId */
function canonicalKey(raw) {
  if (raw === 'agent-id' || raw === 'agent_id') return 'agentId';
  return raw;
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; ) {
    const flag = argv[i];
    if (!flag || !flag.startsWith('--')) {
      console.error(`❌ 参数格式错误: "${flag}"（应以 -- 开头）`);
      process.exit(1);
    }
    const raw = flag.replace(/^--/, '');

    // 开关型：不消耗下一个参数
    if (FLAG_KEYS.has(raw)) {
      args[raw === 'dryRun' ? 'dry-run' : raw] = true;
      i += 1;
      continue;
    }

    if (!KNOWN_KEYS.has(raw)) {
      console.error(`❌ 未知参数: ${flag}`);
      console.error(`   可用: --aid --key --name --agent-id（或 --agentId）--endpoint [--new]`);
      console.error('   提示：写错参数不会被默默忽略——这样才不会"以为改了其实没改"。');
      process.exit(1);
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      console.error(`❌ 参数 ${flag} 缺少取值`);
      process.exit(1);
    }
    args[canonicalKey(raw)] = value;
    i += 2;
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const aidPath = args.aid;
const keyPath = args.key;

if (!aidPath || !keyPath) {
  console.error('❌ 用法: node scripts/rotate-keys.js --aid <aid.json> --key <private-key.pem> [--name 名字] [--agent-id <id>] [--endpoint <url>]');
  console.error('   （--agent-id 与 --agentId 两种写法都接受；相对路径以 csb-security/ 为基准解析）');
  process.exit(1);
}

// ---------- 读取现有 AID（若存在） ----------
// [2026-10-24 · 明德实测反馈] 路径基准修正。
// 旧实现一律 `path.resolve(ROOT, aidPath)`（ROOT = csb-security/），于是从其它目录运行时
// `--aid csb-security/data/x.json` 会被解析成 csb-security/csb-security/data/x.json。
// 更危险的是：解析失败只打一句「未找到现有 AID，将全新生成」就继续——
// **等于可能静默覆盖用户以为还在用的 AID**。
// 新规则：先按当前工作目录解析，再按 ROOT 解析；两处都没有且用户显式给了路径 → 报错退出。
function resolveInput(p, label) {
  const raw = String(p);
  if (path.isAbsolute(raw)) {
    if (fs.existsSync(raw)) return raw;
    console.error(`❌ ${label} 不存在: ${raw}`);
    console.error('   （绝对路径找不到文件，请检查路径）');
    process.exit(1);
  }
  const fromCwd = path.resolve(process.cwd(), raw);
  if (fs.existsSync(fromCwd)) return fromCwd;
  const fromRoot = path.resolve(ROOT, raw);
  if (fs.existsSync(fromRoot)) return fromRoot;
  console.error(`❌ ${label} 找不到: ${raw}`);
  console.error(`   已尝试: ${fromCwd}`);
  console.error(`           ${fromRoot}`);
  console.error('   注：不会"默默当作全新生成"——那可能覆盖你还在用的 AID。');
  process.exit(1);
}

let oldAID = null;
// 解析后的**绝对写入路径**：读取和写入必须用同一个，否则会出现
// 「读到了 csb-security/data/x.json，却往 csb-security/csb-security/data/x.json 写」的错位。
let AID_OUT = null;
let KEY_OUT = null;
{
  // 显式允许"全新生成"：文件确不存在时用 --new 明确表态
  const explicitNew = process.argv.includes('--new');
  const resolved = path.isAbsolute(aidPath) ? aidPath : null;
  const candidates = resolved
    ? [resolved]
    : [path.resolve(process.cwd(), aidPath), path.resolve(ROOT, aidPath)];
  const found = candidates.find(f => fs.existsSync(f));

  if (found) {
    try {
      oldAID = JSON.parse(fs.readFileSync(found, 'utf8'));
      console.log('📄 现有 AID:', oldAID.agent_id, '| kid:', oldAID.public_key?.kid, '| expires:', oldAID.expires_at);
      console.log('   路径:', found);
      AID_OUT = found;
    } catch (e) {
      console.error(`❌ AID 文件无法解析: ${found}`);
      console.error('   ', e.message);
      process.exit(1);
    }
  } else if (explicitNew) {
    console.log('ℹ️  全新生成模式（--new）：现有 AID 不存在，将新建');
    // 新建：保持用户给的位置（绝对则原样，相对则按 CWD），不要静默挪到 ROOT 下
    AID_OUT = path.resolve(process.cwd(), aidPath);
  } else {
    console.error('❌ 找不到现有 AID 文件，拒绝继续（避免误覆盖）:');
    for (const c of candidates) console.error('   尝试过:', c);
    console.error('   · 想轮换已有 AID → 请给出正确路径');
    console.error('   · 确实要新建 → 加 --new 明确表态');
    process.exit(1);
  }

  // 密钥文件同理：轮换时已存在则原地更新；--new 时按用户给的位置
  const keyCandidates = path.isAbsolute(keyPath)
    ? [keyPath]
    : [path.resolve(process.cwd(), keyPath), path.resolve(ROOT, keyPath)];
  KEY_OUT = keyCandidates.find(f => fs.existsSync(f)) || path.resolve(process.cwd(), keyPath);
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

// [2026-10-24] name 提前校验：底层 aid.generateAID 会抛 "name is required"，
// 但那句报错不告诉人怎么办（尤其全新生成时必须给 --name）。
const resolvedName = args.name || oldAID?.name || '';
if (!resolvedName) {
  console.error('❌ 缺少 name（Agent 名称）');
  console.error('   全新生成时必须提供：--name 你的名字');
  console.error('   轮换已有 AID 时若旧文件里有 name 可省略');
  process.exit(1);
}

let newAID = aid.generateAID({
  agentId,
  name: resolvedName,
  endpoint,
  publicJwk: keyPair.publicJwk,
  capabilities: oldAID?.capabilities || [],
}, keyPair.privateKey);
newAID.public_key.kid = kid;

// ---------- 字段透传（2026-10-30 · A-1 第①件）----------
// 以前这里是「白名单重建」：旧 AID 除了 name/agent_id/endpoint/capabilities 之外
// 全部丢掉。10-27 实测丢掉的是 **`covenant`（善良契约）与 `description`** ——
// 换完钥，新 AID 里没有契约记录，`/aat/issue` 会回 `covenant_unsigned`，
// 等于「换了钥，也把自己换出了签发名单」。这类丢失不会报错，只会在下次签发时炸。
//
// 注意：covenant 不能原样复制 —— 它的 `sig` 是**旧私钥**对 {agent_id, version, hash}
// 的签名，抄过来就变成「用旧钥签的契约挂在用新钥的 AID 上」，验签必失败且难查。
// 正确做法：保留 version/hash（契约内容不变），用**新私钥重签**。
const PERSIST_FIELDS = ['emoji', 'description', 'developer', 'capabilities', 'trust_level'];
const carriedFields = [];
for (const f of PERSIST_FIELDS) {
  if (oldAID && oldAID[f] !== undefined) {
    newAID[f] = oldAID[f];
    carriedFields.push(f);
  }
}
// created_at 是**身份生日**，不是文档生日 —— 轮换不该让一个三年的身份看起来像今天出生
if (oldAID?.created_at) {
  newAID.created_at = oldAID.created_at;
  carriedFields.push('created_at');
}

// buildAID 会给 emoji/description 塞空串。旧 AID 没有的字段就别新增空值 ——
// 「多出一个 `${f}: ""`」会让逐字段 diff 看起来像有变化（10-30 实测撞到）
for (const f of ['emoji', 'description', 'developer']) {
  if (newAID[f] === '' && !(oldAID && oldAID[f] !== undefined)) delete newAID[f];
}

let covenantState = 'none';
let covenantVerified = null;
if (oldAID?.covenant && oldAID.covenant.version && oldAID.covenant.hash) {
  if (jcs) {
    const body = {
      agent_id: agentId,
      covenant_version: oldAID.covenant.version,
      covenant_hash: oldAID.covenant.hash,
    };
    const sig = crypto.sign(null, Buffer.from(jcs(body)), keyPair.privateKey).toString('base64');
    newAID.covenant = {
      version: oldAID.covenant.version,
      hash: oldAID.covenant.hash,
      signed_at: new Date().toISOString(),
      sig,
    };
    covenantState = 're-signed';
    // 自检：重签完立刻验一遍，别把「我以为签了」写进文件
    if (verifyCovenant) {
      // verifyCovenant 内部调 crypto.verify(null, …)，publicKey 必须是 KeyObject ——
      // 传 JWK 会静默变成 bad_public_key（10-30 实测，第一版就是这么错的）
      const pubKeyObject = crypto.createPublicKey({ key: keyPair.publicJwk, format: 'jwk' });
      const v = verifyCovenant(
        { agent_id: agentId, covenant_version: oldAID.covenant.version, covenant_hash: oldAID.covenant.hash, covenant_sig: sig },
        pubKeyObject
      );
      covenantVerified = v.valid ? true : v.error;
      if (!v.valid) {
        console.error('❌ 契约重签后自检失败:', v.error);
        console.error('   拒绝写入 —— 带着一个验不过的契约比没有契约更危险。');
        process.exit(1);
      }
    }
  } else {
    covenantState = 'dropped(no-core)';
  }
}

// 透传字段与契约都必须在**重新签名**之前挂上，否则签名覆盖不到它们
newAID = aid.signAID(newAID, keyPair.privateKey);
// 签完再自检一次结构（signAID 会重排 signature 到末尾）
const selfCheck = aid.verifyAID(newAID);
if (!selfCheck.valid) {
  console.error('❌ 新 AID 自验失败:', selfCheck.error, '—— 拒绝写入');
  process.exit(1);
}

const oldFp = oldAID?.public_key ? spkiFingerprint(oldAID.public_key) : null;
const newFp = spkiFingerprint(keyPair.publicJwk);

// ---------- 备份旧文件 ----------
const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
// [2026-10-24] --dry-run：只走到这里，打印将要发生什么，不写任何文件。
// 起因：我验证参数缺陷时对生产 AID/私钥"干跑"了一次真实轮换 ——
// 破坏性脚本没有 dry-run 本身就是缺陷，与参数 bug 同级。
if (args['dry-run']) {
  console.log('');
  console.log('🔍 DRY-RUN（不会写任何文件）');
  console.log('   将写入 AID :', AID_OUT);
  console.log('   将写入私钥 :', KEY_OUT);
  console.log('   新 agent_id :', agentId);
  console.log('   新 endpoint :', endpoint);
  console.log('   新 kid     :', kid);
  console.log('   将备份旧文件:', fs.existsSync(AID_OUT) ? '是' : '否（新建）');
  console.log('');
  // [2026-10-30 · A-1 第①件] 演练清单第 2 步的判据是「F1 ≠ F0」，
  // 但旧版 dry-run 一个指纹都不打，那条判据根本没法执行（10-27 实测）。
  // 现在把候选公钥的 SPKI sha256 打出来 —— 与 aat-doctor / aat-keys 同口径。
  console.log('   🔑 指纹对照（SPKI sha256）:');
  console.log('      旧（服役中）: ' + (oldFp ? oldFp : '（无旧 AID）'));
  console.log('      候选（本次）: ' + newFp + '   ← 每次 dry-run 都会不同，仅供对照');
  console.log('      判定        : ' + (oldFp ? (oldFp === newFp ? '⚠️ 与旧钥相同（异常）' : '✅ 与旧钥不同') : '—'));
  console.log('');
  console.log('   📦 字段透传:');
  console.log('      保留        : ' + (carriedFields.length ? carriedFields.join(', ') : '（无）'));
  console.log('      契约        : ' + (
    covenantState === 're-signed'
      ? '✅ 保留 version/hash，已用候选新钥重签' + (covenantVerified === true ? '（自验通过）' : '')
      : covenantState === 'dropped(no-core)'
        ? '⚠️ 旧 AID 有契约，但读不到 core.js → 会被移除'
        : '（旧 AID 无契约）'
  ));
  console.log('      新签名自验  : ✅ 通过（DRY-RUN 用的是一次性候选钥，不会落盘）');
  console.log('');
  console.log('   去掉 --dry-run 才会真正写入。');
  process.exit(0);
}

if (fs.existsSync(AID_OUT)) {
  const bak = `${AID_OUT}.bak-${stamp}`;
  fs.copyFileSync(AID_OUT, bak);
  console.log(`🗂️  已备份旧 AID → ${bak}`);
}
if (fs.existsSync(KEY_OUT)) {
  const bak = `${KEY_OUT}.bak-${stamp}`;
  fs.copyFileSync(KEY_OUT, bak);
  console.log(`🗂️  已备份旧私钥 → ${bak}`);
}

// ---------- 写新文件（用解析后的绝对路径，与读取保持同一基准）----------
fs.writeFileSync(AID_OUT, JSON.stringify(newAID, null, 2));
const pem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
fs.mkdirSync(path.dirname(KEY_OUT), { recursive: true });
fs.writeFileSync(KEY_OUT, pem, { mode: 0o600 });

console.log('');
console.log('🎉 密钥轮换完成');
console.log('   AID :', aidPath, `(kid: ${kid})`);
console.log('   KEY :', keyPath, '(PEM pkcs8)');
console.log('   agent_id :', agentId);
console.log('   expires  :', newAID.expires_at);
console.log('   旧指纹   :', oldFp || '（无）');
console.log('   新指纹   :', newFp);
if (carriedFields.length) console.log('   已透传   :', carriedFields.join(', '));
console.log('   契约     :', covenantState === 're-signed'
  ? '✅ 已用新钥重签' + (covenantVerified === true ? '（自验通过）' : '')
  : covenantState === 'dropped(no-core)' ? '⚠️ 已移除（读不到 core.js）' : '（无）');
console.log('');
console.log('⚠️  后续步骤（必须做）:');
console.log('   1. 更新启动环境变量指向新文件（若路径没变则无需改）');
console.log('   2. 重启 A2A server 使新密钥生效');
console.log('   3. 向网络重新分发新 AID（curl http://你IP:3100/a2a/aid 自动暴露新公钥）');
console.log('   4. 通知对端 Agent 重新拉取你的 AID（旧公钥签名的 AAT 将验证失败 → 触发 §2.3 紧急轮换路径）');
console.log('   5. 旧私钥文件（.bak-*）妥善保管或销毁，勿外传');
