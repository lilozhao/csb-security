/**
 * CSB-Security 核心: 五步对等握手（Handshake）
 *
 * 协议: CSB-Security v1.0 §7
 *
 * 流程（Caller → Callee）:
 *   Step 1: handshake_init      身份声明（caller AAT + nonce_a + requested_scopes）
 *   Step 2: handshake_challenge 挑战（callee AAT + nonce_b + sign_nonce_a + allowed_scopes）
 *   Step 3: handshake_proof     证明+授权（sign_nonce_b + UAC）
 *   Step 4: handshake_approval  审批（权限交集 → granted/denied + session_id）
 *   Step 5: handshake_complete  安全会话建立（session_id + access_token）
 *
 * 渐进式安全等级（协议 §7.7）:
 *   Level 0: 无握手，直接通信（同一用户 Agent 内部）
 *   Level 1: Step 1→4（无会话密钥）
 *   Level 2: Step 1→5（完整握手）
 *   Level 3: Step 1→5 + 用户实时确认（敏感操作）
 *
 * 设计: 无状态消息流（每条消息自包含 nonce/签名），适配 P2P 乱序/重发场景
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M2)
 */

const crypto = require('crypto');
const aat = require('../identity/aat');
const uac = require('../authz/uac');
const { computeScopeIntersection } = require('../authz/scope-intersection');

const PROTOCOL_VERSION = 'csb-security-1.0';
const MAX_TIME_DRIFT_MS = 5 * 60 * 1000; // 时间戳偏差 > 5 分钟拒绝（协议 §5.1）

// 渐进式安全等级
const SECURITY_LEVEL = { NONE: 0, LIGHT: 1, FULL: 2, USER_CONFIRM: 3 };

class HandshakeError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

class HandshakeManager {
  /**
   * @param {Object} options
   *   - jtiCache: Set，AAT/UAC jti 重放缓存（跨握手共享）
   *   - seenNonces: Set，nonce 重放防护
   *   - trustManager: TrustLevelManager 实例（可选，用于信任等级检查）
   */
  constructor({ jtiCache = new Set(), seenNonces = new Set(), trustManager = null } = {}) {
    this.jtiCache = jtiCache;
    this.seenNonces = seenNonces;
    this.trustManager = trustManager;
  }

  // ================================================
  // Caller 侧
  // ================================================

  /**
   * Step 1: 身份声明（Caller 发起）
   */
  initiate({ callerId, calleeId, requestedScopes = [], securityLevel = SECURITY_LEVEL.LIGHT, callerPrivateKey, callerAID }) {
    if (securityLevel === SECURITY_LEVEL.NONE) {
      // Level 0: 无握手直接会话
      return {
        type: 'handshake_init',
        level: 0,
        directSession: this._createSession(callerId, calleeId, requestedScopes, SECURITY_LEVEL.NONE)
      };
    }
    if (!callerPrivateKey) throw new HandshakeError('missing_key', 'callerPrivateKey is required');
    if (!callerAID) throw new HandshakeError('missing_aid', 'callerAID is required');

    const token = aat.createAAT({
      privateKey: callerPrivateKey,
      issuer: callerId,
      audience: calleeId,
      capabilities: requestedScopes
    });

    return {
      type: 'handshake_init',
      version: PROTOCOL_VERSION,
      level: securityLevel,
      caller_id: callerId,
      callee_id: calleeId,
      caller_aid: callerAID.endpoint,
      caller_attestation: token,
      requested_scopes: requestedScopes,
      nonce_a: randomNonce(),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Step 3: 证明 + 授权（Caller 处理 Challenge）
   */
  processChallenge(initMsg, challengeMsg, { callerPrivateKey, callerAID, calleeAID, userPrivateKey, userId, uacScopes = null }) {
    if (!challengeMsg || challengeMsg.type !== 'handshake_challenge') {
      throw new HandshakeError('bad_message', 'expected handshake_challenge');
    }
    if (challengeMsg.callee_id !== initMsg.callee_id) {
      throw new HandshakeError('callee_mismatch', 'challenge callee_id mismatch');
    }
    this._checkTimestamp(challengeMsg.timestamp);

    // 1. 验证 callee AAT（aud = caller）
    const calleeAatResult = aat.verifyAAT(challengeMsg.callee_attestation, {
      publicKey: calleeAID.public_key,
      expectedAudience: initMsg.caller_id,
      jtiCache: this.jtiCache
    });
    if (!calleeAatResult.valid) {
      throw new HandshakeError('callee_aat_invalid', `callee AAT invalid: ${calleeAatResult.error}`);
    }

    // 2. 验证 sign_nonce_a（callee 用私钥签名了 caller 的 nonce_a）
    if (!verifyNonceSignature(challengeMsg.sign_nonce_a, initMsg.nonce_a, calleeAID.public_key)) {
      throw new HandshakeError('challenge_bad_signature', 'sign_nonce_a verification failed');
    }

    // 3. 生成 sign_nonce_b + UAC（uacScopes = 用户实际授权范围，默认等于请求范围）
    const signNonceB = signNonce(challengeMsg.nonce_b, callerPrivateKey);
    const token = uac.createUAC({
      userPrivateKey,
      userId: userId || `user-${initMsg.caller_id}`,
      agentId: initMsg.caller_id,
      scopes: uacScopes || initMsg.requested_scopes
    });

    return {
      type: 'handshake_proof',
      version: PROTOCOL_VERSION,
      caller_id: initMsg.caller_id,
      callee_id: initMsg.callee_id,
      sign_nonce_b: signNonceB,
      user_auth_credential: token,
      requested_scopes: initMsg.requested_scopes,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Step 5: 会话建立（Caller 处理 Approval）
   */
  processApproval(proofMsg, approvalMsg, { callerPrivateKey, callerAID }) {
    if (!approvalMsg || approvalMsg.type !== 'handshake_approval') {
      throw new HandshakeError('bad_message', 'expected handshake_approval');
    }
    this._checkTimestamp(approvalMsg.timestamp);

    if (!approvalMsg.approved) {
      return { approved: false, denied: approvalMsg.scopes_denied || [], session: null };
    }

    // Level 1: approval 即完成（无会话密钥协商）
    if (approvalMsg.level <= SECURITY_LEVEL.LIGHT) {
      return {
        approved: true,
        session: this._createSession(
          proofMsg.caller_id, proofMsg.callee_id,
          approvalMsg.scopes_granted || [],
          approvalMsg.level,
          approvalMsg.session_id,
          approvalMsg.session_ttl,
          approvalMsg.restrictions
        )
      };
    }

    // Level 2+: 生成 complete
    return {
      approved: true,
      complete: {
        type: 'handshake_complete',
        version: PROTOCOL_VERSION,
        session_id: approvalMsg.session_id,
        access_token: randomToken(),
        timestamp: new Date().toISOString()
      }
    };
  }

  // ================================================
  // Callee 侧
  // ================================================

  /**
   * Step 2: 挑战（Callee 处理 Init）
   */
  processInit(initMsg, { calleePrivateKey, calleeAID, callerAID, calleeAllowedScopes = [] }) {
    if (!initMsg || initMsg.type !== 'handshake_init') {
      throw new HandshakeError('bad_message', 'expected handshake_init');
    }
    if (initMsg.level === 0 && initMsg.directSession) {
      return { directSession: initMsg.directSession };
    }
    if (initMsg.callee_id !== calleeAID.agent_id) {
      throw new HandshakeError('callee_mismatch', 'init callee_id mismatch');
    }
    this._checkTimestamp(initMsg.timestamp);
    this._checkNonce(initMsg.nonce_a);

    // 1. 验证 caller AAT（aud = callee）
    const callerAatResult = aat.verifyAAT(initMsg.caller_attestation, {
      publicKey: callerAID.public_key,
      expectedAudience: calleeAID.agent_id,
      jtiCache: this.jtiCache
    });
    if (!callerAatResult.valid) {
      throw new HandshakeError('caller_aat_invalid', `caller AAT invalid: ${callerAatResult.error}`);
    }

    // 2. 生成 nonce_b + sign_nonce_a
    const nonceB = randomNonce();
    const calleeToken = aat.createAAT({
      privateKey: calleePrivateKey,
      issuer: calleeAID.agent_id,
      audience: initMsg.caller_id,
      capabilities: calleeAllowedScopes
    });

    return {
      type: 'handshake_challenge',
      version: PROTOCOL_VERSION,
      level: initMsg.level,
      caller_id: initMsg.caller_id,
      callee_id: calleeAID.agent_id,
      callee_aid: calleeAID.endpoint,
      callee_attestation: calleeToken,
      nonce_b: nonceB,
      sign_nonce_a: signNonce(initMsg.nonce_a, calleePrivateKey),
      allowed_scopes: calleeAllowedScopes,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Step 4: 审批（Callee 处理 Proof）
   */
  processProof(challengeMsg, proofMsg, {
    callerAID, userPublicKey, calleeAllowedScopes = [],
    minTrustLevel = 'L0', userConfirm = null
  }) {
    if (!proofMsg || proofMsg.type !== 'handshake_proof') {
      throw new HandshakeError('bad_message', 'expected handshake_proof');
    }
    this._checkTimestamp(proofMsg.timestamp);

    // 1. 验证 sign_nonce_b（caller 私钥签名 nonce_b）
    if (!verifyNonceSignature(proofMsg.sign_nonce_b, challengeMsg.nonce_b, callerAID.public_key)) {
      throw new HandshakeError('proof_bad_signature', 'sign_nonce_b verification failed');
    }

    // 2. 验证 UAC（sub = caller，用户公钥）
    const uacResult = uac.verifyUAC(proofMsg.user_auth_credential, {
      userPublicKey,
      expectedAgentId: proofMsg.caller_id,
      jtiCache: this.jtiCache
    });
    if (!uacResult.valid) {
      throw new HandshakeError('uac_invalid', `UAC invalid: ${uacResult.error}`);
    }

    // 3. UAC restrictions.allowed_agents 检查
    if (!uac.allowsAgent(uacResult.payload, proofMsg.caller_id)) {
      throw new HandshakeError('uac_agent_not_allowed', 'caller not in UAC allowed_agents');
    }

    // 4. 信任等级检查（可选）
    if (this.trustManager && minTrustLevel !== 'L0') {
      const record = this.trustManager.getTrustLevel(proofMsg.caller_id);
      if (this.trustManager.levelToInt(record.trustLevel) < this.trustManager.levelToInt(minTrustLevel)) {
        return {
          type: 'handshake_approval',
          approved: false,
          caller_id: proofMsg.caller_id,
          callee_id: proofMsg.callee_id,
          scopes_granted: [],
          scopes_denied: [{ scope: '*', reason: `trust_level_below_${minTrustLevel}` }],
          timestamp: new Date().toISOString()
        };
      }
    }

    // 6. 权限交集（协议 §3.3）
    const intersection = computeScopeIntersection(
      proofMsg.requested_scopes,
      uacResult.payload.scopes,
      calleeAllowedScopes
    );

    // 7. Level 3: 用户实时确认
    if (challengeMsg.level === SECURITY_LEVEL.USER_CONFIRM && typeof userConfirm === 'function') {
      const confirmed = userConfirm({
        callerId: proofMsg.caller_id,
        requestedScopes: proofMsg.requested_scopes,
        grantedScopes: intersection.granted
      });
      if (!confirmed) {
        return {
          type: 'handshake_approval',
          approved: false,
          caller_id: proofMsg.caller_id,
          callee_id: proofMsg.callee_id,
          scopes_granted: [],
          scopes_denied: [{ scope: '*', reason: 'user_denied_realtime' }],
          timestamp: new Date().toISOString()
        };
      }
    }

    const sessionId = `sess-${Math.floor(Date.now() / 1000)}-${crypto.randomBytes(4).toString('hex')}`;

    return {
      type: 'handshake_approval',
      approved: intersection.granted.length > 0,
      level: challengeMsg.level,
      caller_id: proofMsg.caller_id,
      callee_id: proofMsg.callee_id,
      scopes_granted: intersection.granted,
      scopes_denied: intersection.denied,
      session_id: sessionId,
      session_ttl: challengeMsg.level >= SECURITY_LEVEL.FULL ? 3600 : 300,
      restrictions: { rate_limit: '60/minute' },
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Step 5 收尾: Callee 处理 Complete，建立会话
   */
  processComplete(approvalMsg, completeMsg) {
    if (!completeMsg || completeMsg.type !== 'handshake_complete') {
      throw new HandshakeError('bad_message', 'expected handshake_complete');
    }
    if (completeMsg.session_id !== approvalMsg.session_id) {
      throw new HandshakeError('session_mismatch', 'complete session_id mismatch');
    }
    return {
      session: this._createSession(
        approvalMsg.caller_id, approvalMsg.callee_id,
        approvalMsg.scopes_granted || [],
        approvalMsg.level,
        approvalMsg.session_id,
        approvalMsg.session_ttl,
        approvalMsg.restrictions
      )
    };
  }

  // ================================================
  // 内部工具
  // ================================================

  _createSession(callerId, calleeId, scopes, level, sessionId = null, ttl = 300, restrictions = null) {
    return {
      session_id: sessionId || `sess-${Math.floor(Date.now() / 1000)}-${crypto.randomBytes(4).toString('hex')}`,
      caller_id: callerId,
      callee_id: calleeId,
      scopes_granted: scopes,
      security_level: level,
      ttl,
      restrictions,
      created_at: new Date().toISOString()
    };
  }

  _checkTimestamp(iso) {
    if (!iso) throw new HandshakeError('missing_timestamp', 'timestamp is required');
    const ts = new Date(iso).getTime();
    if (Number.isNaN(ts)) throw new HandshakeError('bad_timestamp', 'invalid timestamp');
    if (Math.abs(Date.now() - ts) > MAX_TIME_DRIFT_MS) {
      throw new HandshakeError('time_drift', 'timestamp drift > 5 minutes');
    }
  }

  _checkNonce(nonce) {
    if (!nonce) throw new HandshakeError('missing_nonce', 'nonce is required');
    if (this.seenNonces.has(nonce)) {
      throw new HandshakeError('nonce_replay', 'nonce replay detected');
    }
    this.seenNonces.add(nonce);
  }
}

// ================================================
// 工具函数
// ================================================

function randomNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function randomToken() {
  return crypto.randomBytes(24).toString('base64url');
}

function signNonce(nonce, privateKey) {
  return crypto.sign(null, Buffer.from(nonce), privateKey).toString('base64');
}

function verifyNonceSignature(signatureB64, nonce, publicKeyJwk) {
  try {
    const pub = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });
    return crypto.verify(null, Buffer.from(nonce), pub, Buffer.from(signatureB64, 'base64'));
  } catch (e) {
    return false;
  }
}

module.exports = {
  PROTOCOL_VERSION,
  SECURITY_LEVEL,
  HandshakeError,
  HandshakeManager,
  randomNonce,
  signNonce,
  verifyNonceSignature
};
