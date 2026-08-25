/**
 * CSB-Security 统一入口
 *
 * CSB-Security v1.0 落地实现（M1: 身份层 + 信任等级 · M2: 握手 + 授权）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22
 */

// Layer 1: 身份安全
const aid = require('./identity/aid');
const aat = require('./identity/aat');
const { KeyRotationManager } = require('./identity/key-rotation');

// Layer 2: 授权控制
const trust = require('./authz/trust-level');
const uac = require('./authz/uac');
const scopeIntersection = require('./authz/scope-intersection');
const reputation = require('./authz/reputation');

// 核心: 五步对等握手
const handshake = require('./handshake/handshake');

// Layer 3: 传输安全
const e2eEncryption = require('./transport/e2e-encryption');
const sessionKeys = require('./transport/session-keys');
const tokenBinding = require('./transport/token-binding');
const pkce = require('./transport/pkce');

// Layer 4: 防攻击
const replayGuard = require('./defense/replay-guard');
const rateLimiter = require('./defense/rate-limiter');
const anomalyDetector = require('./defense/anomaly-detector');

// Layer 5: 审计追踪
const auditLog = require('./audit/audit-log');
const auditQuery = require('./audit/audit-query');
const tamperCheck = require('./audit/tamper-check');

module.exports = {
  // Layer 1
  aid,
  aat,
  KeyRotationManager,

  // Layer 2
  trust,
  uac,
  scopeIntersection,
  reputation,
  ReputationStore: reputation.ReputationStore,
  calcScore: reputation.calcScore,
  decayScore: reputation.decayScore,

  // 握手
  handshake,
  HandshakeManager: handshake.HandshakeManager,
  HandshakeError: handshake.HandshakeError,
  SECURITY_LEVEL: handshake.SECURITY_LEVEL,

  // Layer 3
  e2eEncryption,
  E2EEncryption: e2eEncryption.E2EEncryption,
  sessionKeys,
  SessionKeyNegotiator: sessionKeys.SessionKeyNegotiator,
  buildConfirm: sessionKeys.buildConfirm,
  processConfirmV2: sessionKeys.processConfirmV2,
  tokenBinding,
  bindToken: tokenBinding.bindToken,
  verifyBinding: tokenBinding.verifyBinding,
  pkce,

  // Layer 4
  replayGuard,
  ReplayGuard: replayGuard.ReplayGuard,
  rateLimiter,
  RateLimiter: rateLimiter.RateLimiter,
  anomalyDetector,
  AnomalyDetector: anomalyDetector.AnomalyDetector,

  // Layer 5
  auditLog,
  AuditLog: auditLog.AuditLog,
  auditQuery,
  AuditQuery: auditQuery.AuditQuery,
  tamperCheck,
  verifyAuditChain: tamperCheck.verifyEntries,
  checkAuditFile: tamperCheck.checkAuditFile,

  // 便捷引用
  TRUST_LEVELS: trust.TRUST_LEVELS,
  TrustLevelManager: trust.TrustLevelManager,
  TrustChainVerifier: trust.TrustChainVerifier,
  WoTCertifier: trust.WoTCertifier,
  UAC_TTL: uac.UAC_TTL,

  generateKeyPair: aid.generateKeyPair,
  generateAID: aid.generateAID,
  verifyAID: aid.verifyAID,
  createAAT: aat.createAAT,
  verifyAAT: aat.verifyAAT,
  createUAC: uac.createUAC,
  verifyUAC: uac.verifyUAC,
  computeScopeIntersection: scopeIntersection.computeScopeIntersection
};
