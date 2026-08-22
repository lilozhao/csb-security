/**
 * CSB-Security 统一入口
 *
 * CSB-Security v1.0 落地实现（M1: 身份层 + 信任等级）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22
 */

// Layer 1: 身份安全
const aid = require('./identity/aid');
const aat = require('./identity/aat');
const { KeyRotationManager } = require('./identity/key-rotation');

// Layer 2: 授权控制（M1 部分：信任等级）
const trust = require('./authz/trust-level');

module.exports = {
  // Layer 1
  aid,
  aat,
  KeyRotationManager,

  // Layer 2 (M1)
  trust,

  // 便捷引用
  TRUST_LEVELS: trust.TRUST_LEVELS,
  TrustLevelManager: trust.TrustLevelManager,
  TrustChainVerifier: trust.TrustChainVerifier,
  WoTCertifier: trust.WoTCertifier,
  ReputationStore: trust.ReputationStore,

  generateKeyPair: aid.generateKeyPair,
  generateAID: aid.generateAID,
  verifyAID: aid.verifyAID,
  createAAT: aat.createAAT,
  verifyAAT: aat.verifyAAT
};
