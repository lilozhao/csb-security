/**
 * CSB-Security Layer 2: 权限交集计算
 *
 * 协议: CSB-Security v1.0 §3.3
 * 最终有效权限 = 用户授权范围 ∩ 响应方允许范围
 *
 * 规则:
 *  - 交集为空时，不得发放访问权限
 *  - 响应方可以进一步缩减权限范围
 *  - 权限缩减必须记录（返回 denied 原因）
 *
 * 维护者: 若兰 🌸
 * 日期: 2026-08-22 (M2)
 */

/**
 * 计算权限交集
 *
 * @param {string[]} requestedScopes 发起方请求的 scope
 * @param {string[]} userScopes 用户授权范围（UAC.scopes）
 * @param {string[]} calleeScopes 响应方允许范围
 * @returns {{granted: string[], denied: Array<{scope: string, reason: string}>}}
 */
function computeScopeIntersection(requestedScopes, userScopes, calleeScopes) {
  const userSet = new Set(userScopes || []);
  const calleeSet = new Set(calleeScopes || []);

  const granted = [];
  const denied = [];

  for (const scope of requestedScopes) {
    if (!userSet.has(scope)) {
      denied.push({ scope, reason: 'user_policy' });
    } else if (!calleeSet.has(scope)) {
      denied.push({ scope, reason: 'callee_policy' });
    } else {
      granted.push(scope);
    }
  }

  return { granted, denied };
}

/**
 * 判断是否可发放访问权限（交集非空）
 */
function canGrant(result) {
  return result.granted.length > 0;
}

/**
 * 合并两次缩减（用户缩减 + 响应方缩减），保留原因
 */
function mergeDenials(a, b) {
  const map = new Map();
  for (const d of [...a, ...b]) {
    const existing = map.get(d.scope);
    if (!existing) {
      map.set(d.scope, d);
    } else if (!existing.reason.includes(d.reason)) {
      existing.reason = `${existing.reason}+${d.reason}`;
    }
  }
  return [...map.values()];
}

module.exports = {
  computeScopeIntersection,
  canGrant,
  mergeDenials
};
