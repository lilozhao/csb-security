#!/usr/bin/env node
/**
 * run-all-tests.js — CSB-Security M1 全量测试运行器
 *
 * 运行所有单元测试
 * 用法: node run-all-tests.js
 */

const { execSync } = require('child_process');
const path = require('path');

const tests = [
  { name: 'aid.js (Layer 1 身份)', file: 'test-aid.js' },
  { name: 'aat.js (Layer 1 身份)', file: 'test-aat.js' },
  { name: 'key-rotation.js (Layer 1 密钥轮换)', file: 'test-key-rotation.js' },
  { name: 'trust-level.js (Layer 2 信任等级)', file: 'test-trust-level.js' }
];

async function runAllTests() {
  console.log('=== CSB-Security M1 全量测试 ===\n');

  let totalPassed = 0;
  let totalFailed = 0;
  let allPassed = true;

  for (const test of tests) {
    console.log(`运行测试: ${test.name}`);
    console.log('─'.repeat(50));

    try {
      const output = execSync(`node ${path.join(__dirname, test.file)}`, {
        encoding: 'utf-8',
        timeout: 30000
      });

      console.log(output);

      const match = output.match(/通过: (\d+)\n失败: (\d+)/);
      if (match) {
        totalPassed += parseInt(match[1]);
        totalFailed += parseInt(match[2]);
      }
    } catch (error) {
      console.log(`❌ 测试失败: ${error.message}`);
      allPassed = false;
      totalFailed++;
    }

    console.log('');
  }

  console.log('═'.repeat(50));
  console.log('=== 汇总结果 ===');
  console.log(`总通过: ${totalPassed}`);
  console.log(`总失败: ${totalFailed}`);
  console.log(`总计: ${totalPassed + totalFailed}`);
  console.log(`通过率: ${((totalPassed / (totalPassed + totalFailed)) * 100).toFixed(1)}%`);

  if (allPassed && totalFailed === 0) {
    console.log('\n✅ 所有测试通过！');
    process.exit(0);
  } else {
    console.log('\n❌ 存在测试失败！');
    process.exit(1);
  }
}

runAllTests().catch(console.error);
