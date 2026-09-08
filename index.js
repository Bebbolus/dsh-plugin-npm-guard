/**
 * dsh-plugin-npm-guard
 * Cordis Plugin for DeepSeek Harness (DSH)
 * NPM package security auditor, typosquatting detector, and supply-chain heuristic scanner.
 */

import { promises as fs } from 'fs';
import path from 'path';

const POPULAR_PACKAGES = [
  'express', 'react', 'react-dom', 'lodash', 'axios', 'chalk', 'debug', 'commander',
  'moment', 'typescript', 'webpack', 'babel-core', 'dotenv', 'cors', 'body-parser',
  'mongoose', 'socket.io', 'vue', 'next', 'rxjs', 'jest', 'eslint', 'prettier',
  'fastify', 'prisma', 'tailwindcss', 'nodemon', 'inquirer', 'yargs'
];

function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

export function checkTyposquatting(pkgName) {
  const cleanName = pkgName.toLowerCase().replace(/^@[^/]+\//, '');
  if (POPULAR_PACKAGES.includes(cleanName)) return null;

  for (const popular of POPULAR_PACKAGES) {
    const dist = levenshteinDistance(cleanName, popular);
    if (dist === 1 && cleanName.length > 3) {
      return {
        suspicious: cleanName,
        target_popular: popular,
        distance: dist,
        warning: `WARNING: The package '${pkgName}' is nearly identical to the popular package '${popular}'. Possible Typosquatting attack!`
      };
    }
  }
  return null;
}

export function analyzeScriptSecurity(scriptContent) {
  const findings = [];
  const patterns = [
    { regex: /curl\s+.*\|\s*(?:bash|sh)/i, level: 'CRITICAL', desc: 'Remote pipe-to-shell execution (curl | bash)' },
    { regex: /wget\s+.*\|\s*(?:bash|sh)/i, level: 'CRITICAL', desc: 'Remote pipe-to-shell execution (wget | bash)' },
    { regex: /base64\s+-d/i, level: 'HIGH', desc: 'Obfuscated base64 shell decoding (base64 -d)' },
    { regex: /Buffer\.from\s*\([^)]*['"]base64['"]\)/i, level: 'HIGH', desc: 'Node.js Base64 payload decoding (Buffer.from)' },
    { regex: /\batob\s*\(/i, level: 'HIGH', desc: 'In-memory base64 decoding (atob)' },
    { regex: /(?:nc|netcat|ncat)\s+-e/i, level: 'CRITICAL', desc: 'Netcat reverse shell with -e flag' },
    { regex: /\/dev\/tcp\/[0-9.]+\/[0-9]+/i, level: 'CRITICAL', desc: 'Native bash TCP reverse shell' },
    { regex: /child_process\.(?:exec|spawn|fork|execSync|spawnSync)\s*\(/i, level: 'HIGH', desc: 'Child process execution in lifecycle script' },
    { regex: /(?:fs\.readFile|fs\.readFileSync)\s*\([^)]*(?:id_rsa|\.ssh|\.aws|\.env)/i, level: 'CRITICAL', desc: 'Attempted exfiltration of SSH, AWS or .env secrets' },
    { regex: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, level: 'MEDIUM', desc: 'Direct network request to numeric raw IP address' },
    { regex: /\b(?:python|python3|perl|ruby)\s+-c\s+/i, level: 'HIGH', desc: 'Inline scripting interpreter execution' },
    { regex: /eval\s*\(/i, level: 'HIGH', desc: 'Unsafe dynamic eval() execution' },
    { regex: /process\.env\.[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)/i, level: 'MEDIUM', desc: 'Access to secret credentials in environment variables' }
  ];

  for (const p of patterns) {
    if (p.regex.test(scriptContent)) {
      findings.push({ severity: p.level, description: p.desc, match: scriptContent.slice(0, 120) });
    }
  }
  return findings;
}

export const name = 'tool-npm-guard';
export const inject = ['tools'];

export function apply(ctx) {
  if (ctx.tools && typeof ctx.tools.register === 'function') {
    ctx.tools.register({
      name: 'npm_security_audit',
      description: 'Audit a package.json or npm package name for security vulnerabilities, malicious scripts, and typosquatting.',
      parameters: {
        package_name: { type: 'string', required: false, description: 'NPM package name to verify against typosquatting' },
        target_path: { type: 'string', required: false, description: 'Path to package.json file to audit' }
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            safe: { type: 'boolean' },
            typosquatting: { type: 'array' },
            script_risks: { type: 'array' }
          }
        },
        render: (_args, value) => [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }]
      },
      execute: async (args) => {
        const results = { safe: true, typosquatting: [], script_risks: [] };

        if (args.package_name) {
          const typo = checkTyposquatting(args.package_name);
          if (typo) {
            results.safe = false;
            results.typosquatting.push(typo);
          }
        }

        if (args.target_path) {
          try {
            const raw = await fs.readFile(path.resolve(args.target_path), 'utf8');
            const pkg = JSON.parse(raw);
            const scripts = pkg.scripts || {};

            for (const [sName, sCmd] of Object.entries(scripts)) {
              const findings = analyzeScriptSecurity(sCmd);
              if (findings.length > 0) {
                results.safe = false;
                results.script_risks.push({ script_name: sName, command: sCmd, findings });
              }
            }
          } catch (err) {
            results.error = `Failed to read package.json file: ${err.message}`;
          }
        }

        return results;
      }
    });
  }
}

export default {
  name,
  inject,
  apply,
  checkTyposquatting,
  analyzeScriptSecurity
};
