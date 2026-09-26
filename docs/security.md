# Security

- Secrets are stored outside source code in a root-owned environment file.
- The AI helper runs as the dedicated unprivileged `wazuh-ai` account.
- `/api/*` requires an API key.
- UFW restricts lab service exposure.
- File contents/diffs are not sent to the AI service.
- Security-event strings are treated as untrusted evidence to reduce prompt-injection risk.
- `.gitignore` excludes secrets, private keys, runtime analysis files, and environment files.

## Before publishing
Rotate any credential that has previously appeared in screenshots, terminal history, or chat. Do not publish API keys, passwords, MAC addresses, or personally identifying device names.
