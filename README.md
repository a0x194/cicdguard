# CICDGuard

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/go-%3E%3D1.19-00ADD8.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg" alt="Platform">
</p>

<p align="center">
  <b>CI/CD Pipeline Security Scanner</b><br>
  <sub>Detect security vulnerabilities in GitHub Actions, GitLab CI, Jenkins, and more</sub>
</p>

---

## Features

- **Multi-platform support:**
  - GitHub Actions
  - GitLab CI
  - Jenkins (Jenkinsfile)
  - CircleCI
  - Travis CI
  - Azure Pipelines

- **Security checks:**
  - Hardcoded secrets and credentials
  - Command injection vulnerabilities
  - Dangerous workflow triggers
  - Privilege escalation risks
  - Script injection via user input
  - Unpinned action versions

- **Flexible scanning:**
  - Local directory scanning
  - Single file analysis
  - Remote GitHub repository scanning via API

## Installation

### From Source
```bash
git clone https://github.com/a0x194/cicdguard.git
cd cicdguard
go build -o cicdguard main.go
```

### Download Binary
Check the [Releases](https://github.com/a0x194/cicdguard/releases) page for pre-built binaries.

## Usage

### Scan local directory
```bash
./cicdguard -d ./my-project
```

### Scan single file
```bash
./cicdguard -f .github/workflows/ci.yml
```

### Scan GitHub repository
```bash
./cicdguard -repo owner/repo
./cicdguard -repo owner/repo -token ghp_xxxx  # For private repos
```

### Output as JSON
```bash
./cicdguard -d ./project -json -o results.json
```

### Flags
| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Directory to scan | - |
| `-f` | Single file to scan | - |
| `-repo` | GitHub repository (owner/repo) | - |
| `-token` | GitHub token for API access | - |
| `-v` | Verbose output | false |
| `-o` | Output file | - |
| `-json` | Output as JSON | false |
| `-version` | Show version | - |

## Vulnerability Categories

### Secrets Detection
- AWS Access Keys & Secret Keys
- GitHub/GitLab Tokens
- Slack Tokens & Webhooks
- Private Keys (RSA, EC, etc.)
- Google API Keys
- Generic API Keys & Passwords
- JWT Tokens
- Basic Auth & Bearer Tokens

### Workflow Security Issues

| Issue | Severity | Description |
|-------|----------|-------------|
| `pull_request_target` trigger | 🔴 Critical | Runs with base repo permissions |
| Command Injection | 🔴 Critical | User input in run commands |
| Script Injection | 🔴 High | Event data in scripts |
| Secrets in Logs | 🔴 High | Echoing secret values |
| Privileged Container | 🔴 High | Container with elevated privileges |
| `workflow_run` trigger | 🟡 High | Can be triggered by forks |
| Unpinned Actions | 🟡 Medium | Mutable version references |
| Self-hosted Runner | 🟡 Medium | Potential isolation issues |

## Example Output

```
   _____ _____ _____ _____   _____                     _
  / ____|_   _/ ____|  __ \ / ____|                   | |
 | |      | || |    | |  | | |  __ _   _  __ _ _ __ __| |
 | |      | || |    | |  | | | |_ | | | |/ _' | '__/ _' |
 | |____ _| || |____| |__| | |__| | |_| | (_| | | | (_| |
  \_____|_____\_____|_____/ \_____|\__,_|\__,_|_|  \__,_|

  CI/CD Security Scanner v1.0.0
  Author: a0x194 | https://www.tryharder.space
  More tools: https://www.tryharder.space/tools/

[*] Scanning directory: ./my-project

[*] Scan complete! Found 3 issue(s)

[CRITICAL] Command Injection via Title
  ├─ File: .github/workflows/pr.yml:15
  ├─ Category: Workflow Security
  ├─ Description: User-controlled input directly used in command
  └─ Remediation: Use environment variables or sanitize the input

[HIGH] Secrets in Logs
  ├─ File: .github/workflows/deploy.yml:28
  ├─ Category: Workflow Security
  ├─ Description: Secret may be exposed in workflow logs
  └─ Remediation: Avoid echoing secrets, use masking if necessary

[MEDIUM] Unpinned Action Version
  ├─ File: .github/workflows/ci.yml:10
  ├─ Category: Workflow Security
  ├─ Description: Using unpinned or mutable action version
  └─ Remediation: Pin actions to specific commit SHA for security

📊 Summary: 1 Critical, 1 High, 1 Medium, 0 Low
```

## Integration

### Pre-commit Hook
```bash
#!/bin/bash
cicdguard -d . -json | jq '.[] | select(.Severity == "CRITICAL")' | grep -q . && exit 1
exit 0
```

### GitHub Action
```yaml
- name: CI/CD Security Scan
  run: |
    cicdguard -d . -json -o security-results.json
    if jq -e '.[] | select(.Severity == "CRITICAL")' security-results.json; then
      echo "Critical security issues found!"
      exit 1
    fi
```

## References

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Keeping your GitHub Actions secure](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Security](https://owasp.org/www-project-devsecops-guideline/)

## Disclaimer

⚠️ **This tool is for security assessment purposes.**

Use this tool to:
- Audit your own CI/CD pipelines
- Review security before merging changes
- Integrate into your security workflow

Always follow responsible disclosure practices.

## Author

**a0x194** - [https://www.tryharder.space](https://www.tryharder.space)

More security tools: [https://www.tryharder.space/tools/](https://www.tryharder.space/tools/)

## License

MIT License - see [LICENSE](LICENSE) file for details.
