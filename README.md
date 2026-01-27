# VectorVictor

*"What's our vector, Victor?"* - A collection of intentionally vulnerable code examples for security testing, training, and educational purposes.

> **Fun fact:** This repo name is a tribute to the classic *Airplane!* quote, but here we're navigating through security vulnerabilities instead of flight paths. Clearance, Clarence?

## ⚠️ Warning

**DO NOT deploy these applications. These are sample code snippets that have not been tested as executables.**

This repository contains deliberately insecure code designed to demonstrate common security vulnerabilities. All examples are for educational and authorized security testing purposes only.

## 📋 Contents

### 🤖 Vulnerable LLM Agent (`vulnerable_llm_agent/`)

Example agentic LLM application demonstrating **OWASP Top 10 for LLM (2025)** vulnerabilities:

- **agent.py** - Main vulnerable agent with comprehensive security issues
- **prompt_injection_examples.py** - LLM01: Direct/indirect prompt injection and jailbreaks
- **sensitive_data_exposure.py** - LLM02: Hardcoded secrets, PII leakage, system prompt exposure
- **excessive_agency.py** - LLM06: Unrestricted capabilities and auto-execution
- **config.yaml** - Vulnerable configuration with hardcoded credentials
- **requirements.txt** - Python dependencies

**OWASP Top 10 for LLM Coverage:**
1. ✓ **LLM01: Prompt Injection** - No input validation, direct concatenation
2. ✓ **LLM02: Sensitive Information Disclosure** - Hardcoded secrets, PII exposure
3. ✓ **LLM03: Supply Chain Vulnerabilities** - No model verification, untrusted sources
4. ✓ **LLM04: Data and Model Poisoning** - Insecure pickle, no data validation
5. ✓ **LLM05: Improper Output Handling** - Auto-executing commands, eval() usage
6. ✓ **LLM06: Excessive Agency** - Unrestricted file/DB/API access, no approvals
7. ✓ **LLM07: System Prompt Leakage** - Weak protection, credentials in prompts
8. ✓ **LLM08: Vector and Embedding Weaknesses** - No validation, poisoning risk
9. ✓ **LLM09: Misinformation** - No fact-checking or source attribution
10. ✓ **LLM10: Unbounded Consumption** - No rate limits or resource constraints

**References:**
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Gandalf Lakera AI Prompt Injection Challenge](https://gandalf.lakera.ai/)
- [Prompt Injection Primer for Engineers](https://github.com/jthack/PIPE)
- [LLM Security Guide](https://llmsecurity.net/)

### 🐳 Vulnerable Dockerfiles (`vulnerable_dockerfiles/`)

Examples of insecure Docker configurations and container practices:

- **Dockerfile.python-vulnerable** - Python app with multiple security issues
- **Dockerfile.nodejs-vulnerable** - Node.js app with vulnerabilities
- **Dockerfile.java-vulnerable** - Java app with security flaws
- **Dockerfile.secrets-exposed** - Hardcoded secrets and credentials
- **Dockerfile.rootful-privileged** - Privileged containers running as root
- **Dockerfile.multistage-bad** - Insecure multi-stage builds
- **Dockerfile.n8n-vulnerable** - n8n with CVE-2026-21858 (CVSS 10.0)
- **docker-compose.vulnerable.yml** - Insecure Docker Compose configuration

### 🏗️ Vulnerable Terraform (`vulnerable_terraform/`)

Infrastructure-as-Code examples with security misconfigurations:

- **aws_s3_vulnerable.tf** - Publicly accessible S3 buckets, weak encryption
- **aws_ec2_vulnerable.tf** - Insecure EC2 instances, security groups, SSH keys
- **aws_rds_vulnerable.tf** - Unencrypted databases, weak passwords, public access
- **aws_iam_vulnerable.tf** - Overly permissive IAM policies and roles
- **aws_misc_vulnerable.tf** - Additional AWS security issues

### 📦 Vulnerable Packages (`vulnerable_packages/`)

Examples of applications using vulnerable open-source dependencies for SCA testing:

- **n8n-workflow/** - Workflow automation with n8n v1.100.0 (CVE-2026-21858, CVSS 10.0)

### 🌐 Vulnerable Web Applications (`vulnerable_apps/`)

Python web application examples demonstrating **OWASP Top 10 (2021)** vulnerabilities:

- SQL Injection
- Cross-Site Scripting (XSS)
- XML External Entity (XXE)
- Command Injection
- Path Traversal
- Server-Side Request Forgery (SSRF)
- Insecure Deserialization
- Broken Authentication
- Weak Cryptography
- Hardcoded Secrets

## 🎯 Use Cases

- **Security Training** - Learn to identify and exploit common vulnerabilities
- **Tool Testing** - Validate security scanners and SAST/DAST tools
- **CTF Challenges** - Practice offensive security techniques
- **Secure Code Reviews** - Learn what NOT to do
- **Penetration Testing** - Practice in authorized environments

## 🚀 Getting Started

Each directory contains its own README with specific setup instructions and vulnerability descriptions.

### Prerequisites

- Python 3.8+
- Docker & Docker Compose
- Terraform (for IaC examples)
- Virtual environment recommended

### Quick Start

```bash
# Clone the repository
git clone https://github.com/levinebw/vectorvictor.git
cd vectorvictor

# Navigate to specific vulnerability examples
cd vulnerable_llm_agent
pip install -r requirements.txt
python agent.py
```

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## ⚖️  Disclaimer

This repository is for **authorized security testing and educational purposes only**. 

## 🤝 Contributing

Contributions of additional vulnerability examples are welcome. Please ensure:

- Code is clearly documented
- Vulnerabilities are explicitly noted
- Examples are realistic and educational
- No actual sensitive data is included


## 📄 License

This project is provided "as-is" for educational and demonstration purposes. See LICENSE file for details.

## 🔗 Related Projects

- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
- [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)

---

