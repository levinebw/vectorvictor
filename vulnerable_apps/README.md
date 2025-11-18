# Vulnerable Python Applications - Security Scanner Demo

⚠️ **WARNING**: These applications contain intentional security vulnerabilities for educational and testing purposes only. **NEVER** deploy these in production or use this code in real applications!

## Purpose

This collection of Python applications demonstrates common OWASP Top 10 vulnerabilities. It's designed to be used as test cases for vulnerability scanners, security training, and educational purposes.

## Vulnerability Categories

### 1. SQL Injection (`sql_injection.py`)
**OWASP A03:2021 - Injection**

Demonstrates:
- Direct string concatenation in SQL queries
- String formatting vulnerabilities
- Unparameterized queries

Example exploitation:
```python
get_user_by_username("admin' OR '1'='1")
login_user("admin' --", "anything")
```

### 2. Cross-Site Scripting - XSS (`xss_vulnerabilities.py`)
**OWASP A03:2021 - Injection**

Demonstrates:
- Reflected XSS
- Stored XSS
- DOM-based XSS
- XSS in error messages

Example exploitation:
```
/search?q=<script>alert('XSS')</script>
/profile?username=<img src=x onerror=alert('XSS')>
```

### 3. Insecure Deserialization (`insecure_deserialization.py`)
**OWASP A08:2021 - Software and Data Integrity Failures**

Demonstrates:
- Unsafe pickle usage
- YAML deserialization vulnerabilities
- Arbitrary code execution via serialized objects

Vulnerabilities:
- `pickle.loads()` on untrusted data
- `yaml.load()` without SafeLoader
- No signature verification

### 4. Command Injection (`command_injection.py`)
**OWASP A03:2021 - Injection**

Demonstrates:
- OS command injection via `os.system()`
- Subprocess with `shell=True`
- Unsanitized user input in shell commands

Example exploitation:
```python
ping_host("8.8.8.8; cat /etc/passwd")
check_dns("google.com && rm -rf /tmp/*")
```

### 5. Hardcoded Secrets (`hardcoded_secrets.py`)
**OWASP A02:2021 - Cryptographic Failures**
**OWASP A05:2021 - Security Misconfiguration**

Demonstrates:
- Hardcoded database credentials
- API keys in source code
- AWS credentials exposure
- Hardcoded encryption keys
- JWT secrets in code
- GitHub tokens
- Private SSH keys

### 6. Path Traversal (`path_traversal.py`)
**OWASP A01:2021 - Broken Access Control**

Demonstrates:
- Directory traversal in file operations
- Unsanitized file paths
- Bypass of intended directory restrictions

Example exploitation:
```
/download?file=../../etc/passwd
/read?filename=../../../../etc/shadow
/image?img=../../../secret/keys.txt
```

### 7. Broken Authentication (`broken_authentication.py`)
**OWASP A07:2021 - Identification and Authentication Failures**

Demonstrates:
- Weak session management
- No rate limiting
- Plaintext passwords
- Predictable session tokens
- Missing CSRF protection
- Insecure password reset
- No account lockout

### 8. XML External Entity - XXE (`xxe_vulnerabilities.py`)
**OWASP A05:2021 - Security Misconfiguration**

Demonstrates:
- XXE via ElementTree
- lxml parser vulnerabilities
- SOAP request parsing
- XML config file processing
- SVG file XXE

Example XXE payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 9. Server-Side Request Forgery - SSRF (`ssrf_vulnerabilities.py`)
**OWASP A10:2021 - Server-Side Request Forgery**

Demonstrates:
- Unvalidated URL fetching
- Internal network access
- Cloud metadata exploitation
- Webhook vulnerabilities

Example exploitation:
```
/fetch_url?url=http://169.254.169.254/latest/meta-data/
/proxy?target=http://localhost:8080/admin
/webhook?webhook_url=http://internal-service:5000/
```

### 10. Weak Cryptography (`weak_cryptography.py`)
**OWASP A02:2021 - Cryptographic Failures**

Demonstrates:
- MD5/SHA1 for password hashing
- DES encryption
- RC4 cipher usage
- XOR encryption
- Weak random number generation
- No salt in hashing
- Static IVs
- Homemade cryptography

## Usage for Vulnerability Scanner Testing

### Running Individual Tests

```bash
# SQL Injection test
python vulnerable_apps/sql_injection.py

# Command Injection test
python vulnerable_apps/command_injection.py

# Weak Cryptography test
python vulnerable_apps/weak_cryptography.py
```

### Flask Application Tests

Some modules require Flask to run:

```bash
# Install dependencies
pip install flask pyyaml lxml cryptography pycryptodome mysql-connector-python boto3

# Run XSS vulnerable app
python vulnerable_apps/xss_vulnerabilities.py

# Run Path Traversal vulnerable app
python vulnerable_apps/path_traversal.py

# Run SSRF vulnerable app
python vulnerable_apps/ssrf_vulnerabilities.py
```

## Scanner Testing Checklist

Your vulnerability scanner should detect:

- [ ] SQL injection patterns (string concatenation, format strings)
- [ ] Command injection (os.system, subprocess with shell=True)
- [ ] XSS vulnerabilities (unescaped user input in HTML)
- [ ] Hardcoded secrets (API keys, passwords, tokens)
- [ ] Path traversal (unsanitized file paths)
- [ ] Insecure deserialization (pickle.loads, yaml.load)
- [ ] Weak cryptography (MD5, SHA1, DES, RC4)
- [ ] XXE vulnerabilities (unsafe XML parsing)
- [ ] SSRF vulnerabilities (unvalidated URL fetching)
- [ ] Authentication issues (weak sessions, no rate limiting)

## Expected Vulnerability Counts

| Vulnerability Type | Number of Instances |
|-------------------|---------------------|
| SQL Injection | 3 functions |
| XSS | 4 endpoints |
| Command Injection | 8 functions |
| Hardcoded Secrets | 15+ instances |
| Path Traversal | 10 functions |
| Insecure Deserialization | 6 functions |
| Weak Cryptography | 15+ functions |
| XXE | 7 functions |
| SSRF | 11 endpoints |
| Broken Authentication | 8+ issues |

## Contributing

This is a demo project for vulnerability scanner testing. Feel free to add more vulnerability examples following the existing pattern.

## License

This code is provided for educational purposes only. Use at your own risk.

## Disclaimer

⚠️ **DO NOT USE THIS CODE IN PRODUCTION**

These applications are intentionally vulnerable and should only be used in isolated, controlled environments for:
- Testing vulnerability scanners
- Security training
- Educational demonstrations
- CTF challenges
- Security research

The authors are not responsible for any misuse of this code.
