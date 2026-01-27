# N8N Workflow Service

Example workflow automation service using n8n.

## Vulnerability

This package includes **n8n v1.100.0**, which is affected by **CVE-2026-21858** (CVSS 10.0 Critical).

### CVE-2026-21858: Content-Type Confusion RCE

- **Affected versions**: n8n >= 1.65.0 and < 1.121.0
- **Fixed version**: 1.121.0
- **CWE**: CWE-20 (Improper Input Validation)
- **Attack vector**: Unauthenticated remote code execution via Form Webhook

### Description

A content-type confusion vulnerability in n8n's Form Webhook handling allows an unauthenticated attacker to:

1. Read arbitrary files from the n8n instance
2. Extract database credentials and session secrets
3. Forge administrator sessions
4. Execute arbitrary commands on the host

### Remediation

Upgrade to n8n version 1.121.0 or later:

```json
{
  "dependencies": {
    "n8n": "1.121.0"
  }
}
```

### References

- [NVD - CVE-2026-21858](https://nvd.nist.gov/vuln/detail/CVE-2026-21858)
- [GitHub Security Advisory GHSA-v4pr-fm98-w9pg](https://github.com/n8n-io/n8n/security/advisories/GHSA-v4pr-fm98-w9pg)
