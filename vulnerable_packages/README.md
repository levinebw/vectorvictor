# Vulnerable Packages

Examples of applications using vulnerable open-source packages for SCA (Software Composition Analysis) testing.

## Contents

### n8n-workflow/

Workflow automation service using a vulnerable version of n8n affected by **CVE-2026-21858** (CVSS 10.0 Critical).

- **Vulnerability**: Content-Type confusion enabling unauthenticated RCE
- **Affected versions**: n8n >= 1.65.0 and < 1.121.0
- **Fixed version**: 1.121.0

## Use Cases

- Testing SCA scanner detection of critical CVEs
- Validating vulnerability enrichment (CVSS, EPSS, KEV status)
- Demonstrating supply chain risk from vulnerable dependencies
- Training on dependency vulnerability remediation

## Adding New Examples

When adding vulnerable package examples:

1. Create a subdirectory with a descriptive name
2. Include the package manifest (package.json, requirements.txt, go.mod, etc.)
3. Document the specific CVE(s) and affected versions in a README
4. Include remediation guidance
