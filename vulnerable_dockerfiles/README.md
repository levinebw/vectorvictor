# Vulnerable Dockerfiles - Security Scanner Demo

⚠️ **WARNING**: These Dockerfiles contain intentional security vulnerabilities. **NEVER** use these in production or build these images on production systems!

## Purpose

This collection demonstrates common container security vulnerabilities and Docker anti-patterns. Use these examples to test:
- Container security scanners (Trivy, Snyk, Anchore, Clair)
- Dockerfile linters (Hadolint, Dockle)
- CI/CD security gates
- Security training and education

## Dockerfile Examples

### 1. Node.js Application (`Dockerfile.nodejs-vulnerable`)

**Vulnerabilities:**
- Using `latest` tag (no version pinning)
- Running as root user
- Hardcoded secrets in ENV variables
- Installing unnecessary packages
- No apt cache cleanup
- Copying entire build context
- Multiple exposed ports
- No healthcheck
- npm install without audit

**Example Issues:**
```dockerfile
FROM node:latest  # VULNERABLE

ENV DB_PASSWORD="SuperSecret123!"  # VULNERABLE
ENV API_KEY="sk-1234567890abcdef"  # VULNERABLE

COPY . .  # VULNERABLE: May include .git, .env files

CMD ["npm", "start"]  # VULNERABLE: Running as root
```

### 2. Python Application (`Dockerfile.python-vulnerable`)

**Vulnerabilities:**
- Outdated Python version
- Installing attack tools (nmap, tcpdump, netcat)
- Hardcoded database URLs and passwords
- Flask debug mode enabled
- Disabling SSL verification
- World-writable directories (chmod 777)
- pip install without version pinning
- No multi-stage build
- Shell form CMD

**Example Issues:**
```dockerfile
FROM python:3.7  # VULNERABLE: Old version

ENV FLASK_DEBUG=1  # VULNERABLE: Debug in production
ENV DATABASE_URL="postgresql://admin:password@db"  # VULNERABLE

RUN chmod 777 /tmp/uploads  # VULNERABLE

CMD python app.py  # VULNERABLE: Shell form, running as root
```

### 3. Multi-Stage Build (`Dockerfile.multistage-bad`)

**Vulnerabilities:**
- Secrets in build arguments
- Copying .netrc with credentials to final image
- Using full Ubuntu instead of distroless
- Old Go and Ubuntu versions
- Installing shells and debug tools in production
- Overly permissive file permissions
- Shell form CMD
- Secrets persist in build layers

**Example Issues:**
```dockerfile
ARG GITHUB_TOKEN=ghp_1234567890  # VULNERABLE: Secret in build arg

FROM ubuntu:18.04  # VULNERABLE: Old version, large base image

COPY --from=builder /build/.netrc /root/.netrc  # VULNERABLE

RUN chmod 777 /app  # VULNERABLE
```

### 4. Java Application (`Dockerfile.java-vulnerable`)

**Vulnerabilities:**
- Full JDK instead of JRE
- JMX without authentication/SSL
- Remote debugging enabled in production
- Building inside production image (Maven included)
- Skipping tests in build
- Hardcoded JDBC URLs with credentials
- Disabling SSL/TLS verification
- No multi-stage build

**Example Issues:**
```dockerfile
FROM openjdk:latest  # VULNERABLE

ENV DB_PASSWORD="admin123"  # VULNERABLE
ENV JAVA_OPTS="-Dcom.sun.management.jmxremote.authenticate=false"  # VULNERABLE

RUN mvn clean package -DskipTests  # VULNERABLE

CMD java -agentlib:jdwp=...  # VULNERABLE: Debug mode in production
```

### 5. Secrets Exposure (`Dockerfile.secrets-exposed`)

**Vulnerabilities:**
- API keys in ENV variables
- AWS credentials in Dockerfile
- Secrets in build arguments
- .env files with passwords
- SSH private keys in image
- .git directory copied (contains history)
- Credentials in ~/.aws/credentials
- Database connection strings
- Secrets in removed files (still in layers!)

**Example Issues:**
```dockerfile
ENV API_KEY="sk-proj-1234567890"  # VULNERABLE: Visible in docker inspect

ARG GITHUB_TOKEN="ghp_xxxx"  # VULNERABLE: Visible in docker history

RUN echo "password123" > /tmp/secret && rm /tmp/secret
# VULNERABLE: Still in layer even after removal!

COPY .git /app/.git  # VULNERABLE: Exposes git history
```

### 6. Privilege Escalation (`Dockerfile.rootful-privileged`)

**Vulnerabilities:**
- Running as root (no USER directive)
- Passwordless sudo
- World-writable directories
- SUID binaries
- User in privileged groups (root, docker, wheel)
- Overly permissive file permissions
- Installing docker-cli in container
- All files executable (chmod 777)

**Example Issues:**
```dockerfile
RUN echo "appuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers  # VULNERABLE

RUN chmod 777 /app /data /logs  # VULNERABLE

RUN chmod u+s /bin/su /bin/sudo  # VULNERABLE: SUID bits

# Missing: USER appuser
```

### 7. Docker Compose (`docker-compose.vulnerable.yml`)

**Vulnerabilities:**
- privileged: true
- Host network mode
- Host PID namespace
- Mounting Docker socket
- Mounting host root filesystem (/)
- All capabilities (cap_add: ALL)
- Disabled seccomp and AppArmor
- Hardcoded secrets in environment
- No resource limits
- Databases exposed to 0.0.0.0
- Weak default passwords
- No TLS between services

**Example Issues:**
```yaml
privileged: true  # VULNERABLE

network_mode: "host"  # VULNERABLE

volumes:
  - /var/run/docker.sock:/var/run/docker.sock  # VULNERABLE
  - /:/host  # VULNERABLE: Entire host filesystem

environment:
  - DATABASE_PASSWORD=postgres  # VULNERABLE

ports:
  - "0.0.0.0:3306:3306"  # VULNERABLE: Database exposed
```

## Security Scanner Testing

### Expected Detections

| Category | Vulnerability Count |
|----------|-------------------|
| Running as Root | 7 files |
| Hardcoded Secrets | 50+ instances |
| Outdated Base Images | 5 images |
| Missing Version Pins | 10+ instances |
| Unnecessary Packages | 30+ packages |
| Excessive Permissions | 15+ instances |
| Missing Healthchecks | 6 files |
| Privilege Escalation | 10+ issues |

### Testing with Common Tools

#### Trivy
```bash
trivy config vulnerable_dockerfiles/
trivy image vulnerable-app:latest
```

#### Hadolint
```bash
hadolint vulnerable_dockerfiles/Dockerfile.nodejs-vulnerable
hadolint vulnerable_dockerfiles/Dockerfile.python-vulnerable
```

#### Snyk
```bash
snyk container test vulnerable-app:latest
snyk iac test vulnerable_dockerfiles/
```

#### Docker Scan
```bash
docker scan vulnerable-app:latest
```

#### Dockle
```bash
dockle vulnerable-app:latest
```

#### Anchore
```bash
anchore-cli image add vulnerable-app:latest
anchore-cli image vuln vulnerable-app:latest all
```

## Vulnerability Categories

### 1. Base Image Issues
- Using `latest` tag (unpredictable, no version control)
- Outdated versions with known CVEs
- Full OS images instead of minimal (alpine, distroless)
- Including unnecessary tools and packages

### 2. Secrets Management
- Hardcoded secrets in ENV, ARG, RUN commands
- Secrets in git history (.git directory)
- Credentials in config files
- API keys visible in docker inspect/history
- Secrets persisting in intermediate layers

### 3. Privilege & Permissions
- Running as root (uid 0)
- No USER directive
- World-writable directories (chmod 777)
- SUID binaries
- Privileged mode
- Unnecessary capabilities

### 4. Supply Chain Security
- No version pinning for dependencies
- Installing from untrusted sources
- No signature verification
- Including build tools in production
- No vulnerability scanning

### 5. Network Security
- Exposing all ports to 0.0.0.0
- Running in host network mode
- No TLS/encryption
- Unnecessary port exposures

### 6. Operational Security
- Debug mode enabled in production
- Remote debugging exposed
- No logging or monitoring
- No healthchecks
- Missing resource limits

## Security Best Practices

### ✅ Do This Instead

```dockerfile
# Use specific versions
FROM node:18.17.0-alpine3.18 AS builder

# Multi-stage build
WORKDIR /build
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Minimal production image
FROM gcr.io/distroless/nodejs18-debian11

# Copy only what's needed
COPY --from=builder --chown=nonroot:nonroot /build/node_modules ./node_modules
COPY --chown=nonroot:nonroot . .

# Run as non-root
USER nonroot

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node healthcheck.js || exit 1

# Resource limits (in docker-compose)
# deploy:
#   resources:
#     limits:
#       cpus: '0.5'
#       memory: 512M

# Use secrets properly (Docker Swarm or Kubernetes)
# RUN --mount=type=secret,id=api_key \
#     API_KEY=$(cat /run/secrets/api_key) && ...

# Exec form CMD
CMD ["node", "server.js"]
```

### Secure Docker Compose

```yaml
version: '3.8'

services:
  web:
    image: app:1.2.3  # Version pinned
    read_only: true  # Read-only root filesystem

    cap_drop:
      - ALL  # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE  # Add only what's needed

    security_opt:
      - no-new-privileges:true

    user: "1000:1000"  # Non-root user

    secrets:
      - db_password  # Use Docker secrets

    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 3s
      retries: 3

secrets:
  db_password:
    external: true
```

## .dockerignore Example

```
# Prevent secret leakage
.env
.env.*
.git
.gitignore
*.md
.vscode
.idea

# Prevent unnecessary files
node_modules
npm-debug.log
coverage
.pytest_cache
__pycache__

# Credentials
*.pem
*.key
*.crt
*-key.json
credentials.json
.aws
.ssh
```

## CIS Docker Benchmark Violations

These Dockerfiles violate multiple CIS Docker Benchmark recommendations:
- 4.1: Create a user for the container
- 4.2: Use trusted base images
- 4.3: Do not install unnecessary packages
- 4.6: Add HEALTHCHECK instruction
- 4.7: Do not use update instructions alone
- 4.9: Use COPY instead of ADD
- 4.10: Do not store secrets in Dockerfiles

## References

- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [NIST Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

## Disclaimer

⚠️ **DO NOT BUILD OR RUN THESE IMAGES IN PRODUCTION**

These Dockerfiles are intentionally vulnerable for:
- Testing container security scanners
- Security training and education
- Demonstrating security anti-patterns
- CI/CD security gate testing

Building or running these images creates serious security vulnerabilities. The authors are not responsible for any security incidents resulting from misuse.

## License

Educational use only.
