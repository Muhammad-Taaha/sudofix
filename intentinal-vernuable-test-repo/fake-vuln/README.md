# Security Vulnerabilities Test Suite

This repository contains intentionally vulnerable code and configurations for testing security scanning tools. These files should **NEVER** be used in production environments.

## Purpose

These files are designed to test the detection capabilities of security scanning tools across three main categories:
- **SCA (Software Composition Analysis)**: Vulnerable dependencies
- **SAST (Static Application Security Testing)**: Code-level vulnerabilities
- **IaC (Infrastructure as Code)**: Infrastructure misconfigurations

## File Overview

### Python Files

#### 1. `python_sast_vulnerabilities.py`
**Category**: SAST  
**Vulnerabilities**:
- SQL Injection
- Command Injection
- Path Traversal
- Insecure Deserialization (pickle)
- Weak Cryptography (MD5)
- Code Injection (eval)
- Insecure Random Number Generation
- XSS (Cross-Site Scripting)
- Subprocess with shell=True
- Hardcoded Credentials
- Debug Mode in Production

#### 2. `python_additional_vulnerabilities.py`
**Category**: SAST  
**Vulnerabilities**:
- XML External Entity (XXE) Injection
- YAML Unsafe Load
- LDAP Injection
- Weak Ciphers (DES, ARC2)
- Insecure JWT (none algorithm)
- Race Conditions (TOCTOU)
- Insecure Temporary Files
- Disabled Certificate Validation
- Server-Side Request Forgery (SSRF)
- Insufficient Entropy
- Directory Traversal in Archives
- Format String Vulnerabilities
- XPath Injection
- Weak SSL/TLS Configuration
- Blind SQL Injection
- Code Injection (exec)
- Open Redirect
- Information Exposure in Logs
- Uncontrolled Resource Consumption
- Hard-coded IP Addresses

#### 3. `requirements.txt`
**Category**: SCA  
**Vulnerable Dependencies**:
- Django 2.2.0 (Multiple CVEs)
- Flask 0.12.2 (Security vulnerabilities)
- requests 2.6.0 (Security issues)
- PyYAML 5.1 (CVE-2020-1747 - Arbitrary code execution)
- Jinja2 2.10 (XSS vulnerabilities)
- Pillow 6.0.0 (Image processing vulnerabilities)
- cryptography 2.3 (Security issues)
- SQLAlchemy 1.2.0 (SQL injection risks)
- Werkzeug 0.14.0 (Security vulnerabilities)
- urllib3 1.24 (Multiple CVEs)
- And more...

### JavaScript/Node.js Files

#### 4. `javascript_sast_vulnerabilities.js`
**Category**: SAST  
**Vulnerabilities**:
- SQL Injection
- Command Injection
- Path Traversal
- XSS (Cross-Site Scripting)
- Insecure Direct Object Reference
- Weak Cryptography (MD5)
- Insecure Random Number Generation
- Code Injection (eval)
- Regular Expression DoS (ReDoS)
- Insecure Cookie Settings
- Missing CORS Configuration
- Unvalidated Redirects
- Information Disclosure
- Hardcoded Credentials

#### 5. `package.json`
**Category**: SCA  
**Vulnerable Dependencies**:
- express 4.16.0 (Known vulnerabilities)
- lodash 4.17.4 (Prototype pollution)
- mysql 2.15.0 (Security issues)
- mongoose 5.0.0 (Vulnerabilities)
- moment 2.19.0 (ReDoS)
- jquery 3.3.1 (XSS vulnerabilities)
- axios 0.18.0 (Security issues)
- ws 3.3.1 (DoS vulnerabilities)
- handlebars 4.0.11 (Prototype pollution)
- marked 0.3.9 (XSS)
- jsonwebtoken 8.1.0 (Security issues)
- And more...

### Infrastructure as Code (IaC) Files

#### 6. `Dockerfile`
**Category**: IaC  
**Vulnerabilities**:
- Using latest tag (non-deterministic)
- Running as root
- Hardcoded secrets in ENV
- Installing unnecessary packages
- Not using specific versions
- No cleanup after apt-get
- World-writable permissions
- Exposing unnecessary ports
- Using --allow-unauthenticated
- No HEALTHCHECK
- Downloading and executing remote scripts
- No multi-stage build
- No resource limits

#### 7. `docker-compose.yml`
**Category**: IaC  
**Vulnerabilities**:
- Weak database credentials
- Exposed database ports
- Privileged containers
- Disabled security features
- Redis without authentication
- MongoDB weak credentials
- Hardcoded secrets in environment
- Mounting sensitive host directories
- Running as root
- Network mode host
- Disabling container isolation
- No resource limits
- SSL disabled on databases
- Security features disabled

#### 8. `kubernetes-deployment.yaml`
**Category**: IaC  
**Vulnerabilities**:
- Secrets in base64 (easily decoded)
- Sensitive data in ConfigMap
- Running as root
- Privileged containers
- No resource limits
- Secrets in plain text environment variables
- Mounting sensitive volumes (/, /var/run/docker.sock)
- Host network access
- Host PID and IPC namespace
- Automounting service account tokens
- ClusterRoleBinding with cluster-admin
- No TLS/HTTPS enforcement
- Permissive CORS
- ReadWriteMany access mode

#### 9. `terraform-main.tf`
**Category**: IaC  
**Vulnerabilities**:
- No backend encryption
- Hardcoded AWS credentials
- S3 bucket with public access
- No S3 encryption
- No S3 versioning
- Security groups with 0.0.0.0/0
- SSH and RDP open to world
- EC2 without EBS encryption
- Public IP addresses
- RDS publicly accessible
- No RDS encryption
- Weak database credentials
- No backup retention
- Overly permissive IAM policies
- ELB without HTTPS
- No access logs
- Lambda with environment secrets
- CloudFront without WAF
- No CloudWatch logs
- Sensitive outputs not marked
- No VPC flow logs

## Testing Your Security Scanners

### SCA Testing
1. Run your SCA tool against `requirements.txt` (Python)
2. Run your SCA tool against `package.json` (Node.js)
3. Verify detection of vulnerable dependencies and CVEs

### SAST Testing
1. Run your SAST tool against Python files:
   - `python_sast_vulnerabilities.py`
   - `python_additional_vulnerabilities.py`
2. Run your SAST tool against JavaScript files:
   - `javascript_sast_vulnerabilities.js`
3. Verify detection of code-level security issues

### IaC Testing
1. Run your IaC scanner against:
   - `Dockerfile`
   - `docker-compose.yml`
   - `kubernetes-deployment.yaml`
   - `terraform-main.tf`
2. Verify detection of infrastructure misconfigurations

## Automated security scans (GitHub Actions)

This repository includes a GitHub Actions workflow that runs an automated vulnerability scan using Trivy and commits the results back to the repository for inspection.

- Workflow file: `.github/workflows/scans.yaml`
- Trigger: runs on `push` to the `main` branch and supports manual runs via `workflow_dispatch`.
- Runner: `ubuntu-latest` (GitHub-hosted runner)
- Scanner: `aquasecurity/trivy-action` (Trivy)

Key details of the scan configuration:
- scan-type: `fs` — filesystem scanning (detects vulnerabilities in files and installed packages found in the repo)
- format: `json` — the results are written in JSON format
- output: `scan-results.json` — the report file is saved at the repository root
- ignore-unfixed: `true` — Trivy will ignore vulnerabilities that don't yet have fixes available
- severity: `CRITICAL,HIGH` — the scan is configured to focus on high-severity issues

After the scan completes the workflow will attempt to commit `scan-results.json` back to the repository (the job sets `contents: write` permission and only commits when there are changes). This gives you a history of scan results in commits for easy review.

How to use and inspect results:
- Trigger the scan automatically by pushing to `main`, or run it manually from the Actions tab.
- After the run, check the `scan-results.json` file in the repository root to view the JSON output of Trivy.
- You can open the JSON in any viewer or convert to human-friendly formats for reporting.

Notes & recommendations:
- The workflow focuses on the most severe issues by default; if you want to catch more findings change the `severity` option in `.github/workflows/scans.yaml`.
- `ignore-unfixed: true` keeps noisy, unfixable findings out of the report — set it to `false` if you want everything reported.
- Consider adding additional Trivy scan types (like `image` or `remote`) or other scanners to broaden coverage.

## Expected Detections

Your security scanners should detect:

### High Severity
- SQL Injection
- Command Injection
- Hardcoded credentials
- Insecure deserialization
- XXE vulnerabilities
- SSRF vulnerabilities
- Privileged containers
- Public cloud resources
- Weak database credentials

### Medium Severity
- Weak cryptography
- Insecure random numbers
- Path traversal
- XSS vulnerabilities
- Missing authentication
- Exposed debugging ports
- No encryption at rest
- Missing security headers

### Low Severity
- Information disclosure
- Debug mode enabled
- Missing resource limits
- No logging configuration
- Latest tags in containers
- No health checks

## Important Notes

⚠️ **WARNING**: These files contain real security vulnerabilities and should:
- NEVER be deployed to production
- NEVER be committed to production repositories
- Only be used in isolated testing environments
- Be deleted after testing is complete

## Security Scanner Comparison

Use these files to compare the effectiveness of different security scanning tools:
- Detection rate (how many vulnerabilities are found)
- False positive rate
- Severity accuracy
- Remediation guidance quality
- Reporting capabilities

## License

These files are provided for security testing purposes only. Use at your own risk in isolated testing environments.
