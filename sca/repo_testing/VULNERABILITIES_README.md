# Test Vulnerabilities and Security Issues

This directory contains test files with intentional security vulnerabilities for testing the Software Composition Analysis toolkit.

## Files

### flow.py
Contains 11 critical/high severity Python vulnerabilities:

1. **eval()** - Line 8: Arbitrary code execution via eval()
2. **pickle.loads()** - Line 12: Deserialization vulnerability
3. **subprocess with shell=True** - Line 16: Command injection vulnerability
4. **os.system()** - Line 20: System command injection
5. **exec()** - Line 24: Code execution vulnerability
6. **SQL Injection** - Line 28: String concatenation in SQL queries
7. **SSTI (Server-Side Template Injection)** - Line 33: Template injection via render_template_string()
8. **Weak Random** - Line 38: Insecure random token generation
9. **Missing Timeout** - Line 43: requests.get() without timeout
10. **Hardcoded Credentials** - Line 46: Database password in source code
11. **Hardcoded API Key** - Line 47: API key in source code
12. **Debug Mode Enabled** - Line 51: Flask running with debug=True

### utils.js
Contains 11 critical/high severity JavaScript vulnerabilities:

1. **dangerouslySetInnerHTML** - Line 10: XSS vulnerability via React
2. **SQL Injection** - Line 18: Template literal in SQL query
3. **eval()** - Line 26: Code execution vulnerability
4. **innerHTML** - Line 31: DOM XSS vulnerability
5. **Function Constructor** - Line 36: Dynamic code execution
6. **Math.random()** - Line 41: Weak random for security tokens
7. **Hardcoded API Key** - Line 45: Secret exposed in source
8. **XSS via Attribute** - Line 56: User input in HTML attributes
9. **Unsafe JSON.parse()** - Line 63: Parsing without validation

### vulnerabilities.json
Comprehensive JSON file documenting:
- 4 CVE-based package vulnerabilities (lodash, numpy, pandas, scipy)
- 18 code-level security issues
- Issue locations, descriptions, and remediation steps
- Severity levels and CVSS scores

## Rule Files Added

New ast-grep rule files in `sca/db/rules/`:

### Python Rules
- `python-eval.yml` - Detects eval() usage
- `python-pickle.yml` - Detects pickle.loads() usage
- `python-subprocess-shell.yml` - Detects subprocess with shell=True
- `python-os-system.yml` - Detects os.system() usage
- `python-exec.yml` - Detects exec() usage
- `python-hardcoded-password.yml` - Detects hardcoded credentials

### JavaScript Rules
- `js-dangerouslySetInnerHTML.yml` - Detects React dangerouslySetInnerHTML
- `js-innerHTML.yml` - Detects innerHTML usage
- `js-eval.yml` - Detects eval() usage
- `js-function-constructor.yml` - Detects Function constructor usage
- `js-hardcoded-secrets.yml` - Detects hardcoded API keys/secrets

## Package Vulnerabilities

### Affected Packages
1. **lodash** 4.17.21 - CVE-2021-23337 (Prototype Pollution)
2. **numpy** 1.21.0 - CVE-2021-3129 (Buffer Overflow)
3. **pandas** 1.3.0 - CVE-2021-25919 (Code Injection via eval)
4. **scipy** 1.7.0 - CVE-2020-26217 (Insecure Randomness)

## Testing the Scanner

Run the analysis with:
```bash
python main.py repo_testing --verbose
```

Expected output should include:
- **4 Packages** (lodash, numpy, scipy, pandas)
- **4 Vulnerabilities** (from CVE database)
- **Multiple Rule Findings** (from ast-grep rules)
- **Outdated Packages** with latest versions
- **License Findings** (MIT AND proprietary-license from LICENSE file)

## Severity Reference

- **Critical**: Allows arbitrary code execution, full system compromise
- **High**: XSS, SSTI, unsafe cryptography, authentication bypass
- **Medium**: Information disclosure, weak encryption, missing validation
- **Low**: Best practice violations, code quality issues
