# Security Policy

BugFinder is a security assessment platform. We take security vulnerabilities in BugFinder itself seriously. This document outlines how to report issues and what to expect.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Please report vulnerabilities via one of the following methods:

- **Email**: [security@bugfinder.dev](mailto:security@bugfinder.dev)
- **GitHub Private Vulnerability Disclosure**: Use the "Report a vulnerability" button on the repository's Security tab

### What to include

- Type of vulnerability
- Steps to reproduce (PoC preferred)
- Affected versions and configurations
- Potential impact
- Any suggested remediation (if known)

You should receive a response within 48 hours. We will acknowledge receipt and provide an estimated timeline for a fix.

### Disclosure policy

- We will acknowledge receipt within 48 hours
- We will validate and triage within 5 business days
- We aim to release a fix within 14 days for critical issues
- We will notify you when the fix is deployed
- Public disclosure is coordinated — please allow 30 days after fix release

## Security Best Practices for Users

Since BugFinder performs active security testing, please follow these guidelines:

1. **Scope enforcement**: Always configure `BF_ALLOWED_DOMAINS` and use scope files for production scans
2. **Rate limiting**: Respect rate limits — do not disable `BF_RATE_LIMIT_PER_SECOND` unless testing in a lab
3. **API keys**: Store NVIDIA API keys in environment variables or `.env` files — never commit them
4. **Docker**: Run in isolated containers; use read-only filesystems where possible
5. **Database**: Use Postgres with TLS for multi-user deployments
6. **Scan targets**: Only scan targets you own or have explicit written permission to test
7. **Educational mode**: Enable `BF_EDUCATIONAL_MODE=true` to review every action before execution

## Responsible Use

BugFinder is designed for authorized security assessments only. Users are responsible for complying with all applicable laws. The project maintainers disclaim any liability for misuse.

## Threat Model

BugFinder processes the following sensitive data:
- Target URLs, IP ranges, and application metadata
- Discovered credentials and secrets (stored encrypted at rest)
- API keys for AI providers (NVIDIA)
- Scan results and vulnerability data

Data-at-rest encryption is used for stored secrets. Network traffic to AI providers is TLS-encrypted. Scope files prevent accidental out-of-scope scanning.

## Hall of Fame

We maintain a list of researchers who responsibly disclose vulnerabilities. Contact us if you would like to be credited (anonymously or named).

## Contact

- **Security team**: security@bugfinder.dev
- **PGP key**: Available on the repository's Security tab
