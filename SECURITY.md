# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ |
| 0.1.x   | ❌ |

## Reporting a Vulnerability

BugFinder is a security assessment tool designed to find vulnerabilities in other applications. However, if you discover a security issue in BugFinder itself:

1. **Do not** open a public GitHub issue
2. Email details to: security@bugfinder.dev (or open a [security advisory](https://github.com/highoncomputers/BugFinder/security/advisories/new))
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work on a fix.

## Scope

BugFinder is released as a security tool. By design it:
- Performs HTTP requests to targets
- Scans for vulnerabilities
- Requires API keys for AI features

Known and documented security considerations:
- API keys are stored in environment variables or `.env` files
- Reports may contain sensitive findings about scanned targets
- Always run BugFinder against targets you own or have permission to test

## Best Practices

1. Never commit `.env` files to version control
2. Use `BF_SCOPE_ENFORCEMENT=true` and set `BF_ALLOWED_DOMAINS`
3. Review reports before sharing them
4. Keep BugFinder updated to the latest version
