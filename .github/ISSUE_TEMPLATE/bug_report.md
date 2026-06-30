---
name: Bug report
about: Report a bug or security concern in BugFinder
title: ""
labels: bug, needs-triage
assignees: ""
---

## Bug Description

A clear and concise description of the bug.

## Security Impact

Does this bug have security implications? For example: crash, data leak, scope bypass, permission escalation, false negative/positive.

- [ ] Yes — mark this issue as confidential if the details are sensitive
- [ ] No

## Steps to Reproduce

1. Run command: `bf scan ...`
2. ...
3. See error

## Expected Behaviour

What should have happened?

## Actual Behaviour

What actually happened? Include error output, stack traces, or unexpected behaviour.

## Environment

- BugFinder version: [e.g. 0.1.0 or commit hash]
- Python version: [e.g. 3.12.0]
- OS: [e.g. Linux, macOS]
- Docker: [yes/no]
- AI provider enabled: [NVIDIA / none]

## Target Information (if applicable)

- Target type: [website / API / APK / IP / cloud / other]
- Did you configure scope enforcement? [yes/no]

## Configuration

```yaml
# Paste relevant config (redact API keys and secrets)
BF_ALLOWED_DOMAINS=
BF_MAX_CONCURRENT_TASKS=
BF_RATE_LIMIT_PER_SECOND=
BF_BEGINNER_MODE=
```

## Logs

```text
# Paste relevant log output here
```

## Additional Context

Add any other context, screenshots, or related issues.

## Possible Fix

If you have a suggestion for the fix, include it here.
