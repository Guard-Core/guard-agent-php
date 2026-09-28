# Security Policy for Guard Agent PHP

## Supported Versions

We currently provide security updates for the following versions of Guard Agent PHP:

| Version | Supported          |
| ------- | ------------------ |
| 3.1.x | :white_check_mark: |
| 3.0.x | :white_check_mark: |
| < 3.0.0 | :x:              |

## Reporting a Vulnerability

We take the security of Guard Agent PHP seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly** until it has been addressed by the maintainers.
2. **Report the vulnerability through GitHub's security advisory feature**:
   - Go to the [Security tab](https://github.com/rennf93/guard-agent-php/security/advisories) of the Guard Agent PHP repository
   - Click on "New draft security advisory"
   - Fill in the details of the vulnerability
   - Submit the advisory

   Alternatively, you can report vulnerabilities through [GitHub's private vulnerability reporting feature](https://github.com/rennf93/guard-agent-php/security/advisories/new).

3. Include the following information in your report:
   - A description of the vulnerability and its potential impact
   - Steps to reproduce the issue
   - Affected versions
   - Any potential mitigations or workarounds

The maintainers will acknowledge your report within 48 hours and provide a detailed response within 7 days, including the next steps in handling the vulnerability.

## Security Considerations

Guard Agent PHP is a security library: report anything that weakens detection, bypasses rate limiting, leaks secrets into logs, or trusts unvalidated input.
