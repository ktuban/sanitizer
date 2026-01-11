# Security Policy

## Supported Versions

We release security updates for actively maintained versions of `@ktuban/sanitizer`.

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| <1.0    | ❌        |

Only the latest major version receives security patches.  
Older, unsupported versions will not receive fixes.

---

## Reporting a Vulnerability

If you discover a security vulnerability in `@ktuban/sanitizer`:

- **Do not open a public issue.**
- **Do not disclose publicly until a fix is released.**

Instead, please report it responsibly:

1. Submit a private report via [GitHub Security Advisories](https://github.com/k/sanitizer/security/advisories).
2. Or email: **security@yourdomain.com** (replace with your preferred contact).

We will acknowledge receipt within **48 hours** and provide a timeline for investigation and remediation.

---

## Disclosure Policy

- We aim to fix confirmed vulnerabilities within **30 days**.
- Critical issues may be patched sooner.
- Once a fix is released, we will publish a new version and update the [CHANGELOG](CHANGELOG.md).
- Public disclosure will occur only after a patch is available.

---

## Security Philosophy

`@ktuban/sanitizer` is built with a **defense‑in‑depth** model:

- Strict input validation and sanitization
- Prototype pollution detection
- SSRF, NoSQL injection, and path traversal protection
- Rate limiting and suspicious pattern detection
- Audit logging of security events
- Diagnostics suite to verify security perimeter

We benchmark against **OWASP ASVS**, **PCI‑DSS**, and **NIST 800‑53** guidelines where applicable.

---

## Best Practices for Users

To maximize security when using `@ktuban/sanitizer`:

- Always run the latest version.
- Configure environment presets (`production`, `staging`, `development`, `test`) appropriately.
- Enable audit logging in production.
- Use strict security levels (`high` or `paranoid`) for sensitive systems.
- Run the diagnostics suite regularly in CI/CD pipelines.

---

## Responsible Disclosure

We appreciate responsible disclosure from the community.  
If you report a vulnerability, we will:

- Credit you in the release notes (unless you prefer anonymity).
- Work with you to validate and remediate the issue.
- Keep communication open and transparent.

---

## Contact

- Security advisories: [GitHub Security Advisories](https://github.com/ktuban/sanitizer/security/advisories)  
- Email: dev.tuban@hotmail.com
