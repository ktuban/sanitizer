
---

# ⭐ **CHANGELOG.md (Minimal Initial Version)**

```md
# Changelog

All notable changes to this project will be documented in this file.

This project follows **semantic versioning**:  
`MAJOR.MINOR.PATCH`

---

## 1.0.0 — Initial Release

### ✨ Features
- Core sanitization pipeline (`CoreStringSanitizer`)
- Security decorator (`SecurityStringSanitizer`)
- Unified configuration engine (`ConfigValidator`)
- Full validator suite (HTML, URL, JSON, MongoDB filter, SQL identifier, etc.)
- Prototype pollution protection
- SSRF, NoSQL injection, path traversal detection
- Rate limiting (per IP / context)
- Audit logging (security + sanitization events)
- Metrics and observability hooks
- Diagnostics suite (security, observability, performance)
- Factory functions (`createConfiguredSanitizer`, `defaultSanitizer`)
- ESM + CJS builds with full TypeScript types

### 📚 Documentation
- Comprehensive README
- Architecture overview
- Configuration examples
- Diagnostics usage
- Extensibility guide

### 🛠 Tooling
- Vitest test suite
- ESLint configuration
- GitHub Actions workflow for automated publishing
- Dual build pipeline (ESM + CJS + types)

---

Future versions will be added here.
