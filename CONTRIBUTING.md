# Contributing to @k/sanitizer

Thanks for your interest in contributing!  
This project aims to provide a high‑security, extensible sanitization framework with strong guarantees, predictable behavior, and excellent developer experience. Contributions that improve security, correctness, performance, documentation, or developer tooling are always welcome.

---

## 🧭 Project Structure

src/
config/               Global configuration engine
core/                 Core sanitization pipeline
security/             Security decorator (rate limiting, audit logging, metrics)
validators/           Built‑in validators + registry
diagnostics/          Diagnostics suite
types/                Shared types and interfaces
factory/              Sanitizer factories
dist/                   Build output (ESM, CJS, types)

---

## 🧪 Requirements Before Submitting

Please ensure:

## 1. **All tests pass**
   ```bash
   npm test

## 2. Diagnostics suite passes
import { sanitizationDiagnostics } from "@k/sanitizer";
await sanitizationDiagnostics.run({ deep: true });

## 3. Linting passes 
npm run lint
## 4. Build succeeds
npm run build
## 5. No regressions in:

XSS, SSRF, NoSQLi, path traversal, prototype pollution detection
Rate limiting behavior
Audit logging
Metrics
Performance thresholds

🧩 Types of Contributions
🐛 Bug Fixes
Please include:

A clear description of the issue

A minimal reproduction if possible

Tests that fail before your fix and pass after

🔐 Security Improvements
Security is the core of this project.
If you discover a vulnerability, do not open a public issue.
Instead, email:

security@yourdomain.com  
(or open a private GitHub security advisory)

🧪 New Validators
Validators must:

Implement ValidationStrategy

Include tests

Include malicious payloads for diagnostics

Be registered in ValidationStrategyRegistry

⚙️ Configuration Improvements
Changes to ConfigValidator must:

Preserve backward compatibility

Include documentation updates

Include diagnostics coverage

📚 Documentation
Improvements to README, examples, or inline docs are always welcome.

🔀 Pull Request Process
Fork the repository

Create a feature branch

Make your changes

Add/update tests

Run diagnostics

Submit a PR with:

Summary of changes

Motivation

Any breaking changes

Before/after behavior

A maintainer will review your PR and may request changes.

🧱 Coding Standards
TypeScript strict mode

No implicit any

Prefer explicit types

Avoid side effects in modules

Keep core and security layers separate

Preserve deterministic behavior in the core pipeline

Document all new public APIs

🧪 Testing Standards
Tests should cover:

Valid inputs

Invalid inputs

Edge cases

Malicious payloads

Diagnostics behavior

Performance (when relevant)

Use vitest for all tests.

🛡 Security Philosophy
This project follows a defense‑in‑depth model:

Validate early
Sanitize aggressively
Log suspicious behavior
Fail safely
Never trust input
Prefer explicit over implicit behavior
Contributions should align with this philosophy.

❤️ Thank You
Your contributions help make this library safer, more reliable, and more useful for everyone.
We appreciate your time and expertise.
