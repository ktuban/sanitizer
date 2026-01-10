# @k/sanitizer

[![npm version](https://img.shields.io/npm/v/@k/sanitizer.svg)](https://www.npmjs.com/package/@k/sanitizer)
[![npm downloads](https://img.shields.io/npm/dm/@k/sanitizer.svg)](https://www.npmjs.com/package/@k/sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Support via PayPal](https://img.shields.io/badge/Support-PayPal-blue.svg)](https://paypal.me/YOURNAME)
[![Ko‑fi](https://img.shields.io/badge/Support-Ko--fi-red.svg)](https://ko-fi.com/YOURNAME)



A high-security, extensible sanitization framework for Node.js and TypeScript.

Designed for production systems that demand **strong guarantees**, **predictable behavior**, and **defense-in-depth** against modern input-based attacks.

Built with:

- A unified configuration engine  
- A high-performance core sanitizer  
- A security-aware decorator layer  
- A full suite of validators  
- Path-aware error reporting  
- Diagnostics and observability tools  

---

## ✨ Features

- **Core + Security Layers**  
  Fast core sanitization with an optional security perimeter (rate limiting, suspicious pattern detection, audit logging, metrics).

- **Unified Configuration Engine**  
  Environment-aware, override-friendly, and fully validated.

- **Extensible Validator Architecture**  
  Add custom validators or override built-ins.

- **Security-Focused Defaults**  
  Safe-by-default behavior for HTML, URLs, JSON, filenames, and more.

- **Prototype Pollution Protection**  
  JSON validator detects and strips `__proto__`, `constructor`, and `prototype` keys.

- **Diagnostics Suite**  
  Run automated checks for XSS, SSRF, NoSQL injection, path traversal, prototype pollution, observability, and performance.

- **TypeScript First**  
  Full type definitions, strict mode, and clean ESM/CJS builds.

---
## ☕ Support the Project

If this library helps you build safer systems, consider supporting ongoing development:

- [PayPal.me/YOURNAME](https://paypal.me/YOURNAME)  
- [Ko‑fi.com/YOURNAME](https://ko-fi.com/YOURNAME)

Your support helps keep the project maintained, secure, and evolving.

---

## 📦 Installation

```bash
npm install @k/sanitizer
🚀 Quick Start
Basic sanitization (recommended path)
import {
  defaultSanitizer,
  createConfiguredSanitizer,
  ConfigValidator
} from "@k/sanitizer";

// Optional: initialize or override global config
ConfigValidator.initialize({
  environment: "production",          // "development" | "staging" | "test"
  securityLevel: "high"               // "low" | "medium" | "high" | "paranoid"
});

// Easiest: use the default preconfigured security sanitizer
const sanitizer = defaultSanitizer;

// Or: build a configured instance (useful for tests / multi-tenant setups)
const customSanitizer = createConfiguredSanitizer({
  rateLimiting: {
    enabled: true,
    requestsPerMinute: 60
  }
});

const result = await sanitizer.sanitize("hello<script>", {
  sanitizeAs: "html",
  mode: "sanitize-for-storage"
});

console.log(result.sanitized);
📚 Exports
The main entry point @k/sanitizer exposes:

Export	Description
defaultSanitizer	Ready-to-use SecurityStringSanitizer configured from ConfigValidator and environment variables.
createConfiguredSanitizer	Factory that builds a full security sanitizer (core + security + plugins) from a partial config.
createCoreOnlySanitizer	Factory that builds a fast, core-only sanitizer without rate limiting or audit logging.
ConfigValidator	Global configuration engine. Handles environment presets, validation, and overrides.
sanitizationDiagnostics	Pre-wired diagnostics runner instance that exercises the full security perimeter.
SecurityStringSanitizer	Security-aware decorator class (advanced usage; prefer the factory/default exports).
CoreStringSanitizer	Core pipeline class (advanced usage).
ValidationStrategyRegistry	Registry that maps sanitizeAs → validator strategy.
🧱 Architecture Overview
CoreStringSanitizer
High-performance, pure sanitization pipeline responsible for deterministic, side-effect-free transformations.

Pipeline responsibilities:

String conversion

Bounds enforcement

Strategy selection and validation

Security-level transformations

Custom validator chaining

Truncation

SecurityStringSanitizer
A security-aware decorator that wraps the core pipeline and adds defense-in-depth protections.

Security responsibilities:

Rate limiting (per IP / context)

Suspicious pattern detection

Audit logging (security events + sanitization events)

Metrics and counters

Health checks / diagnostics hooks

ConfigValidator
Single source of truth for all configuration.

Manages:

Environment presets (production, staging, development, test)

SANITIZER_* environment variable overrides

Type defaults (per sanitizeAs)

Security levels and constants

HTML and JSON bounds

Rate limiting configuration

Audit logging configuration

ValidationStrategyRegistry & Validators
ValidationStrategyRegistry maps sanitizeAs → validator strategy.

Built-in validators include:

Email, password, username

Plain text, filename, search-query, phone, zip-code

HTML, HTML attribute

URL, path, safe path

JSON (with prototype-pollution protection)

MongoDB filter

SQL identifier

Base64, hex, UUID

Currency, percentage

ISO date, time, datetime

IP address, MongoDB ObjectId

You can register your own validators or override built-ins.

⚙ Configuration
You can configure the sanitizer via:

Environment presets (environment: "production" | "staging" | "development" | "test")

Environment variables (SANITIZER_*)

Direct calls to ConfigValidator.initialize() or ConfigValidator.updateConfig()

Example: Harden production behavior
ts
import { ConfigValidator, createConfiguredSanitizer } from "@k/sanitizer";

ConfigValidator.initialize({
  environment: "production",
  securityLevel: "paranoid",
  rateLimiting: {
    enabled: true,
    requestsPerMinute: 30,
    blockDurationMs: 5 * 60 * 1000,
    suspiciousPatterns: ["<script", "javascript:", "onerror=", "../"]
  },
  auditLogging: {
    enabled: true,
    destination: "json",     // "console" in dev, "json" in prod
    maxLogs: 10000
  }
});

const sanitizer = createConfiguredSanitizer();

const result = await sanitizer.sanitize("<script>alert(1)</script>", {
  sanitizeAs: "html"
});
Environment variable overrides
Variable	Description
SANITIZER_SECURITY_LEVEL	Override global security level
SANITIZER_RATE_LIMIT	Requests per minute
SANITIZER_MAX_JSON_BYTES	JSON size limit
SANITIZER_MAX_HTML_BYTES	HTML size limit
SANITIZER_MAX_STRING_LENGTH	Max string length
SANITIZER_AUDIT_ENABLED	Enable/disable audit logging
🧪 Diagnostics
The library ships with a diagnostics suite that exercises the full security perimeter, not just validators.

ts
import { sanitizationDiagnostics } from "@k/sanitizer";

const report = await sanitizationDiagnostics.run({ deep: true });
console.table(report);
Example output (truncated):

text
┌──────────────────────────────────────┬────────────────┬──────────┬────────┬───────────────────────────────────────────────┐
│ id                                   │ category       │ severity │ passed │ message                                       │
├──────────────────────────────────────┼────────────────┼──────────┼────────┼───────────────────────────────────────────────┤
│ security.xss-basic                   │ security       │ error    │ true   │ XSS payload was neutralized                   │
│ security.ssrn-internal               │ security       │ error    │ true   │ SSRF to metadata IP was blocked               │
│ security.nosql-mongodb-filter        │ security       │ error    │ true   │ NoSQL injection operator was rejected         │
│ observability.audit-logging          │ observability  │ info     │ true   │ Security audit logs increased as expected     │
│ observability.metrics-increment      │ observability  │ info     │ true   │ Metrics 'calls' counter increments correctly  │
│ security.rate-limiting               │ security       │ warning  │ false  │ Rate limiting did not trigger under test load │
│ performance.average-time             │ performance    │ warning  │ false  │ Average processing time above configured bar  │
└──────────────────────────────────────┴────────────────┴──────────┴────────┴───────────────────────────────────────────────┘
Diagnostics include checks for:

XSS, SSRF, NoSQL injection, path traversal, prototype pollution

Plugin wiring (abuse prevention, audit logger)

Rate limiting behavior

Metrics availability and correctness

Audit logging behavior

Performance regressions

Use this in CI to catch regressions before they ship.

🧩 Extending
Add a custom validator
ts
import { ValidationStrategyRegistry } from "@k/sanitizer";
import type { ValidationStrategy } from "@k/sanitizer";

class MyCustomValidator implements ValidationStrategy {
  readonly sanitizeAs = "my-custom-type";

  validate(input: string) {
    // throw on invalid
  }

  sanitize(input: string) {
    // return sanitized string
    return input.trim();
  }
}

const registry = new ValidationStrategyRegistry();
registry.initializeDefaultValidators();
registry.register(new MyCustomValidator());
Override defaults
ts
import { ConfigValidator } from "@k/sanitizer";

ConfigValidator.updateConfig({
  securityConstants: {
    MAX_JSON_BYTES: 2 * 1024 * 1024
  }
});

🛡 Security Notes
This library follows a defense-in-depth philosophy:
Prototype pollution detection in JSON
SSRF pattern detection for URLs
NoSQL injection detection for MongoDB filters
Path traversal protection for paths and filenames
Strict bounds and truncation for strings
Security levels (low → paranoid)
Rate limiting hooks (per IP / context)
Audit logging for security-relevant events
Diagnostics suite to validate behavior

It does not replace a full security review of your system, but it gives you a hardened, observable sanitization layer to build on.
📄 License
MIT © K

🤝 Contributing
Pull requests are welcome.

Run tests: npm test

Run lint: npm run lint

Run diagnostics: use sanitizationDiagnostics.run({ deep: true }) in a small harness or test
Please include tests and, when relevant, update documentation.

🧭 Roadmap
Plugin marketplace (custom validators & security plugins)
Schema-driven sanitization
Async validator support
WASM acceleration