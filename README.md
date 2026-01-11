# @ktuban/sanitizer

[![npm version](https://img.shields.io/npm/v/@ktuban/sanitizer.svg)](https://www.npmjs.com/package/@ktuban/sanitizer)
[![npm downloads](https://img.shields.io/npm/dm/@ktuban/sanitizer.svg)](https://www.npmjs.com/package/@ktuban/sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Support via PayPal](https://img.shields.io/badge/Support-PayPal-blue.svg)](https://paypal.me/KhalilTuban)
[![Ko‑fi](https://img.shields.io/badge/Support-Ko--fi-red.svg)](https://ko-fi.com/ktuban)


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

- [PayPal.me/YOURNAME](https://paypal.me/KhalilTuban)  
- [Ko‑fi.com/YOURNAME](https://ko-fi.com/ktuban)

Your support helps keep the project maintained, secure, and evolving.

---

## 📦 Installation

```bash
npm install @ktuban/sanitizer

Absolutely — your new `factory.ts` changes the ergonomics of the library in a really nice way, and your README should reflect that. Below is a **clean, professional, developer‑friendly Usage section** you can drop directly into your README.

I’ve written it so that:

- It mirrors your new factory API exactly  
- It explains the three layers (core → security → diagnostics)  
- It includes async and sync examples  
- It’s copy‑paste friendly  
- It feels like a modern OSS library (Zod‑style clarity, OWASP‑grade seriousness)

You can paste this under **“Usage”** in your README.

---
# 📦 Usage

`@ktuban/sanitizer` provides three levels of sanitization:

1. **CoreStringSanitizer** — fast, pure sanitization engine (no security layers)  
2. **SecurityStringSanitizer** — full security perimeter (audit logging, abuse prevention, rate limiting)  
3. **SanitizerDiagnostics** — full-suite diagnostics to validate your security perimeter  

You can construct each layer individually or build the entire system at once.

---

## 1. Core‑Only Sanitizer (Fast, No Security Layers)

Use this when you only need **pure sanitization** without audit logging, rate limiting, or abuse‑prevention plugins.

```ts
import { createCoreOnlySanitizer } from "@ktuban/sanitizer";

const core = createCoreOnlySanitizer({
  environment: "production",
});

const clean = core.sanitize("  Hello <script>evil()</script>  ");
console.log(clean);
```

### Async version

```ts
import { asyncCoreOnlySanitizer } from "@ktuban/sanitizer";

const core = await asyncCoreOnlySanitizer();
```

---

## 2. Full Security Sanitizer (Core + Plugins)

This builds the **security perimeter**, including:

- Audit logging  
- Abuse prevention  
- Rate limiting  
- Suspicious pattern detection  

```ts
import { createConfiguredSecuritySanitizer } from "@ktuban/sanitizer";

const security = createConfiguredSecuritySanitizer({
  environment: "production",
  auditLogging: {
    enabled: true,
    logLevels: ["info"],
    destination: "file",
    filePath: "./logs/security.log",
  },
  rateLimiting: {
    requestsPerMinute: 60,
    blockDurationMs: 10_000,
    suspiciousPatterns: [/select\s+.*from/i],
  },
});

const safe = security.sanitize("DROP TABLE users;");
console.log(safe);
```

### Async version

```ts
import { asyncConfiguredSecuritySanitizer } from "@ktuban/sanitizer";

const security = await asyncConfiguredSecuritySanitizer();
```

---

## 3. Diagnostics (Full Security Perimeter Testing)

Diagnostics validate that your security perimeter is functioning correctly.

```ts
import { createConfiguredSecuritySanitizer, createSanitizerDiagnostics } from "@ktuban/sanitizer";

const security = createConfiguredSecuritySanitizer();
const diagnostics = createSanitizerDiagnostics(security);

const report = diagnostics.runAll();
console.log(report);
```

### Async version

```ts
import { asyncConfiguredSecuritySanitizer, asyncCreateSanitizerDiagnostics } from "@ktuban/sanitizer";

const security = await asyncConfiguredSecuritySanitizer();
const diagnostics = await asyncCreateSanitizerDiagnostics(security);
```

---

## 4. Build the Entire Sanitizer System (Recommended)

This gives you everything:

- `core` — pure sanitization engine  
- `security` — full security perimeter  
- `diagnostics` — full-suite diagnostics  

```ts
import { createSanitizerSystem } from "@ktuban/sanitizer";

const { core, security, diagnostics } = createSanitizerSystem({
  environment: "production",
});

core.sanitize("hello");
security.sanitize("hello");
diagnostics.runAll();
```

### Async version

```ts
import { asyncCreateSanitizerSystem } from "@ktuban/sanitizer";

const { core, security, diagnostics } = await asyncCreateSanitizerSystem();
```

---

## 5. Configuration

All factory functions accept a `Partial<ISanitizerGlobalConfig>`, letting you override only what you need:

```ts
createSanitizerSystem({
  environment: "production",
  auditLogging: {
    enabled: true,
    destination: "remote",
    remoteEndpoint: "https://logs.example.com/ingest",
  },
});



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
import { ValidationStrategyRegistry } from "@ktuban/sanitizer";
import type { ValidationStrategy } from "@ktuban/sanitizer";

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
import { ConfigValidator } from "@ktuban/sanitizer";

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