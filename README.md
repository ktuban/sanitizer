# @k/sanitizer

A high‑security, extensible sanitization framework for Node.js and TypeScript.

Designed for production systems that demand **strong guarantees**, **predictable behavior**, and **defense‑in‑depth** against modern input‑based attacks.

Built with:

- A unified configuration engine  
- A high‑performance core sanitizer  
- A security‑aware decorator layer  
- A full suite of validators  
- Path‑aware error reporting  
- Diagnostics and observability tools  

---

## ✨ Features

- **Core + Security Layers**  
  Fast core sanitization with optional security perimeter (rate limiting, suspicious pattern detection, audit logging).

- **Unified Configuration Engine**  
  Environment‑aware, override‑friendly, and fully validated.

- **Extensible Validator Architecture**  
  Add custom validators or override built‑ins.

- **Security‑Focused Defaults**  
  Safe‑by‑default behavior for HTML, URLs, JSON, filenames, and more.

- **Prototype Pollution Protection**  
  JSON validator detects and strips `__proto__`, `constructor`, and `prototype` keys.

- **Diagnostics Suite**  
  Run automated checks for SSRF, NoSQL injection, path traversal, prototype pollution, and performance.

- **TypeScript First**  
  Full type definitions, strict mode, and clean ESM/CJS builds.

---

## 📦 Installation

Local development:

```bash
npm install @k/sanitizer
```

Or link locally:

```bash
npm link
npm link @k/sanitizer
```

---

## 🚀 Quick Start

### Basic sanitization

```ts
import { SecurityStringSanitizer, ConfigValidator } from "@k/sanitizer";

// Initialize global config (optional)
ConfigValidator.initialize();

const sanitizer = new SecurityStringSanitizer(/* core, config, plugins */);

const result = await sanitizer.sanitize("hello<script>", {
  sanitizeAs: "html",
  mode: "sanitize-for-storage"
});

console.log(result.sanitized);
```

---

## 🧱 Architecture Overview

### **CoreStringSanitizer**
High‑performance, pure sanitization pipeline responsible for deterministic, side‑effect‑free transformations.

**Pipeline responsibilities:**
- String conversion  
- Bounds enforcement  
- Strategy validation  
- Security‑level transformations  
- Custom validators  
- Truncation  

---

### **SecurityStringSanitizer**
A security‑aware decorator that wraps the core pipeline and adds defense‑in‑depth protections.

**Security responsibilities:**
- Rate limiting  
- Suspicious pattern detection  
- Audit logging  
- Metrics  
- Health checks  

---

### **ConfigValidator**
The single source of truth for all configuration.

**Manages:**
- Global defaults  
- Environment presets (production, staging, development, test)  
- `SANITIZER_*` environment variable overrides  
- Type defaults  
- Security constants  
- HTML defaults  
- Rate limiting configuration  
- Audit logging configuration  

---

### **ValidationStrategyRegistry**
Maps `sanitizeAs` → validator strategy.

This registry enables:
- Pluggable validators  
- Custom strategies  
- Overriding built‑in validators  
- Clean separation of concerns  

---

### **Validators**
A comprehensive suite of built‑in validators, each implementing strict, type‑specific validation and sanitization rules.

**Includes:**
- Email, password, username  
- HTML, HTML attribute  
- URL, filename, path  
- JSON (with prototype‑pollution protection)  
- MongoDB filter  
- SQL identifier  
- Base64, hex, UUID  
- Currency, percentage  
- ISO date/time  
- And more…  

---

## 🛡 Security

This library is built with a **defense‑in‑depth** philosophy:

- Prototype pollution detection  
- SSRF pattern detection  
- NoSQL injection detection  
- Path traversal protection  
- Strict input bounds  
- Security levels (low → paranoid)  
- Audit logging  
- Rate limiting  
- Environment‑aware defaults  

---

## 🧪 Diagnostics

Run the built‑in diagnostics suite:

```ts
import { sanitizationDiagnostics } from "@k/sanitizer";

const report = await sanitizationDiagnostics.run({ deep: true });
console.table(report);
```

Diagnostics include:
- Prototype pollution detection  
- SSRF blocking  
- NoSQL injection detection  
- Path traversal detection  
- Performance benchmarks  
- Metrics validation  
- Audit logging verification  

---

## ⚙ Configuration

### Environment presets
- **production**
- **staging**
- **development**
- **test**

### Environment variable overrides

| Variable | Description |
|---------|-------------|
| `SANITIZER_SECURITY_LEVEL` | Override all security levels |
| `SANITIZER_RATE_LIMIT` | Requests per minute |
| `SANITIZER_MAX_JSON_BYTES` | JSON size limit |
| `SANITIZER_MAX_HTML_BYTES` | HTML size limit |
| `SANITIZER_MAX_STRING_LENGTH` | Max string length |
| `SANITIZER_AUDIT_ENABLED` | Enable/disable audit logging |

---

## 🧩 Extending

### Add a custom validator

```ts
registry.register(new MyCustomValidator());
```

### Override defaults

```ts
ConfigValidator.updateConfig({
  securityConstants: {
    MAX_JSON_BYTES: 2 * 1024 * 1024
  }
});
```

---

## 📄 License

MIT © K

---

## 🤝 Contributing

Pull requests are welcome.  
Please run diagnostics and tests before submitting.

---

## 🧭 Roadmap

- Plugin marketplace  
- Schema‑driven sanitization  
- Async validator support  
- WASM acceleration  

---

If you want, I can also generate:

- A **CONTRIBUTING.md**  
- A **CHANGELOG.md**  
- A **docs/ site structure**  
- A **GitHub Actions CI pipeline**  

Just tell me what direction you want to take this package next.
