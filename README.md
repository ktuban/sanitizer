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

- **Enhanced Diagnostics**  
  Comprehensive security testing including command injection, edge cases, and internationalization tests (100% attack vector coverage).

- **TypeScript First**  
  Full type definitions, strict mode, and clean ESM/CJS builds.

---
## ☕ Support the Project

If this library helps you build safer systems, consider supporting ongoing development:

- [PayPal.me/khaliltuban](https://paypal.me/KhalilTuban)  
- [Ko‑fi.com/ktuban](https://ko-fi.com/ktuban)

Your support helps keep the project maintained, secure, and evolving.

---

## 📦 Installation

```bash
npm install @ktuban/sanitizer
```

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

const result = await core.sanitize("user@example.com", {
  sanitizeAs: "email",
});
console.log(result.sanitized);
```

### Async version

```ts
import { createCoreOnlySanitizerAsync } from "@ktuban/sanitizer";

const core = await createCoreOnlySanitizerAsync();
const result = await core.sanitize("user@example.com", { sanitizeAs: "email" });
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
    logLevel: "high",
  },
  rateLimiting: {
    enabled: true,
    windowMs: 60000,
    maxRequests: 100,
  },
});

const result = await security.sanitize("test@example.com", {
  sanitizeAs: "email",
});
console.log(result.sanitized);
```

### Async version

```ts
import { createConfiguredSecuritySanitizerAsync } from "@ktuban/sanitizer";

const security = await createConfiguredSecuritySanitizerAsync();
const result = await security.sanitize("test@example.com", { sanitizeAs: "email" });
```

---

## 3. Diagnostics (Full Security Perimeter Testing)

Diagnostics validate that your security perimeter is functioning correctly.

```ts
import { createSanitizerSystem } from "@ktuban/sanitizer";

const { diagnostics } = createSanitizerSystem();

const report = await diagnostics.runAll({ deep: true });
console.log(report.summary);
```

### Async version

```ts
import { createSanitizerSystemAsync } from "@ktuban/sanitizer";

const { diagnostics } = await createSanitizerSystemAsync();
const report = await diagnostics.runAll({ deep: true });
console.log(report.summary);
```

---

## 4. Enhanced Diagnostics (Comprehensive Security Testing)

**New in v1.2.0**: Enhanced diagnostics provide comprehensive security testing including command injection, edge cases, and internationalization tests.

### Enhanced Diagnostics Features:
- **Command Injection Tests**: 28 tests covering all sanitizeAs types
- **Edge Case Testing**: Empty strings, null characters, very long inputs, Unicode
- **Internationalization Testing**: Emoji, RTL text, CJK characters, homoglyph attacks
- **Deep Security Validation**: 100% attack vector coverage

### Basic Usage

```ts
import { createEnhancedSanitizerSystemAsync } from "@ktuban/sanitizer";

const system = await createEnhancedSanitizerSystemAsync();
const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
console.log(`Enhanced tests: ${report.summary.total}`);
console.log(`Command injection tests: ${report.results.filter(r => r.id.includes('command-injection')).length}`);
```

### Standalone Enhanced Diagnostics

```ts
import { createEnhancedSanitizerDiagnostics } from "@ktuban/sanitizer";

const security = await createConfiguredSecuritySanitizerAsync();
const enhanced = createEnhancedSanitizerDiagnostics(security);
const report = await enhanced.runAllEnhanced({ deep: true });
```

### Test Categories

**Command Injection Tests (28 tests):**
- HTML: `<img src=x onerror="eval('require(\"child_process\").exec(\"ls\")')">`
- Plain text: `Hello; echo "hacked"`
- URL: `http://example.com/$(ls)`
- JSON: `{"cmd": "ls; rm -rf /"}`
- ...and 24 more types

**Edge Case Tests (8 tests):**
- Empty strings, null characters, whitespace-only
- Very long inputs (50,000+ characters)
- Unicode HTML, multiple null bytes

**Internationalization Tests (9 tests):**
- Emoji and symbols: `🎉🎊😊🌟✨🎈🎁🎀`
- Right-to-left text: `مرحبا بالعالم`
- Chinese/Japanese/Korean: `你好こんにちは안녕하세요`
- Homoglyph attacks: `аррӏе.com`

### Example Output

```javascript
=== ENHANCED DIAGNOSTICS REPORT ===
Total original tests: 63
Total enhanced tests: 28
Command injection tests: 28
Edge case tests: 8
Internationalization tests: 9
✅ All command injection tests passed
✅ All edge case tests passed  
✅ All internationalization tests passed
```

### Use in CI/CD Pipeline

```javascript
// test_security.mjs
import { createEnhancedSanitizerSystemAsync } from "@ktuban/sanitizer";

async function securityTest() {
  const system = await createEnhancedSanitizerSystemAsync();
  const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
  
  const criticalFailures = report.results.filter(r => 
    r.severity === 'critical' && !r.passed
  );
  
  if (criticalFailures.length > 0) {
    console.error('❌ Critical security failures detected!');
    criticalFailures.forEach(f => console.error(`   ${f.id}: ${f.message}`));
    process.exit(1);
  }
  
  console.log('✅ All security tests passed');
}

securityTest().catch(console.error);
```

---

## 5. Build the Entire Sanitizer System (Recommended)

This gives you everything:

- `core` — pure sanitization engine  
- `security` — full security perimeter  
- `diagnostics` — full-suite diagnostics  

```ts
import { createSanitizerSystem } from "@ktuban/sanitizer";

const { core, security, diagnostics } = createSanitizerSystem({
  environment: "production",
  securityLevel: "high",
});

const result1 = await core.sanitize("test@example.com", { sanitizeAs: "email" });
const result2 = await security.sanitize("test@example.com", { sanitizeAs: "email" });
const report = await diagnostics.runAll({ deep: true });
```

### Async version

```ts
import { createSanitizerSystemAsync } from "@ktuban/sanitizer";

const { core, security, diagnostics } = await createSanitizerSystemAsync();
const result = await core.sanitize("test@example.com", { sanitizeAs: "email" });
```

---

## 6. Configuration

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

---

# 📖 StringConverter — Type‑Aware String Conversion

The `StringConverter` is the bridge between arbitrary `unknown` input and the **string‑based sanitization engine**.  
It ensures that all inputs are safely converted into strings, while surfacing warnings and metadata when conversion may cause **data loss**.

---

## 🚀 Features

- 🔌 **Type‑aware conversion** for strings, numbers, booleans, BigInt, Dates, Buffers, arrays, and objects.  
- 🛡️ **Safe serialization** using `safe-stable-stringify` (handles circular references, stable key ordering).  
- ⚠️ **Warnings system** to flag potential precision or structure loss.  
- 📊 **Metadata** describing original type, conversion method, and data‑loss risk.  
- 🔐 **SecurityLevel‑aware behavior**:
  - **low** → fast path, minimal checks.  
  - **medium** → warnings logged, metadata included.  
  - **high** → suspicious conversions escalate to errors.  
  - **paranoid** → only primitives and JSON allowed; everything else rejected.  

---

## 📦 Installation

```bash
npm install safe-stable-stringify
```

---

## 🧩 Usage

### Basic Conversion

```ts
import { StringConverter } from "./StringConverter";

const result = StringConverter.toString(123, "json", "medium");

console.log(result.value);     // "123"
console.log(result.warnings);  // []
console.log(result.metadata);  // { originalType: "number", conversionType: "direct", dataLoss: false }
console.log(result.isSafe());  // true
```

---

### Handling Arrays

```ts
StringConverter.toString([1, 2, 3], "json", "medium");
// → { value: "[1,2,3]", warnings: [], isSafe: true }

StringConverter.toString([1, 2, 3], "search-query", "medium");
// → { value: "1 2 3", warnings: ["Array flattened to string"], isSafe: false }
```

---

### Handling Objects

```ts
StringConverter.toString({ age: { $gt: 30 } }, "json", "high");
// → { value: "{\"age\":{\"$gt\":30}}", warnings: [], isSafe: true }

StringConverter.toString({ a: 1, b: 2 }, "html", "medium");
// → { value: "{\"a\":1,\"b\":2}", warnings: ["Object converted to JSON string"], isSafe: false }
```

---

### Handling Special Types

```ts
StringConverter.toString(BigInt(9007199254740991), "json", "medium");
// → { value: "9007199254740991", warnings: ["BigInt precision may be lost"], isSafe: false }

StringConverter.toString(new Date("invalid"), "date-iso", "medium");
// → { value: "Invalid Date", warnings: ["Invalid Date"], isSafe: false }

StringConverter.toString(Buffer.from("hello"), "json", "medium");
// → { value: "aGVsbG8=", warnings: [], isSafe: true }
```

---

## 🔐 SecurityLevel Behavior

| SecurityLevel | Behavior |
|---------------|----------|
| **low**       | Fast path, minimal warnings, metadata skipped. |
| **medium**    | Metadata included, warnings logged. |
| **high**      | Suspicious conversions escalate to errors (e.g., BigInt, non‑finite numbers). |
| **paranoid**  | Rejects anything except safe primitives and JSON. |

Example:

```ts
StringConverter.toString([1,2,3], "search-query", "low");
// → { value: "1 2 3", warnings: [] }   // warnings suppressed

StringConverter.toString([1,2,3], "search-query", "paranoid");
// → throws Error("Array flattening not allowed at paranoid level")
```

---

## 📊 Data Loss Detection

You can pre‑check whether conversion will cause data loss:

```ts
const check = StringConverter.willLoseData([1,2,3], "search-query");

console.log(check.willLose);   // true
console.log(check.reasons);    // ["Array will be flattened to string"]
```

---

## 🏁 Best Practices

- Use `sanitizeAs: "json"` for structured data (filters, configs).  
- Use `sanitizeAs: "search-query"` for search strings.  
- Always pass `SecurityLevel` from your controller or app config.  
- Treat warnings seriously — they indicate potential precision or structure loss.  
- At **high/paranoid** levels, escalate warnings to errors to enforce strict safety.

---

## 🔧 Example Integration with StringSanitizer

```ts
const { normalized } = validateAndNormalizeOptions(
  { sanitizeAs: "mongodb-filter", securityLevel: "high" },
  req.query
);

const converted = StringConverter.toString(req.query, "json", normalized.securityLevel);

if (!converted.isSafe()) {
  throw new Error(`Unsafe conversion: ${converted.warnings.join(", ")}`);
}
```

---

# 🧭 Final Notes

The refactored `StringConverter` is designed to be:

- **Fast** for common cases.  
- **Safe** for complex inputs.  
- **Flexible** across sanitization contexts.  
- **Adaptive** to different security levels.  

It’s the backbone of your **Sanitizer** pipeline, ensuring that every input is converted consistently, safely, and transparently.

---

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