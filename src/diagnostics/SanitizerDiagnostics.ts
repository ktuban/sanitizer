// SanitizerDiagnostics.ts

import {
  SanitizeAs,
  SecurityLevel,
  ISanitizerGlobalConfig,
  ValidationStrategy,
  SanitizerPlugins,
  ISanitizationResult,
} from "../types.js";

import { SecurityStringSanitizer } from "../sanitizers/SecurityStringSanitizer.js";
import { ValidationStrategyRegistry } from "../validators/validaters.js";

/**
 * Diagnostic categories.
 */

export type DiagnosticCategory =
  | "config"
  | "validator"
  | "security"
  | "plugin"
  | "performance"
  | "observability";

/**
 * Diagnostic severity.
 */
export type DiagnosticSeverity =
  | "info"
  | "warning"
  | "error"
  | "critical";

/**
 * Result of a single diagnostic test.
 */
export interface DiagnosticResult {
  id: string;
  category: DiagnosticCategory;
  severity: DiagnosticSeverity;
  message: string;
  remediation?: string;
  details?: any;
  sanitizeAs?: SanitizeAs;
  securityLevel?: SecurityLevel;
  passed: boolean;
  durationMs: number;
}

/**
 * Aggregated diagnostic report.
 */
export interface DiagnosticReport {
  summary: {
    total: number;
    passed: number;
    warnings: number;
    errors: number;
    critical: number;
    durationMs: number;
  };
  results: DiagnosticResult[];
}

/**
 * Context passed to each diagnostic test.
 */
export interface DiagnosticContext {
  sanitizer: SecurityStringSanitizer;
  config: ISanitizerGlobalConfig;
  validators: ValidationStrategyRegistry;
  plugins: SanitizerPlugins;
  deep: boolean;
}

/**
 * A diagnostic test function.
 */
export type DiagnosticTest = (ctx: DiagnosticContext) => Promise<DiagnosticResult>;

/**
 * Global registry of diagnostic tests.
 */
const diagnosticRegistry: DiagnosticTest[] = [];

/* ============================================================================
 * Type-Specific Malicious Payload Suites
 * ============================================================================
 */

const maliciousPayloads: Record<
  SanitizeAs,
  { id: string; description: string; sample: string }[]
> = {
  /* ============================================================
   * HIGH‑RISK TYPES (already provided)
   * ============================================================ */

  html: [
    {
      id: "xss-basic",
      description: "XSS payload using <script>",
      sample: `<script>alert('xss')</script>`
    },
    {
      id: "xss-img-onerror",
      description: "XSS via <img onerror>",
      sample: `<img src=x onerror=alert('xss')>`
    }
  ],

  "html-attribute": [
    {
      id: "xss-attr-javascript-url",
      description: "XSS via javascript: URL",
      sample: `href="javascript:alert('xss')"`
    }
  ],

  json: [
    {
      id: "prototype-pollution",
      description: "Prototype pollution via __proto__",
      sample: `{"__proto__": {"polluted": true}}`
    }
  ],

  url: [
    {
      id: "ssrf-file",
      description: "SSRF via file://",
      sample: `file:///etc/passwd`
    },
    {
      id: "ssrf-internal",
      description: "SSRF to internal metadata service",
      sample: `http://169.254.169.254/latest/meta-data`
    }
  ],

  path: [
    {
      id: "path-traversal",
      description: "Path traversal using ../",
      sample: `../../etc/passwd`
    }
  ],

  "path-safe": [
    {
      id: "path-traversal-safe",
      description: "Path traversal attempt in safe path context",
      sample: `../../../etc/shadow`
    }
  ],

  "mongodb-filter": [
    {
      id: "nosql-injection-operator",
      description: "NoSQL injection via $ne",
      sample: `{"username": {"$ne": ""}}`
    }
  ],

  "sql-identifier": [
    {
      id: "sql-injection",
      description: "SQL injection attempt",
      sample: `users; DROP TABLE users;`
    }
  ],

  /* ============================================================
   * MEDIUM‑RISK TYPES (format + injection attempts)
   * ============================================================ */

  email: [
    {
      id: "email-injection",
      description: "Email header injection attempt",
      sample: `test@example.com\r\nBCC: attacker@example.com`
    }
  ],

  password: [
    {
      id: "password-script",
      description: "Password containing script tag",
      sample: `p@ss<script>alert(1)</script>`
    }
  ],

  username: [
    {
      id: "username-xss",
      description: "Username containing HTML",
      sample: `<b>admin</b>`
    }
  ],

  "plain-text": [
    {
      id: "plaintext-control-chars",
      description: "Control characters in plain text",
      sample: `Hello\u0000World`
    }
  ],

  filename: [
    {
      id: "filename-traversal",
      description: "Filename with traversal",
      sample: `../../secret.txt`
    }
  ],

  "search-query": [
    {
      id: "search-xss",
      description: "Search query with HTML injection",
      sample: `<img src=x onerror=alert(1)>`
    }
  ],

  phone: [
    {
      id: "phone-injection",
      description: "Phone number with SQL injection",
      sample: `12345 OR 1=1`
    }
  ],

  "zip-code": [
    {
      id: "zip-code-injection",
      description: "Zip code with JS injection",
      sample: `12345<script>alert(1)</script>`
    }
  ],

  "credit-card": [
    {
      id: "creditcard-invalid",
      description: "Invalid credit card with letters",
      sample: `4111-1111-1111-ABCD`
    }
  ],

  uuid: [
    {
      id: "uuid-invalid",
      description: "Invalid UUID with script",
      sample: `1234<script>1</script>`
    }
  ],

  base64: [
    {
      id: "base64-invalid",
      description: "Invalid base64 with symbols",
      sample: `@@@notbase64@@@`
    }
  ],

  hex: [
    {
      id: "hex-invalid",
      description: "Invalid hex with non-hex chars",
      sample: `GGGGGG`
    }
  ],

  "ip-address": [
    {
      id: "ip-injection",
      description: "IP address with SQL injection",
      sample: `127.0.0.1 OR 1=1`
    }
  ],

  "mongodb-id": [
    {
      id: "mongoid-invalid",
      description: "Invalid MongoDB ObjectId",
      sample: `ZZZZZZZZZZZZZZZZZZZZZZZZ`
    }
  ],

  currency: [
    {
      id: "currency-invalid",
      description: "Currency with HTML injection",
      sample: `$100<script>alert(1)</script>`
    }
  ],

  percentage: [
    {
      id: "percentage-invalid",
      description: "Percentage with JS injection",
      sample: `50%"><script>alert(1)</script>`
    }
  ],

  "color-hex": [
    {
      id: "colorhex-invalid",
      description: "Invalid color hex with script",
      sample: `#GGGGGG<script>1</script>`
    }
  ],

  "date-iso": [
    {
      id: "dateiso-invalid",
      description: "Invalid ISO date",
      sample: `2025-99-99`
    }
  ],

  "time-iso": [
    {
      id: "timeiso-invalid",
      description: "Invalid ISO time",
      sample: `25:61:99`
    }
  ],

  "datetime-iso": [
    {
      id: "datetimeiso-invalid",
      description: "Invalid ISO datetime",
      sample: `2025-13-40T99:99:99Z`
    }
  ]
};

/* ============================================================================
 * Diagnostic Test Generators
 * ============================================================================
 */

/**
 * Security tests using real sanitizer behavior.
 */
function createTypeSpecificSecurityTests(): DiagnosticTest[] {
  const tests: DiagnosticTest[] = [];

  for (const sanitizeAs of Object.keys(maliciousPayloads) as SanitizeAs[]) {
    const payloads = maliciousPayloads[sanitizeAs];

    for (const payload of payloads) {
      const test: DiagnosticTest = async (ctx) => {
        const start = performance.now();

        try {
          const result = await ctx.sanitizer.sanitize(payload.sample, {
            sanitizeAs,
            mode: "sanitize-for-storage",
          });

          const reacted = result.errors.length > 0 || result.warnings.length > 0;

          return {
            id: `security.${payload.id}.${sanitizeAs}`,
            category: "security",
            severity: reacted ? "info" : "critical",
            message: reacted
              ? `${payload.description} test passed for '${sanitizeAs}'.`
              : `${payload.description} test FAILED for '${sanitizeAs}'.`,
            remediation: reacted
              ? undefined
              : `Update validator for '${sanitizeAs}' to detect: ${payload.description}.`,
            details: {
              payload: payload.sample,
              errors: result.errors,
              warnings: result.warnings,
            },
            sanitizeAs,
            passed: reacted,
            durationMs: performance.now() - start,
          };
        } catch (error) {
          return {
            id: `security.${payload.id}.${sanitizeAs}`,
            category: "security",
            severity: "critical",
            message: `Sanitizer threw an error during ${payload.description} test.`,
            remediation: `Fix sanitizer error handling for '${sanitizeAs}'.`,
            details: { error },
            sanitizeAs,
            passed: false,
            durationMs: performance.now() - start,
          };
        }
      };

      tests.push(test);
    }
  }

  return tests;
}

/**
 * Validator existence tests.
 */
function createValidatorExistenceTests(): DiagnosticTest[] {
  return Array.from(Object.keys(maliciousPayloads) as SanitizeAs[]).map((sanitizeAs) => {
    return async (ctx) => {
      const exists = ctx.validators.has(sanitizeAs);

      return {
        id: `validator.exists.${sanitizeAs}`,
        category: "validator",
        severity: exists ? "info" : "error",
        message: exists
          ? `Validator for '${sanitizeAs}' is registered.`
          : `Validator for '${sanitizeAs}' is missing.`,
        remediation: exists
          ? undefined
          : `Register a validator for '${sanitizeAs}'.`,
        sanitizeAs,
        passed: exists,
        durationMs: 0,
      };
    };
  });
}

/**
 * Plugin presence tests.
 */
function createPluginPresenceTests(): DiagnosticTest[] {
  return [
    async (ctx) => {
      const missing: string[] = [];

      if (!ctx.plugins.auditLogger) missing.push("auditLogger");
      if (!ctx.plugins.abusePrevention) missing.push("abusePrevention");

      const passed = missing.length === 0;

      return {
        id: "plugin.presence",
        category: "plugin",
        severity: passed ? "info" : "warning",
        message: passed
          ? "All plugins configured."
          : `Missing plugins: ${missing.join(", ")}`,
        remediation: passed
          ? undefined
          : "Configure missing plugins for full security perimeter.",
        details: { missing },
        passed,
        durationMs: 0,
      };
    },
  ];
}


/* ============================================================================
 * Rate Limiting Test
 * ============================================================================
 */
function createRateLimitingTest(): DiagnosticTest {
  return async (ctx) => {
    const start = performance.now();

    const { sanitizer, config } = ctx;

    // If rate limiting disabled → warning, not failure
    if (!config.rateLimiting.enabled) {
      return {
        id: "security.rate-limiting-disabled",
        category: "security",
        severity: "warning",
        message: "Rate limiting is disabled in configuration.",
        remediation: "Enable rate limiting for production environments.",
        passed: false,
        durationMs: performance.now() - start,
      };
    }

    const ip = "203.0.113.10";
    const attempts = Math.min(
      config.rateLimiting.requestsPerMinute + 5,
      config.rateLimiting.requestsPerMinute + 20
    );

    let blocked = false;

    for (let i = 0; i < attempts; i++) {
      try {
        await sanitizer.sanitize("rate-limit-test", {
          sanitizeAs: "plain-text",
        }, { ipAddress: ip });
      } catch {
        blocked = true;
        break;
      }
    }

    if (!blocked) {
      return {
        id: "security.rate-limiting",
        category: "security",
        severity: "warning",
        message: `Rate limiting did not trigger after ${attempts} attempts.`,
        remediation: "Verify abusePrevention plugin configuration.",
        passed: false,
        durationMs: performance.now() - start,
      };
    }

    return {
      id: "security.rate-limiting",
      category: "security",
      severity: "info",
      message: "Rate limiting triggered as expected.",
      passed: true,
      durationMs: performance.now() - start,
    };
  };
}

/* ============================================================================
 * Metrics Increment Test
 * ============================================================================
 */
function createMetricsIncrementTest(): DiagnosticTest {
  return async (ctx) => {
    const start = performance.now();

    const before = ctx.sanitizer.getMetrics?.();
    if (!before) {
      return {
        id: "observability.metrics-missing",
        category: "observability",
        severity: "warning",
        message: "getMetrics() not implemented on sanitizer.",
        passed: false,
        durationMs: performance.now() - start,
      };
    }

    await ctx.sanitizer.sanitize("metrics-test", { sanitizeAs: "plain-text" });

    const after = ctx.sanitizer.getMetrics();

    const passed = after.calls === before.calls + 1;

    return {
      id: "observability.metrics-increment",
      category: "observability",
      severity: passed ? "info" : "error",
      message: passed
        ? "Metrics 'calls' counter increments correctly."
        : `Metrics 'calls' counter did not increment (before=${before.calls}, after=${after.calls}).`,
      remediation: passed
        ? undefined
        : "Ensure SecurityStringSanitizer increments metrics on each sanitize() call.",
      passed,
      durationMs: performance.now() - start,
    };
  };
}

/* ============================================================================
 * Audit Logging Test
 * ============================================================================
 */
function createAuditLoggingTest(): DiagnosticTest {
  return async (ctx) => {
    const start = performance.now();

    if (!ctx.sanitizer.getAuditLogs) {
      return {
        id: "observability.audit-logging-missing",
        category: "observability",
        severity: "warning",
        message: "Audit logging not available on sanitizer.",
        passed: false,
        durationMs: performance.now() - start,
      };
    }

    const before = ctx.sanitizer.getAuditLogs({ type: "SECURITY" }) ?? [];

    await ctx.sanitizer.sanitize(`<script>alert(1)</script>`, {
      sanitizeAs: "html",
    });

    const after = ctx.sanitizer.getAuditLogs({ type: "SECURITY" }) ?? [];

    const passed = after.length > before.length;

    return {
      id: "observability.audit-logging",
      category: "observability",
      severity: passed ? "info" : "error",
      message: passed
        ? "Security audit logs increased after suspicious input."
        : "Security audit logs did NOT increase after suspicious input.",
      remediation: passed
        ? undefined
        : "Verify auditLogger plugin configuration.",
      passed,
      durationMs: performance.now() - start,
    };
  };
}

/* ============================================================================
 * Performance Test
 * ============================================================================
 */
function createPerformanceTest(): DiagnosticTest {
  return async (ctx) => {
    const start = performance.now();

    const iterations = 50;
    const t0 = performance.now();

    for (let i = 0; i < iterations; i++) {
      await ctx.sanitizer.sanitize(`perf-${i}`, {
        sanitizeAs: "plain-text",
      });
    }

    const totalMs = performance.now() - t0;
    const avgMs = totalMs / iterations;

    const threshold = 200; // configurable if needed

    const passed = avgMs <= threshold;

    return {
      id: "performance.average-time",
      category: "performance",
      severity: passed ? "info" : "warning",
      message: passed
        ? `Average processing time OK (${avgMs.toFixed(2)}ms)`
        : `Average processing time too high (${avgMs.toFixed(
            2
          )}ms, threshold=${threshold}ms)`,
      remediation: passed
        ? undefined
        : "Investigate validator or plugin performance bottlenecks.",
      passed,
      durationMs: performance.now() - start,
    };
  };
}
/* ============================================================================
 * Registry Initialization
 * ============================================================================
 */

(function initializeRegistry() {
  diagnosticRegistry.push(
    ...createValidatorExistenceTests(),
    ...createTypeSpecificSecurityTests(),
    ...createPluginPresenceTests(),
    
    // NEW TESTS
    createRateLimitingTest(),
    createMetricsIncrementTest(),
    createAuditLoggingTest(),
    createPerformanceTest()

  );
})();

/* ============================================================================
 * SanitizerDiagnostics Class
 * ============================================================================
 */

export class SanitizerDiagnostics {
  constructor(private readonly sanitizer: SecurityStringSanitizer) {}

  async runAll(options?: { deep?: boolean }): Promise<DiagnosticReport> {
    const ctx: DiagnosticContext = {
      sanitizer: this.sanitizer,
      config: this.sanitizer.core.config,
      validators: this.sanitizer.core.validationRegistry,
      plugins: this.sanitizer.plugins,
      deep: options?.deep ?? false,
    };

    const start = performance.now();
    const results: DiagnosticResult[] = [];

    for (const test of diagnosticRegistry) {
      const result = await test(ctx);
      results.push(result);
    }

    return this.buildReport(results, performance.now() - start);
  }

  private buildReport(
    results: DiagnosticResult[],
    durationMs: number
  ): DiagnosticReport {
    const summary = {
      total: results.length,
      passed: results.filter((r) => r.passed).length,
      warnings: results.filter((r) => r.severity === "warning").length,
      errors: results.filter((r) => r.severity === "error").length,
      critical: results.filter((r) => r.severity === "critical").length,
      durationMs,
    };

    return { summary, results };
  }
}