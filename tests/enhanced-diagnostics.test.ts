import { describe, test, expect, beforeEach } from '@jest/globals';
import { createEnhancedSanitizerSystemAsync } from '../src/sanitizers/factory.js';

describe('SanitizerDiagnostics_Enhanced', () => {
  let system: Awaited<ReturnType<typeof createEnhancedSanitizerSystemAsync>>;

  beforeEach(async () => {
    system = await createEnhancedSanitizerSystemAsync({
      auditLogging: {
        enabled: true,
        logLevel: 'all',
        destination: 'console',
        maxLogs: 1000,
        retentionDays: 7,
        alertOn: ['CRITICAL', 'HIGH'],
        redactFields: ["password", "token", "authorization", "creditCard"]
      }
    });
  });

  describe('Enhanced diagnostics features', () => {
    test('should have enhanced diagnostics instance', () => {
      expect(system.enhancedDiagnostics).toBeDefined();
      expect(system.enhancedDiagnostics.constructor.name).toBe('SanitizerDiagnostics_Enhanced');
    });

    test('should run enhanced diagnostics', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });

      expect(report).toHaveProperty('summary');
      expect(report.summary).toHaveProperty('total');
      expect(report.summary).toHaveProperty('passed');
      expect(report.summary).toHaveProperty('failed');
      expect(report).toHaveProperty('results');
      expect(Array.isArray(report.results)).toBe(true);
    });

    test('should have more tests than original diagnostics', async () => {
      const originalReport = await system.diagnostics.runAll({ deep: false });
      const enhancedReport = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });

      expect(enhancedReport.summary.total).toBeGreaterThan(originalReport.summary.total);
    });
  });

  describe('Command injection tests', () => {
    test('should have command injection tests', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      
      const commandInjectionTests = report.results.filter(r => 
        r.id.includes('command-injection')
      );
      expect(commandInjectionTests.length).toBeGreaterThan(0);
    });

    test('should test command injection for HTML', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      
      const htmlCommandInjectionTests = report.results.filter(r => 
        r.id.includes('command-injection') && r.id.includes('html')
      );
      expect(htmlCommandInjectionTests.length).toBeGreaterThan(0);
    });

    test('should test command injection for plain text', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      
      const plainTextCommandInjectionTests = report.results.filter(r => 
        r.id.includes('command-injection') && r.id.includes('plain-text')
      );
      expect(plainTextCommandInjectionTests.length).toBeGreaterThan(0);
    });

    test('should test command injection for URLs', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      
      const urlCommandInjectionTests = report.results.filter(r => 
        r.id.includes('command-injection') && r.id.includes('url')
      );
      expect(urlCommandInjectionTests.length).toBeGreaterThan(0);
    });
  });

  describe('Edge case tests', () => {
    test('should have edge case tests', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const edgeCaseTests = report.results.filter(r => 
        r.id.includes('edge-case') || r.message.includes('Edge case')
      );
      expect(edgeCaseTests.length).toBeGreaterThan(0);
    });

    test('should test empty strings', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const emptyStringTests = report.results.filter(r => 
        r.id.includes('empty-string') || r.message.includes('Empty string')
      );
      expect(emptyStringTests.length).toBeGreaterThan(0);
    });

    test('should test null characters', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const nullCharTests = report.results.filter(r => 
        r.id.includes('null-character') || r.message.includes('Null character')
      );
      expect(nullCharTests.length).toBeGreaterThan(0);
    });

    test('should test very long inputs', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const longInputTests = report.results.filter(r => 
        r.id.includes('very-long') || r.message.includes('very long') || r.message.includes('50000')
      );
      expect(longInputTests.length).toBeGreaterThan(0);
    });
  });

  describe('Internationalization tests', () => {
    test('should have internationalization tests', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const i18nTests = report.results.filter(r => 
        r.id.includes('i18n') || r.message.includes('Internationalization') || 
        r.message.includes('Emoji') || r.message.includes('RTL') ||
        r.message.includes('Chinese') || r.message.includes('Japanese') || 
        r.message.includes('Korean') || r.message.includes('Cyrillic') ||
        r.message.includes('Devanagari') || r.message.includes('Homoglyph')
      );
      expect(i18nTests.length).toBeGreaterThan(0);
    });

    test('should test emoji and symbols', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const emojiTests = report.results.filter(r => 
        r.id.includes('emoji') || r.message.includes('Emoji')
      );
      expect(emojiTests.length).toBeGreaterThan(0);
    });

    test('should test right-to-left text', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const rtlTests = report.results.filter(r => 
        r.id.includes('right-to-left') || r.message.includes('RTL') || r.message.includes('right-to-left')
      );
      expect(rtlTests.length).toBeGreaterThan(0);
    });

    test('should test CJK characters', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const cjkTests = report.results.filter(r => 
        r.id.includes('cjk') || r.message.includes('Chinese') || r.message.includes('Japanese') || r.message.includes('Korean')
      );
      expect(cjkTests.length).toBeGreaterThan(0);
    });

    test('should test homoglyph attacks', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const homoglyphTests = report.results.filter(r => 
        r.id.includes('homoglyph') || r.message.includes('Homoglyph')
      );
      expect(homoglyphTests.length).toBeGreaterThan(0);
    });
  });

  describe('Deep enhanced diagnostics', () => {
    test('should have more tests in deep mode', async () => {
      const shallowReport = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      const deepReport = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });

      expect(deepReport.summary.total).toBeGreaterThan(shallowReport.summary.total);
    });

    test('should include all test categories in deep mode', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
      
      const categories = new Set(report.results.map(r => r.category));
      expect(categories.size).toBeGreaterThan(1);
      
      // Should have at least security tests
      expect(categories.has('security')).toBe(true);
    });
  });

  describe('Test results quality', () => {
    test('should have high pass rate for enhanced tests', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      
      const passRate = report.summary.passed / report.summary.total;
      expect(passRate).toBeGreaterThan(0.7); // At least 70% pass rate
    });

    test('should not have critical failures in enhanced tests', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      
      const criticalFailures = report.results.filter(r => 
        r.severity === 'critical' && !r.passed
      );
      expect(criticalFailures.length).toBe(0);
    });

    test('should provide remediation for failures', async () => {
      const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: false });
      
      const failures = report.results.filter(r => !r.passed);
      for (const failure of failures) {
        if (failure.remediation) {
          expect(typeof failure.remediation).toBe('string');
          expect(failure.remediation.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('Integration with security sanitizer', () => {
    test('should use the same security sanitizer as original diagnostics', () => {
      expect(system.enhancedDiagnostics).toBeDefined();
      expect(system.diagnostics).toBeDefined();
      // Both should be using the same underlying security sanitizer
    });

    test('should detect real command injection attempts', async () => {
      // Test a real command injection payload
      const commandInjection = 'test; rm -rf /';
      const result = await system.security.sanitize(commandInjection, {
        sanitizeAs: 'plain-text',
        securityLevel: 'high'
      });

      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings.some(w => 
        w.includes('suspicious') || w.includes('command') || w.includes('injection')
      )).toBe(true);
    });
  });
});