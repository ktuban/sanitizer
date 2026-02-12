import { describe, test, expect, beforeEach } from '@jest/globals';
import { createSanitizerSystem } from '../src/sanitizers/factory.js';

describe('SanitizerDiagnostics', () => {
  let diagnostics: ReturnType<typeof createSanitizerSystem>['diagnostics'];

  beforeEach(async () => {
    const system = createSanitizerSystem();
    diagnostics = system.diagnostics;
  });

  describe('Basic diagnostics', () => {
    test('should run all diagnostics', async () => {
      const report = await diagnostics.runAll({ deep: false });

      expect(report).toHaveProperty('summary');
      expect(report.summary).toHaveProperty('total');
      expect(report.summary).toHaveProperty('passed');
      expect(report.summary).toHaveProperty('failed');
      expect(report).toHaveProperty('results');
      expect(Array.isArray(report.results)).toBe(true);
    });

    test('should have test results with expected structure', async () => {
      const report = await diagnostics.runAll({ deep: false });

      // Check first few results
      for (const result of report.results.slice(0, 5)) {
        expect(result).toHaveProperty('id');
        expect(result).toHaveProperty('category');
        expect(result).toHaveProperty('severity');
        expect(result).toHaveProperty('passed');
        expect(result).toHaveProperty('message');
        expect(typeof result.id).toBe('string');
        expect(typeof result.category).toBe('string');
        expect(typeof result.severity).toBe('string');
        expect(typeof result.passed).toBe('boolean');
        expect(typeof result.message).toBe('string');
      }
    });

    test('should have security tests', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const securityTests = report.results.filter(r => r.category === 'security');
      expect(securityTests.length).toBeGreaterThan(0);

      // Check for specific security test categories
      const testIds = securityTests.map(t => t.id);
      expect(testIds.some(id => id.includes('xss'))).toBe(true);
      expect(testIds.some(id => id.includes('ssrf'))).toBe(true);
      expect(testIds.some(id => id.includes('nosql'))).toBe(true);
    });
  });

  describe('Deep diagnostics', () => {
    test('should run deep diagnostics with same tests (deep parameter may affect behavior)', async () => {
      const shallowReport = await diagnostics.runAll({ deep: false });
      const deepReport = await diagnostics.runAll({ deep: true });

      // Both should have same number of tests since deep parameter might not affect test count
      // but could affect test behavior
      expect(deepReport.summary.total).toBe(shallowReport.summary.total);
    });

    test('should have security tests with edge case payloads', async () => {
      const report = await diagnostics.runAll({ deep: true });
      
      const edgeCaseTests = report.results.filter(r => 
        r.id.includes('control-chars') || r.id.includes('null')
      );
      expect(edgeCaseTests.length).toBeGreaterThan(0);
    });
  });

  describe('Test categories', () => {
    test('should have observability tests', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const observabilityTests = report.results.filter(r => r.category === 'observability');
      expect(observabilityTests.length).toBeGreaterThan(0);

      // Check for audit logging and metrics tests
      const testMessages = observabilityTests.map(t => t.message.toLowerCase());
      expect(testMessages.some(msg => msg.includes('audit'))).toBe(true);
      expect(testMessages.some(msg => msg.includes('metric'))).toBe(true);
    });

    test('should have performance tests', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const performanceTests = report.results.filter(r => r.category === 'performance');
      expect(performanceTests.length).toBeGreaterThan(0);
    });

    test('should have validator tests', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const validatorTests = report.results.filter(r => r.category === 'validator');
      expect(validatorTests.length).toBeGreaterThan(0);
    });

    test('should have plugin tests', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const pluginTests = report.results.filter(r => r.category === 'plugin');
      expect(pluginTests.length).toBeGreaterThan(0);
    });

    test('should have config tests', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const configTests = report.results.filter(r => r.category === 'config');
      expect(configTests.length).toBeGreaterThan(0);
    });
  });

  describe('Test results validation', () => {
    test('should have high pass rate', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const passRate = report.summary.passed / report.summary.total;
      expect(passRate).toBeGreaterThan(0.8); // At least 80% pass rate
    });

    test('should not have critical failures', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const criticalFailures = report.results.filter(r => 
        r.severity === 'critical' && !r.passed
      );
      expect(criticalFailures.length).toBe(0);
    });

    test('should provide remediation for failures when available', async () => {
      const report = await diagnostics.runAll({ deep: false });
      
      const failures = report.results.filter(r => !r.passed);
      for (const failure of failures) {
        // remediation is optional, but if present should be a string
        if (failure.remediation) {
          expect(typeof failure.remediation).toBe('string');
          expect(failure.remediation.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('Diagnostics configuration', () => {
    test('should respect configuration options', async () => {
      const system = createSanitizerSystem({
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

      const report = await system.diagnostics.runAll({ deep: false });
      
      // Should have audit logging tests
      const auditTests = report.results.filter(r => 
        r.id.includes('audit') || r.message.includes('audit')
      );
      expect(auditTests.length).toBeGreaterThan(0);
    });
  });
});