import { describe, test, expect, beforeEach } from '@jest/globals';
import { createConfiguredSecuritySanitizer } from '../src/sanitizers/factory.js';

describe('SecurityStringSanitizer', () => {
  let security: ReturnType<typeof createConfiguredSecuritySanitizer>;

  beforeEach(() => {
    security = createConfiguredSecuritySanitizer({
      auditLogging: {
        enabled: true,
        logLevel: 'all',
        destination: 'console',
        maxLogs: 1000,
        retentionDays: 7,
        alertOn: ['CRITICAL', 'HIGH'],
        redactFields: ["password", "token", "authorization", "creditCard"]
      },
      rateLimiting: {
        enabled: true,
        requestsPerMinute: 100,
        blockDurationMs: 300000,
        cleanupIntervalMs: 60000,
        suspiciousPatterns: []
      }
    });
  });

  describe('Basic sanitization with security features', () => {
    test('should sanitize email with audit logging', async () => {
      const result = await security.sanitize('user@example.com', {
        sanitizeAs: 'email',
      });

      expect(result.sanitized).toBe('user@example.com');
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });

    test('should detect and log suspicious patterns', async () => {
      const xssPayload = '<script>alert("xss")</script>';
      const result = await security.sanitize(xssPayload, {
        sanitizeAs: 'html',
      });

      expect(result.sanitized).not.toContain('<script>');
      // Should have warnings about suspicious patterns
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    test('should handle command injection attempts', async () => {
      const commandInjection = 'test; rm -rf /';
      const result = await security.sanitize(commandInjection, {
        sanitizeAs: 'plain-text',
        securityLevel: 'high'
      });

      expect(result.warnings.some(w => 
        w.includes('suspicious pattern') || 
        w.includes('command injection')
      )).toBe(true);
    });
  });

  describe('Rate limiting', () => {
    test('should allow requests within rate limit', async () => {
      const ipAddress = '192.168.1.1';
      
      // Make multiple requests
      for (let i = 0; i < 5; i++) {
        const result = await security.sanitize(`test${i}@example.com`, {
          sanitizeAs: 'email',
        });
        expect(result.sanitized).toBe(`test${i}@example.com`);
      }
    });

    test('should detect abuse patterns', async () => {
      const sqlInjection = "' OR '1'='1";
      const result = await security.sanitize(sqlInjection, {
        sanitizeAs: 'sql-identifier',
      });

      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });

  describe('Audit logging', () => {
    test('should log security events', async () => {
      const maliciousInput = '../../etc/passwd';
      const result = await security.sanitize(maliciousInput, {
        sanitizeAs: 'path',
        securityLevel: 'high'
      });

      expect(result.sanitized).not.toContain('..');
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    test('should log validation failures', async () => {
      const invalidEmail = 'not-an-email';
      const result = await security.sanitize(invalidEmail, {
        sanitizeAs: 'email',
      });

      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('Security levels', () => {
    test('should apply different security levels', async () => {
      const testInput = 'test<script>alert(1)</script>';

      // Low security level
      const lowResult = await security.sanitize(testInput, {
        sanitizeAs: 'html',
        securityLevel: 'low'
      });

      // High security level
      const highResult = await security.sanitize(testInput, {
        sanitizeAs: 'html',
        securityLevel: 'high'
      });

      // Paranoid security level
      const paranoidResult = await security.sanitize(testInput, {
        sanitizeAs: 'html',
        securityLevel: 'paranoid'
      });

      // Higher security levels should have more warnings/errors
      expect(highResult.warnings.length).toBeGreaterThanOrEqual(lowResult.warnings.length);
      expect(paranoidResult.warnings.length).toBeGreaterThanOrEqual(highResult.warnings.length);
    });

    test('should reject dangerous inputs at paranoid level', async () => {
      const dangerousInput = '<iframe src="javascript:alert(1)"></iframe>';
      
      const result = await security.sanitize(dangerousInput, {
        sanitizeAs: 'html',
        securityLevel: 'paranoid'
      });

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.sanitized).not.toContain('<iframe');
    });
  });

  describe('Internationalization security', () => {
    test('should handle homoglyph attacks', async () => {
      const homoglyph = 'аррӏе.com'; // Looks like "apple.com"
      const result = await security.sanitize(homoglyph, {
        sanitizeAs: 'url',
        securityLevel: 'high'
      });

      expect(result.warnings.some(w => 
        w.includes('homoglyph') || 
        w.includes('internationalization')
      )).toBe(true);
    });

    test('should handle mixed script attacks', async () => {
      const mixedScript = 'paypal.com' + 'р' + 'aypal.com'; // Cyrillic 'р' in the middle
      const result = await security.sanitize(mixedScript, {
        sanitizeAs: 'url',
        securityLevel: 'high'
      });

      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });

  describe('Performance and resource limits', () => {
    test('should handle large inputs within limits', async () => {
      const largeInput = 'A'.repeat(5000); // 5KB
      const result = await security.sanitize(largeInput, {
        sanitizeAs: 'plain-text',
      });

      expect(result.sanitized).toBe(largeInput);
      expect(result.errors).toHaveLength(0);
    });

    test('should reject excessively large inputs', async () => {
      const hugeInput = 'A'.repeat(15000); // 15KB, exceeds default limit
      const result = await security.sanitize(hugeInput, {
        sanitizeAs: 'plain-text',
      });

      expect(result.errors.length).toBeGreaterThan(0);
    });
  });
});