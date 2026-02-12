import { describe, test, expect, beforeEach } from '@jest/globals';
import { createCoreOnlySanitizer } from '../src/sanitizers/factory.js';

describe('CoreStringSanitizer', () => {
  let core: ReturnType<typeof createCoreOnlySanitizer>;

  beforeEach(() => {
    core = createCoreOnlySanitizer();
  });

  describe('Basic sanitization', () => {
    test('should sanitize email addresses', async () => {
      const result = await core.sanitize('user@example.com', {
        sanitizeAs: 'email',
      });

      expect(result.sanitized).toBe('user@example.com');
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });

    test('should sanitize HTML content', async () => {
      const html = '<script>alert("xss")</script><p>Hello World</p>';
      const result = await core.sanitize(html, {
        sanitizeAs: 'html',
      });

      expect(result.sanitized).not.toContain('<script>');
      expect(result.sanitized).toContain('<p>Hello World</p>');
    });

    test('should sanitize URLs', async () => {
      const url = 'https://example.com/path?query=test<script>alert(1)</script>';
      const result = await core.sanitize(url, {
        sanitizeAs: 'url',
      });

      expect(result.sanitized).toMatch(/^https:\/\/example\.com\/path\?query=test/);
      expect(result.sanitized).not.toContain('<script>');
    });

    test('should sanitize JSON strings', async () => {
      const json = '{"name": "John", "age": 30, "__proto__": {"polluted": true}}';
      const result = await core.sanitize(json, {
        sanitizeAs: 'json',
      });

      expect(() => JSON.parse(result.sanitized)).not.toThrow();
      const parsed = JSON.parse(result.sanitized);
      expect(parsed.name).toBe('John');
      expect(parsed.age).toBe(30);
      expect(parsed.__proto__).toBeUndefined();
    });
  });

  describe('Edge cases', () => {
    test('should handle empty strings', async () => {
      const result = await core.sanitize('', {
        sanitizeAs: 'plain-text',
      });

      expect(result.sanitized).toBe('');
      expect(result.errors).toHaveLength(0);
    });

    test('should handle null characters', async () => {
      const text = 'Hello\u0000World';
      const result = await core.sanitize(text, {
        sanitizeAs: 'plain-text',
      });

      expect(result.sanitized).toBe('HelloWorld');
    });

    test('should handle very long strings', async () => {
      const longText = 'A'.repeat(10000);
      const result = await core.sanitize(longText, {
        sanitizeAs: 'plain-text',
      });

      expect(result.sanitized).toBe(longText);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Security features', () => {
    test('should prevent XSS in HTML', async () => {
      const xssPayload = '<img src=x onerror=alert(1)>';
      const result = await core.sanitize(xssPayload, {
        sanitizeAs: 'html',
      });

      expect(result.sanitized).not.toContain('onerror');
      expect(result.sanitized).not.toContain('alert(1)');
    });

    test('should prevent SQL injection', async () => {
      const sqlInjection = "'; DROP TABLE users; --";
      const result = await core.sanitize(sqlInjection, {
        sanitizeAs: 'sql-identifier',
      });

      expect(result.sanitized).not.toContain('DROP');
      expect(result.sanitized).not.toContain('--');
    });

    test('should prevent path traversal', async () => {
      const pathTraversal = '../../../etc/passwd';
      const result = await core.sanitize(pathTraversal, {
        sanitizeAs: 'path',
      });

      expect(result.sanitized).not.toContain('..');
      expect(result.sanitized).not.toContain('/etc/passwd');
    });
  });

  describe('Internationalization', () => {
    test('should handle Unicode characters', async () => {
      const unicodeText = 'Hello 世界 🌍';
      const result = await core.sanitize(unicodeText, {
        sanitizeAs: 'plain-text',
      });

      expect(result.sanitized).toBe('Hello 世界 🌍');
      expect(result.errors).toHaveLength(0);
    });

    test('should handle RTL text', async () => {
      const rtlText = 'مرحبا بالعالم';
      const result = await core.sanitize(rtlText, {
        sanitizeAs: 'plain-text',
      });

      expect(result.sanitized).toBe('مرحبا بالعالم');
      expect(result.errors).toHaveLength(0);
    });

    test('should handle emoji', async () => {
      const emojiText = 'Hello 🎉🎊😊🌟✨';
      const result = await core.sanitize(emojiText, {
        sanitizeAs: 'plain-text',
      });

      expect(result.sanitized).toBe('Hello 🎉🎊😊🌟✨');
      expect(result.errors).toHaveLength(0);
    });
  });
});