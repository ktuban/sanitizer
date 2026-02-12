import { describe, test, expect } from '@jest/globals';

// Test that we can import from the built CJS module
describe('Built Sanitizer Tests', () => {
  test('should import sanitizer module', async () => {
    // Try to import the built module
    const module = await import('../dist/cjs/index.js');
    expect(module).toBeDefined();
    expect(typeof module).toBe('object');
  });

  test('should have expected exports', async () => {
    const module = await import('../dist/cjs/index.js');
    
    // Check for expected exports
    expect(module).toHaveProperty('createSanitizerSystem');
    expect(module).toHaveProperty('createEnhancedSanitizerSystemAsync');
    expect(module).toHaveProperty('SanitizerError');
    
    // Check types
    expect(typeof module.createSanitizerSystem).toBe('function');
    expect(typeof module.createEnhancedSanitizerSystemAsync).toBe('function');
  });

  test('should create sanitizer system', async () => {
    const { createSanitizerSystem } = await import('../dist/cjs/index.js');
    
    const system = createSanitizerSystem();
    expect(system).toBeDefined();
    expect(system).toHaveProperty('core');
    expect(system).toHaveProperty('security');
    expect(system).toHaveProperty('diagnostics');
    
    // Check that core has sanitize method
    expect(system.core).toHaveProperty('sanitize');
    expect(typeof system.core.sanitize).toBe('function');
    
    // Check that security has sanitize method
    expect(system.security).toHaveProperty('sanitize');
    expect(typeof system.security.sanitize).toBe('function');
    
    // Check diagnostics
    expect(system.diagnostics).toHaveProperty('runAll');
    expect(typeof system.diagnostics.runAll).toBe('function');
  });
});
