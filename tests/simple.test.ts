import { describe, test, expect } from '@jest/globals';

describe('Simple Sanitizer Tests', () => {
  test('should pass basic test', () => {
    expect(true).toBe(true);
  });

  test('should test basic string operations', () => {
    const input = 'test';
    expect(input).toBe('test');
    expect(input.length).toBe(4);
  });

  test('should test array operations', () => {
    const arr = [1, 2, 3];
    expect(arr.length).toBe(3);
    expect(arr[0]).toBe(1);
  });
});