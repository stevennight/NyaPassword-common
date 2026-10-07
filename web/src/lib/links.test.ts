import { describe, expect, it } from 'vitest';
import { webUrl } from './links';

describe('webUrl', () => {
  it('opens http(s) addresses and bare hosts', () => {
    expect(webUrl('https://example.com/login')).toBe('https://example.com/login');
    expect(webUrl('http://203.0.113.5:8080')).toBe('http://203.0.113.5:8080/');
    expect(webUrl(' example.com ')).toBe('https://example.com/');
    expect(webUrl('example.com:8443/a')).toBe('https://example.com:8443/a');
  });

  it('refuses other schemes', () => {
    expect(webUrl('androidapp://com.example.app')).toBeNull();
    expect(webUrl('javascript:alert(1)')).toBeNull();
    expect(webUrl('file:///C:/Windows/System32/calc.exe')).toBeNull();
    expect(webUrl('')).toBeNull();
  });
});
