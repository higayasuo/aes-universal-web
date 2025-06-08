import { describe, it, expect, vi } from 'vitest';
import { WebAesCipher } from '../WebAesCipher';
import { WebCbcCipher } from '../WebCbcCipher';
import { WebGcmCipher } from '../WebGcmCipher';

describe('WebAesCipher', () => {
  const getRandomBytes = vi
    .fn()
    .mockImplementation((size) => new Uint8Array(size).fill(0x42));

  it('should initialize with WebCbcCipher and WebGcmCipher', () => {
    const cipher = new WebAesCipher(getRandomBytes);
    expect(cipher).toBeInstanceOf(WebAesCipher);
    expect(cipher['cbc']).toBeInstanceOf(WebCbcCipher);
    expect(cipher['gcm']).toBeInstanceOf(WebGcmCipher);
  });

  it('should pass randomBytes to both CBC and GCM ciphers', () => {
    const cipher = new WebAesCipher(getRandomBytes);
    expect(cipher['randomBytes']).toBe(getRandomBytes);
  });
});
