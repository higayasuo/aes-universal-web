import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { NodeCbcCipher } from 'expo-aes-universal-node';
import { CryptoModule } from 'expo-crypto-universal';
import crypto from 'crypto';

const keyConfigs = [
  { enc: 'A128CBC-HS256' as const, keyBytes: 16 },
  { enc: 'A192CBC-HS384' as const, keyBytes: 24 },
  { enc: 'A256CBC-HS512' as const, keyBytes: 32 },
] as const;

describe('CbcCipher.encryptInternal', () => {
  let mockCryptoModule: CryptoModule;
  let webCipher: WebCbcCipher;
  let nodeCipher: NodeCbcCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
      sha256Async: vi.fn().mockImplementation((data: Uint8Array) => {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return Promise.resolve(new Uint8Array(hash.digest()));
      }),
    } as unknown as CryptoModule;
    webCipher = new WebCbcCipher(mockCryptoModule);
    nodeCipher = new NodeCbcCipher(mockCryptoModule);
  });

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %j',
    async ({ keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const iv = new Uint8Array(16).fill(0x42);
      const plaintext = new Uint8Array([1, 2, 3]);

      const webResult = await webCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      expect(webResult).toEqual(nodeResult);
    },
  );

  it.each(keyConfigs)(
    'should handle empty plaintext consistently for %j',
    async ({ keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const iv = new Uint8Array(16).fill(0x42);
      const plaintext = new Uint8Array(0);

      const webResult = await webCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      expect(webResult).toEqual(nodeResult);
    },
  );

  it.each(keyConfigs)(
    'should handle block-aligned plaintext with PKCS#7 padding consistently for %j',
    async ({ keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const iv = new Uint8Array(16).fill(0x42);
      const plaintext = new Uint8Array(1024).fill(0xaa);

      const webResult = await webCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      expect(webResult).toEqual(nodeResult);
      expect(webResult.length).toBe(1040); // 1024 + 16 bytes of padding
    },
  );
});
