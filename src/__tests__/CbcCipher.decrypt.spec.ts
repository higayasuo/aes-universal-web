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

describe('CbcCipher.decrypt', () => {
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
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle empty ciphertext consistently for %j',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle empty AAD consistently for %j',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should reject invalid tag for %j',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const invalidTag = new Uint8Array(keyBytes).fill(0xff);

      await expect(
        webCipher.decrypt({
          enc,
          cek,
          ciphertext,
          tag: invalidTag,
          iv,
          aad,
        }),
      ).rejects.toThrow();
      await expect(
        nodeCipher.decrypt({
          enc,
          cek,
          ciphertext,
          tag: invalidTag,
          iv,
          aad,
        }),
      ).rejects.toThrow();
    },
  );
});
