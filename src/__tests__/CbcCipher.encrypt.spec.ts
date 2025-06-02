import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { NodeCbcCipher } from 'aes-universal-node';

const keyConfigs = [
  { enc: 'A128CBC-HS256' as const, keyBytes: 16, cekLength: 32 },
  { enc: 'A192CBC-HS384' as const, keyBytes: 24, cekLength: 48 },
  { enc: 'A256CBC-HS512' as const, keyBytes: 32, cekLength: 64 },
] as const;

describe('CbcCipher.encrypt', () => {
  const getRandomBytes = vi
    .fn()
    .mockImplementation((size) => new Uint8Array(size).fill(0x42));
  const webCipher = new WebCbcCipher(getRandomBytes);
  const nodeCipher = new NodeCbcCipher(getRandomBytes);

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %j',
    async ({ enc, cekLength }) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);

      const webResult = await webCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(webResult.tag).toEqual(nodeResult.tag);
      expect(webResult.iv).toEqual(nodeResult.iv);
      expect(webResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );

  it.each(keyConfigs)(
    'should handle empty plaintext consistently for %j',
    async ({ enc, cekLength }) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);

      const webResult = await webCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(webResult.tag).toEqual(nodeResult.tag);
      expect(webResult.iv).toEqual(nodeResult.iv);
      expect(webResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );

  it.each(keyConfigs)(
    'should handle empty AAD consistently for %j',
    async ({ enc, cekLength }) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);

      const webResult = await webCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(webResult.tag).toEqual(nodeResult.tag);
      expect(webResult.iv).toEqual(nodeResult.iv);
      expect(webResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );
});
