import { describe, it, expect, vi } from 'vitest';
import { WebGcmCipher } from '../WebGcmCipher';
import { NodeGcmCipher } from 'aes-universal-node';

const keyConfigs = [
  { enc: 'A128GCM' as const, keyBytes: 16 },
  { enc: 'A192GCM' as const, keyBytes: 24 },
  { enc: 'A256GCM' as const, keyBytes: 32 },
] as const;

describe('GcmCipher.decrypt', () => {
  const getRandomBytes = vi
    .fn()
    .mockImplementation((size) => new Uint8Array(size).fill(0x42));
  const webCipher = new WebGcmCipher(getRandomBytes);
  const nodeCipher = new NodeGcmCipher(getRandomBytes);

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %j',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
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
      const cek = new Uint8Array(keyBytes).fill(0xaa);
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
      const cek = new Uint8Array(keyBytes).fill(0xaa);
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
      const cek = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const invalidTag = new Uint8Array(16).fill(0xff);

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
