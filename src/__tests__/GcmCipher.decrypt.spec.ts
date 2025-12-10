import { describe, it, expect } from 'vitest';
import { WebGcmCipher } from '../WebGcmCipher';
import { NodeGcmCipher } from 'aes-universal-node';

const keyConfigs = [
  { enc: 'A128GCM', keyBytes: 16 },
  { enc: 'A192GCM', keyBytes: 24 },
  { enc: 'A256GCM', keyBytes: 32 },
] as const;

const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
};

describe('GcmCipher.decrypt', () => {
  const webCipher = new WebGcmCipher();
  const nodeCipher = new NodeGcmCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)(
      'should produce the same result across all implementations for $enc',
      async ({ enc }) => {
        const iv = randomBytes(webCipher.getIvByteLength(enc));
        const cek = randomBytes(webCipher.getCekByteLength(enc));
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);
        const { ciphertext, tag } = await nodeCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
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
  });

  describe('should handle empty ciphertext consistently', () => {
    it.each(keyConfigs)(
      'should handle empty ciphertext consistently for $enc',
      async ({ enc }) => {
        const iv = randomBytes(webCipher.getIvByteLength(enc));
        const cek = randomBytes(webCipher.getCekByteLength(enc));
        const plaintext = new Uint8Array(0);
        const aad = new Uint8Array([4, 5, 6]);
        const { ciphertext, tag } = await nodeCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
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
  });

  describe('should handle empty AAD consistently', () => {
    it.each(keyConfigs)(
      'should handle empty AAD consistently for $enc',
      async ({ enc }) => {
        const iv = randomBytes(webCipher.getIvByteLength(enc));
        const cek = randomBytes(webCipher.getCekByteLength(enc));
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array(0);
        const { ciphertext, tag } = await nodeCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
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
  });

  describe('should reject invalid tag', () => {
    it.each(keyConfigs)(
      'should reject invalid tag for $enc',
      async ({ enc }) => {
        const iv = randomBytes(webCipher.getIvByteLength(enc));
        const cek = randomBytes(webCipher.getCekByteLength(enc));
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);
        const { ciphertext } = await nodeCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
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
});
