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

describe('GcmCipher.encrypt', () => {
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

        const webResult = await webCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
        });
        const nodeResult = await nodeCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
        });

        expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
        expect(webResult.tag).toEqual(nodeResult.tag);
      },
    );
  });

  describe('should handle empty plaintext consistently', () => {
    it.each(keyConfigs)(
      'should handle empty plaintext consistently for $enc',
      async ({ enc }) => {
        const iv = randomBytes(webCipher.getIvByteLength(enc));
        const cek = randomBytes(webCipher.getCekByteLength(enc));
        const plaintext = new Uint8Array(0);
        const aad = new Uint8Array([4, 5, 6]);

        const webResult = await webCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
        });
        const nodeResult = await nodeCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
        });

        expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
        expect(webResult.tag).toEqual(nodeResult.tag);
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

        const webResult = await webCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
        });
        const nodeResult = await nodeCipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
          iv,
        });

        expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
        expect(webResult.tag).toEqual(nodeResult.tag);
      },
    );
  });
});
