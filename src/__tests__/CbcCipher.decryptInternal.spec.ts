import { describe, it, expect } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { NodeCbcCipher } from 'aes-universal-node';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBytes: 16 },
  { enc: 'A192CBC-HS384', keyBytes: 24 },
  { enc: 'A256CBC-HS512', keyBytes: 32 },
] as const;

const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
};

describe('CbcCipher.decryptInternal', () => {
  const webCipher = new WebCbcCipher();
  const nodeCipher = new NodeCbcCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)(
      'should produce the same result across all implementations for $enc',
      async ({ keyBytes }) => {
        const encRawKey = randomBytes(keyBytes);
        const iv = randomBytes(16);
        const plaintext = new Uint8Array([1, 2, 3]);

        // Encrypt using nodeCipher first
        const ciphertext = await nodeCipher.encryptInternal({
          encRawKey,
          iv,
          plaintext,
        });

        const webResult = await webCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
        });
        const nodeResult = await nodeCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
        });

        expect(webResult).toEqual(nodeResult);
        expect(webResult).toEqual(plaintext);
      },
    );
  });

  describe('should handle empty ciphertext consistently', () => {
    it.each(keyConfigs)(
      'should handle empty ciphertext consistently for $enc',
      async ({ keyBytes }) => {
        const encRawKey = randomBytes(keyBytes);
        const iv = randomBytes(16);
        const plaintext = new Uint8Array(0);

        // Encrypt using nodeCipher first
        const ciphertext = await nodeCipher.encryptInternal({
          encRawKey,
          iv,
          plaintext,
        });

        const webResult = await webCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
        });
        const nodeResult = await nodeCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
        });

        expect(webResult).toEqual(nodeResult);
        expect(webResult).toEqual(plaintext);
      },
    );
  });

  describe('should handle block-aligned ciphertext with PKCS#7 padding consistently', () => {
    it.each(keyConfigs)(
      'should handle block-aligned ciphertext with PKCS#7 padding consistently for $enc',
      async ({ keyBytes }) => {
        const encRawKey = randomBytes(keyBytes);
        const iv = randomBytes(16);
        const plaintext = new Uint8Array(1024).fill(0xaa);

        // Encrypt using nodeCipher first
        const ciphertext = await nodeCipher.encryptInternal({
          encRawKey,
          iv,
          plaintext,
        });

        const webResult = await webCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
        });
        const nodeResult = await nodeCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
        });

        expect(webResult).toEqual(nodeResult);
        expect(webResult).toEqual(plaintext);
      },
    );
  });
});
