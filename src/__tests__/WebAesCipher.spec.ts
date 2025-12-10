import { describe, it, expect } from 'vitest';
import { WebAesCipher } from '../WebAesCipher';
import { NodeAesCipher } from 'aes-universal-node';
import { WebCbcCipher } from '../WebCbcCipher';
import { WebGcmCipher } from '../WebGcmCipher';

const cbcConfigs = [
  { enc: 'A128CBC-HS256', keyBytes: 16 },
  { enc: 'A192CBC-HS384', keyBytes: 24 },
  { enc: 'A256CBC-HS512', keyBytes: 32 },
] as const;

const gcmConfigs = [
  { enc: 'A128GCM', keyBytes: 16 },
  { enc: 'A192GCM', keyBytes: 24 },
  { enc: 'A256GCM', keyBytes: 32 },
] as const;

const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
};

describe('WebAesCipher', () => {
  const webCipher = new WebAesCipher();
  const nodeCipher = new NodeAesCipher();

  it('should initialize with WebCbcCipher and WebGcmCipher', () => {
    expect(webCipher).toBeInstanceOf(WebAesCipher);
    expect(webCipher['cbc']).toBeInstanceOf(WebCbcCipher);
    expect(webCipher['gcm']).toBeInstanceOf(WebGcmCipher);
  });

  describe('CBC mode', () => {
    describe('encrypt', () => {
      describe('should produce the same result across all implementations', () => {
        it.each(cbcConfigs)(
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
        it.each(cbcConfigs)(
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
        it.each(cbcConfigs)(
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

    describe('decrypt', () => {
      describe('should produce the same result across all implementations', () => {
        it.each(cbcConfigs)(
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
        it.each(cbcConfigs)(
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
        it.each(cbcConfigs)(
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
    });
  });

  describe('GCM mode', () => {
    describe('encrypt', () => {
      describe('should produce the same result across all implementations', () => {
        it.each(gcmConfigs)(
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
        it.each(gcmConfigs)(
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
        it.each(gcmConfigs)(
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

    describe('decrypt', () => {
      describe('should produce the same result across all implementations', () => {
        it.each(gcmConfigs)(
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
        it.each(gcmConfigs)(
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
        it.each(gcmConfigs)(
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
    });
  });
});
