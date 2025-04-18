import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebGcmCipher } from '../WebGcmCipher';
import { NodeGcmCipher } from 'expo-aes-universal-node';
import { CryptoModule } from 'expo-crypto-universal';

const keyConfigs = [
  { enc: 'A128GCM' as const, keyBytes: 16 },
  { enc: 'A192GCM' as const, keyBytes: 24 },
  { enc: 'A256GCM' as const, keyBytes: 32 },
] as const;

describe('GcmCipher.decryptInternal', () => {
  let mockCryptoModule: CryptoModule;
  let webCipher: WebGcmCipher;
  let nodeCipher: NodeGcmCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
    } as unknown as CryptoModule;
    webCipher = new WebGcmCipher(mockCryptoModule);
    nodeCipher = new NodeGcmCipher(mockCryptoModule);
  });

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %j',
    async ({ enc, keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek: encRawKey,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle empty ciphertext consistently for %j',
    async ({ enc, keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek: encRawKey,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle empty AAD consistently for %j',
    async ({ enc, keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek: encRawKey,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should reject invalid tag for %j',
    async ({ enc, keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, iv } = await nodeCipher.encrypt({
        enc,
        cek: encRawKey,
        plaintext,
        aad,
      });
      const invalidTag = new Uint8Array(16).fill(0xff);

      await expect(
        webCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
          tag: invalidTag,
          aad,
        }),
      ).rejects.toThrow();
      await expect(
        nodeCipher.decryptInternal({
          encRawKey,
          iv,
          ciphertext,
          tag: invalidTag,
          aad,
        }),
      ).rejects.toThrow();
    },
  );
});
