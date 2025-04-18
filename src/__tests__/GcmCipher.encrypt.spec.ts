import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebGcmCipher } from '../WebGcmCipher';
import { NodeGcmCipher } from 'expo-aes-universal-node';
import { CryptoModule } from 'expo-crypto-universal';

const keyConfigs = [
  { enc: 'A128GCM' as const, keyBytes: 16 },
  { enc: 'A192GCM' as const, keyBytes: 24 },
  { enc: 'A256GCM' as const, keyBytes: 32 },
] as const;

describe('GcmCipher.encrypt', () => {
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
      const cek = new Uint8Array(keyBytes).fill(0xaa);
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
    },
  );

  it.each(keyConfigs)(
    'should handle empty plaintext consistently for %j',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
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
    },
  );

  it.each(keyConfigs)(
    'should handle empty AAD consistently for %j',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
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
    },
  );
});
