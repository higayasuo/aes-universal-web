import { describe, it, expect, vi } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { NodeCbcCipher } from 'aes-universal-node';

const keyConfigs = [
  { enc: 'A128CBC-HS256' as const, keyBitLength: 128 },
  { enc: 'A192CBC-HS384' as const, keyBitLength: 192 },
  { enc: 'A256CBC-HS512' as const, keyBitLength: 256 },
] as const;

describe('CbcCipher.generateTag', () => {
  const getRandomBytes = vi
    .fn()
    .mockImplementation((size) => new Uint8Array(size).fill(0x42));
  const webCipher = new WebCbcCipher(getRandomBytes);
  const nodeCipher = new NodeCbcCipher(getRandomBytes);

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %j',
    async ({ keyBitLength }) => {
      const macRawKey = new Uint8Array(keyBitLength / 8).fill(0xaa);
      const macData = new Uint8Array([1, 2, 3]);

      const webResult = await webCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });

      expect(webResult).toEqual(nodeResult);
    },
  );

  it.each(keyConfigs)(
    'should handle key size %j consistently',
    async ({ keyBitLength }) => {
      const macRawKey = new Uint8Array(keyBitLength / 8).fill(0xaa);
      const macData = new Uint8Array([1, 2, 3]);

      const webResult = await webCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });

      expect(webResult).toEqual(nodeResult);
    },
  );

  it.each(keyConfigs)(
    'should handle empty macData consistently for %j',
    async ({ keyBitLength }) => {
      const macRawKey = new Uint8Array(keyBitLength / 8).fill(0xaa);
      const macData = new Uint8Array(0);

      const webResult = await webCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });

      expect(webResult).toEqual(nodeResult);
    },
  );
});
