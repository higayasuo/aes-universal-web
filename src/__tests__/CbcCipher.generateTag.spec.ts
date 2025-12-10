import { describe, it, expect } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { NodeCbcCipher } from 'aes-universal-node';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBitLength: 128 },
  { enc: 'A192CBC-HS384', keyBitLength: 192 },
  { enc: 'A256CBC-HS512', keyBitLength: 256 },
] as const;

const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
};

describe('CbcCipher.generateTag', () => {
  const webCipher = new WebCbcCipher();
  const nodeCipher = new NodeCbcCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)(
      'should produce the same result across all implementations for $enc',
      async ({ keyBitLength }) => {
        const macRawKey = randomBytes(keyBitLength / 8);
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
  });

  describe('should handle key size consistently', () => {
    it.each(keyConfigs)(
      'should handle key size consistently for $enc',
      async ({ keyBitLength }) => {
        const macRawKey = randomBytes(keyBitLength / 8);
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
  });

  describe('should handle empty macData consistently', () => {
    it.each(keyConfigs)(
      'should handle empty macData consistently for $enc',
      async ({ keyBitLength }) => {
        const macRawKey = randomBytes(keyBitLength / 8);
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
});
