import {
  AbstractCbcCipher,
  CbcDecryptInternalParams,
  CbcEncryptInternalParams,
  GenerateTagParams,
} from 'aes-universal';

/**
 * Class representing a Web-based CBC mode cipher.
 * Extends the AbstractCbcCipher class to provide specific implementations
 * for web environments using the SubtleCrypto API.
 */
export class WebCbcCipher extends AbstractCbcCipher {
  /**
   * Performs the internal encryption process using the AES-CBC algorithm.
   * @param args - The arguments required for encryption, including the raw encryption key, IV, and plaintext.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  encryptInternal = async ({
    encRawKey,
    iv,
    plaintext,
  }: CbcEncryptInternalParams): Promise<Uint8Array> => {
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey as BufferSource,
      'AES-CBC',
      false,
      ['encrypt'],
    );

    return new Uint8Array(
      await crypto.subtle.encrypt(
        {
          iv: iv as BufferSource,
          name: 'AES-CBC',
        },
        encKey,
        plaintext as BufferSource,
      ),
    );
  };

  /**
   * Performs the internal decryption process using the AES-CBC algorithm.
   * @param args - The arguments required for decryption, including the raw encryption key, IV, and ciphertext.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  decryptInternal = async ({
    encRawKey,
    iv,
    ciphertext,
  }: CbcDecryptInternalParams): Promise<Uint8Array> => {
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey as BufferSource,
      'AES-CBC',
      false,
      ['decrypt'],
    );

    return new Uint8Array(
      await crypto.subtle.decrypt(
        { iv: iv as BufferSource, name: 'AES-CBC' },
        encKey,
        ciphertext as BufferSource,
      ),
    );
  };

  /**
   * Generates a tag using the HMAC algorithm.
   * @param args - The arguments required for tag generation, including the raw MAC key, MAC data, and the length of the key in bits.
   * @returns A promise that resolves to the generated tag as a Uint8Array.
   */
  generateTag = async ({
    macRawKey,
    macData,
    keyBitLength,
  }: GenerateTagParams): Promise<Uint8Array> => {
    const macKey = await crypto.subtle.importKey(
      'raw',
      macRawKey as BufferSource,
      {
        hash: `SHA-${keyBitLength << 1}`,
        name: 'HMAC',
      },
      false,
      ['sign'],
    );

    return new Uint8Array(
      (await crypto.subtle.sign('HMAC', macKey, macData as BufferSource)).slice(
        0,
        keyBitLength >> 3,
      ),
    );
  };
}
