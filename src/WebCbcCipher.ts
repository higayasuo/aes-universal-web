import {
  AbstractCbcCipher,
  CbcDecryptInternalArgs,
  CbcEncryptInternalArgs,
  GenerateTagArgs,
  RandomBytes,
} from 'aes-universal';

/**
 * Class representing a Web-based CBC mode cipher.
 * Extends the AbstractCbcCipher class to provide specific implementations
 * for web environments using the SubtleCrypto API.
 */
export class WebCbcCipher extends AbstractCbcCipher {
  /**
   * Constructs a WebCbcCipher instance.
   * @param randomBytes - The random bytes to be used for cryptographic operations.
   */
  constructor(randomBytes: RandomBytes) {
    super(randomBytes);
  }

  /**
   * Performs the internal encryption process using the AES-CBC algorithm.
   * @param args - The arguments required for encryption, including the raw encryption key, IV, and plaintext.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  encryptInternal = async ({
    encRawKey,
    iv,
    plaintext,
  }: CbcEncryptInternalArgs): Promise<Uint8Array> => {
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey,
      'AES-CBC',
      false,
      ['encrypt'],
    );

    return new Uint8Array(
      await crypto.subtle.encrypt(
        {
          iv,
          name: 'AES-CBC',
        },
        encKey,
        plaintext,
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
  }: CbcDecryptInternalArgs): Promise<Uint8Array> => {
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey,
      'AES-CBC',
      false,
      ['decrypt'],
    );

    return new Uint8Array(
      await crypto.subtle.decrypt({ iv, name: 'AES-CBC' }, encKey, ciphertext),
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
  }: GenerateTagArgs): Promise<Uint8Array> => {
    const macKey = await crypto.subtle.importKey(
      'raw',
      macRawKey,
      {
        hash: `SHA-${keyBitLength << 1}`,
        name: 'HMAC',
      },
      false,
      ['sign'],
    );

    return new Uint8Array(
      (await crypto.subtle.sign('HMAC', macKey, macData)).slice(
        0,
        keyBitLength >> 3,
      ),
    );
  };
}
