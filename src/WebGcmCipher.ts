import {
  AbstractGcmCipher,
  GcmDecryptInternalParams,
  GcmEncryptInternalParams,
  GcmEncryptInternalResult,
} from 'aes-universal';
import { concatUint8Arrays } from 'u8a-utils';

/**
 * Class representing a Web-based GCM cipher.
 * Extends the AbstractGcmCipher class to provide specific implementations
 * for web environments using the SubtleCrypto API.
 */
export class WebGcmCipher extends AbstractGcmCipher {
  /**
   * Performs the internal encryption process using the AES-GCM algorithm.
   * @param args - The arguments required for encryption, including the raw encryption key, IV, plaintext, and additional authenticated data.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  encryptInternal = async ({
    encRawKey,
    iv,
    plaintext,
    aad,
  }: GcmEncryptInternalParams): Promise<GcmEncryptInternalResult> => {
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey as BufferSource,
      'AES-GCM',
      false,
      ['encrypt'],
    );

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          additionalData: aad as BufferSource,
          iv: iv as BufferSource,
          name: 'AES-GCM',
          tagLength: 128,
        },
        encKey,
        plaintext as BufferSource,
      ),
    );

    return {
      ciphertext: encrypted.slice(0, -16),
      tag: encrypted.slice(-16),
    };
  };

  /**
   * Performs the internal decryption process using the AES-GCM algorithm.
   * @param args - The arguments required for decryption, including the raw encryption key, IV, ciphertext, and additional authenticated data.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  decryptInternal = async ({
    encRawKey,
    iv,
    ciphertext,
    tag,
    aad,
  }: GcmDecryptInternalParams): Promise<Uint8Array> => {
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey as BufferSource,
      'AES-GCM',
      false,
      ['decrypt'],
    );

    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          additionalData: aad as BufferSource,
          iv: iv as BufferSource,
          name: 'AES-GCM',
          tagLength: 128,
        },
        encKey,
        concatUint8Arrays(ciphertext, tag) as BufferSource,
      ),
    );
  };
}
