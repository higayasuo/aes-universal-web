import { AesCipher, RandomBytes } from 'aes-universal';
import { WebCbcCipher } from './WebCbcCipher';
import { WebGcmCipher } from './WebGcmCipher';

/**
 * Web implementation of the AES cipher using Web crypto module.
 *
 * This class extends the base AesCipher class and provides implementations
 * for both CBC and GCM modes using Web crypto functionality.
 */
export class WebAesCipher extends AesCipher<
  WebCbcCipher,
  typeof WebCbcCipher,
  WebGcmCipher,
  typeof WebGcmCipher
> {
  /**
   * Creates a new instance of WebAesCipher.
   *
   * @param randomBytes - Function that generates cryptographically secure random bytes
   *                      Must implement the RandomBytes interface from aes-universal
   */
  constructor(randomBytes: RandomBytes) {
    super({
      cbc: WebCbcCipher,
      gcm: WebGcmCipher,
      randomBytes,
    });
  }
}
