import { AesCipher } from 'aes-universal';
import { WebCbcCipher } from './WebCbcCipher';
import { WebGcmCipher } from './WebGcmCipher';

/**
 * Web implementation of the AES cipher using Web crypto module.
 *
 * This class extends the base AesCipher class and provides implementations
 * for both CBC and GCM modes using Web crypto functionality.
 */
export class WebAesCipher extends AesCipher {
  /**
   * Constructs a new instance of the WebAesCipher.
   *
   * Initializes the AES cipher with WebCrypto-based CBC and GCM cipher implementations.
   */
  constructor() {
    super({
      cbc: new WebCbcCipher(),
      gcm: new WebGcmCipher(),
    });
  }
}

/**
 * A singleton instance of {@link WebAesCipher}, providing WebCrypto-based AES encryption and decryption.
 */
export const webAesCipher = new WebAesCipher();
