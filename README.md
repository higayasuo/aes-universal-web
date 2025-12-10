# aes-universal-web

Web implementation of aes-universal for Expo applications.

## Installation

```bash
npm install aes-universal-web
```

## Peer Dependencies

This package requires the following peer dependencies:

- `aes-universal`: The base package that defines the interfaces
- `u8a-utils`: Utility functions for Uint8Array operations

```bash
npm install aes-universal u8a-utils
```

## Usage

`WebAesCipher` provides AES encryption and decryption using Web Crypto API, supporting both CBC and GCM modes.

### CBC Mode

CBC mode supports the following encryption algorithms:

- `A128CBC-HS256`: 32 bytes CEK (16 bytes for encryption + 16 bytes for MAC)
- `A192CBC-HS384`: 48 bytes CEK (24 bytes for encryption + 24 bytes for MAC)
- `A256CBC-HS512`: 64 bytes CEK (32 bytes for encryption + 32 bytes for MAC)

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key.

### GCM Mode

GCM mode supports the following encryption algorithms:

- `A128GCM`: 16 bytes CEK
- `A192GCM`: 24 bytes CEK
- `A256GCM`: 32 bytes CEK

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption.

## Example: AES-128

### CBC Mode (A128CBC-HS256)

```typescript
import { webAesCipher } from 'aes-universal-web';

const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
};

const enc = 'A128CBC-HS256';
const plaintext = new Uint8Array([1, 2, 3, 4]);
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate CEK and IV
const cek = randomBytes(webAesCipher.getCekByteLength(enc));
const iv = randomBytes(webAesCipher.getIvByteLength(enc));

// Encrypt data
const { ciphertext, tag } = await webAesCipher.encrypt({
  enc, // AES-128 in CBC mode with HMAC-SHA-256
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
  iv,
});

// Decrypt data
const decrypted = await webAesCipher.decrypt({
  enc,
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A128GCM)

```typescript
import { webAesCipher } from 'aes-universal-web';

const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
};

const enc = 'A128GCM';
const plaintext = new Uint8Array([1, 2, 3, 4]);
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate CEK and IV
const cek = randomBytes(webAesCipher.getCekByteLength(enc));
const iv = randomBytes(webAesCipher.getIvByteLength(enc));

// Encrypt data
const { ciphertext, tag } = await webAesCipher.encrypt({
  enc, // AES-128 in GCM mode
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
  iv,
});

// Decrypt data
const decrypted = await webAesCipher.decrypt({
  enc,
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

## Development

### Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

### Scripts

- `npm run build` - Build the library
- `npm test` - Run tests

## License

MIT
