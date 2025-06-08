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

```typescript
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';

const { getRandomBytes } = webCryptoModule;

// Create cipher instance
const cipher = new WebAesCipher(getRandomBytes);

// Define plaintext and AAD
const plaintext = new Uint8Array([1, 2, 3, 4]);
const aad = new Uint8Array([5, 6, 7, 8]);
```

## AES-128

### CBC Mode (A128CBC-HS256)

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A128CBC-HS256: 32 bytes (16 bytes for encryption + 16 bytes for MAC)

```typescript
const enc = 'A128CBC-HS256' as const;

// Generate CEK for AES-128-CBC-HS256
const cek = await cipher.generateCek(enc);

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc, // AES-128 in CBC mode with HMAC-SHA-256
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
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

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A128GCM: 16 bytes

```typescript
const enc = 'A128GCM' as const;

// Generate CEK for AES-128-GCM
const cek = await cipher.generateCek(enc);

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc, // AES-128 in GCM mode
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc,
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

## AES-192

### CBC Mode (A192CBC-HS384)

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A192CBC-HS384: 48 bytes (24 bytes for encryption + 24 bytes for MAC)

```typescript
const enc = 'A192CBC-HS384' as const;

// Generate CEK for AES-192-CBC-HS384
const cek = await cipher.generateCek(enc);

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc, // AES-192 in CBC mode with HMAC-SHA-384
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc,
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A192GCM)

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A192GCM: 24 bytes

```typescript
const enc = 'A192GCM' as const;

// Generate CEK for AES-192-GCM
const cek = await cipher.generateCek(enc);

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc, // AES-192 in GCM mode
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc,
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

## AES-256

### CBC Mode (A256CBC-HS512)

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A256CBC-HS512: 64 bytes (32 bytes for encryption + 32 bytes for MAC)

```typescript
const enc = 'A256CBC-HS512' as const;

// Generate CEK for AES-256-CBC-HS512
const cek = await cipher.generateCek(enc);

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc, // AES-256 in CBC mode with HMAC-SHA-512
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc,
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A256GCM)

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A256GCM: 32 bytes

```typescript
const enc = 'A256GCM' as const;

// Generate CEK for AES-256-GCM
const cek = await cipher.generateCek(enc);

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc, // AES-256 in GCM mode
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
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
- `npm run test:coverage` - Run tests with coverage
- `npm run typecheck` - Run TypeScript type checking

## License

MIT
