# expo-aes-universal-web

AES encryption/decryption module for Expo and web applications.

## Installation

```bash
npm install expo-aes-universal-web
```

## Usage

```typescript
import { encrypt, decrypt } from 'expo-aes-universal-web';

const options = {
  iv: 'your-iv-here',
  key: 'your-key-here',
};

// Encrypt data
const encrypted = await encrypt('your data', options);

// Decrypt data
const decrypted = await decrypt(encrypted, options);
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
- `npm run lint` - Run ESLint

## License

MIT
