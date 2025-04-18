import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
  build: {
    lib: {
      entry: 'src/index.ts',
      name: 'ExpoAesUniversalWeb',
      formats: ['es', 'cjs'],
      fileName: (format) => `index.${format === 'es' ? 'mjs' : 'cjs'}`,
    },
    rollupOptions: {
      external: ['expo-aes-universal', 'expo-crypto-universal'],
    },
  },
  plugins: [
    dts({
      rollupTypes: true,
    }),
  ],
});
