import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import path from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: 'src/index.ts',
      name: 'ExpoAesUniversalWeb',
      formats: ['es', 'cjs'],
      fileName: (format) => `index.${format === 'es' ? 'js' : 'cjs'}`,
    },
    rollupOptions: {
      external: ['expo-aes-universal', 'expo-crypto-universal'],
    },
  },
  resolve: {
    alias: {
      'expo-aes-universal': path.resolve(__dirname, '../expo-aes-universal'),
    },
  },
  plugins: [
    dts({
      rollupTypes: true,
    }),
  ],
});
