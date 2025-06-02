import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
  build: {
    lib: {
      entry: 'src/index.ts',
      name: 'AesUniversalWeb',
      formats: ['es', 'cjs'],
      fileName: (format) => `index.${format === 'es' ? 'mjs' : 'cjs'}`,
    },
    rollupOptions: {
      external: ['aes-universal', '@higayasuo/u8a-utils'],
    },
  },
  plugins: [
    dts({
      rollupTypes: true,
    }),
  ],
});
