import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:5867',
      '/oauth': 'http://localhost:5867',
      '/.well-known': 'http://localhost:5867',
      '/css': 'http://localhost:5867',
      '/fonts': 'http://localhost:5867',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
