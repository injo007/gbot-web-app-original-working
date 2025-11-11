import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react({
      // Enable emotion's JSX pragma
      jsxImportSource: '@emotion/react',
      // Enable Fast Refresh
      fastRefresh: true,
    }),
  ],
  resolve: {
    alias: {
      // Add path aliases for cleaner imports
      '@': resolve(__dirname, './src'),
      '@components': resolve(__dirname, './src/components'),
      '@pages': resolve(__dirname, './src/pages'),
      '@store': resolve(__dirname, './src/store'),
      '@theme': resolve(__dirname, './src/theme'),
      '@api': resolve(__dirname, './src/api'),
    },
  },
  server: {
    // Development server configuration
    port: 3000,
    strictPort: true,
    proxy: {
      // Proxy API requests to Flask backend
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    // Production build configuration
    outDir: 'dist',
    sourcemap: true,
    // Optimize chunks
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom', '@reduxjs/toolkit', '@emotion/react'],
          ui: ['@emotion/styled', 'framer-motion'],
        },
      },
    },
    // Transpilation targets
    target: 'es2015',
  },
  optimizeDeps: {
    // Dependencies to pre-bundle
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      '@reduxjs/toolkit',
      '@emotion/react',
      '@emotion/styled',
      'framer-motion',
    ],
  },
});
