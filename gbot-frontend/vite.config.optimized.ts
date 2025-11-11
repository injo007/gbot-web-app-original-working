import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

// https://vitejs.dev/config/
// Memory-optimized configuration for production builds
export default defineConfig({
  plugins: [
    react({
      // Enable emotion's JSX pragma
      jsxImportSource: '@emotion/react',
      // Fast refresh is enabled by default in development
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
  // Memory-optimized build configuration
  build: {
    outDir: 'dist',
    // Disable sourcemaps for production (reduces memory usage)
    sourcemap: process.env.NODE_ENV !== 'production',
    // Use smaller chunks for better memory efficiency
    chunkSizeWarningLimit: 800,
    // Reduce memory usage during build
    rollupOptions: {
      output: {
        // Split chunks more efficiently but with simpler rules
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            if (id.includes('redux') || id.includes('toolkit')) return 'vendor-redux';
            if (id.includes('emotion') || id.includes('framer')) return 'vendor-ui';
            return 'vendor'; // All other dependencies
          }
        },
        // Optimize asset file naming
        assetFileNames: 'assets/[name]-[hash:8][extname]',
        chunkFileNames: 'chunks/[name]-[hash:8].js',
        entryFileNames: 'entries/[name]-[hash:8].js',
      },
    },
    // Transpilation targets - more conservative settings
    target: 'es2015',
    // Minification options - reduce memory by sacrificing compression
    minify: 'esbuild', // Use faster and less memory-intensive minifier
    assetsInlineLimit: 4096, // Lower the inline limit to reduce memory usage
    cssCodeSplit: true, // Split CSS to reduce memory
    cssMinify: true, // Minify CSS
    reportCompressedSize: false, // Skip reporting compressed size to save memory
    emptyOutDir: true, // Clean output directory
  },
  optimizeDeps: {
    // Reduce number of dependencies to pre-bundle to save memory
    include: [
      'react', 
      'react-dom',
      'react-router-dom'
    ],
    // Exclude large dependencies that don't need pre-optimization
    exclude: [
      '@emotion/styled',
      'framer-motion'
    ],
  },
});
