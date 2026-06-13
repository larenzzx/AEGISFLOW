import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api/virustotal': {
        target: 'https://www.virustotal.com/api/v3',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/virustotal/, '')
      },
      '/api/abuseipdb': {
        target: 'https://api.abuseipdb.com/api/v2',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/abuseipdb/, '')
      },
      '/api/alienvault': {
        target: 'https://otx.alienvault.com/api/v1',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/alienvault/, '')
      }
    }
  }
})
