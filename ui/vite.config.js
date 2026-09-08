import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { resolve } from 'node:path'

function devAdminToken() {
  if (process.env.SHIELD_DEV_ADMIN_TOKEN) return process.env.SHIELD_DEV_ADMIN_TOKEN.trim()
  const tenant = process.env.SHIELD_DEV_TENANT || 'tenant-a'
  try { return readFileSync(process.env.SHIELD_DEV_ADMIN_TOKEN_FILE || resolve(homedir(), `.xibalba-shield/${tenant}-admin-token`), 'utf8').trim() } catch { return '' }
}

function shieldLocalSession() {
  return {
    name: 'shield-local-session',
    configureServer(server) {
      server.middlewares.use('/__shield_dev/session', (request, response) => {
        if (request.method !== 'POST') { response.statusCode = 405; return response.end() }
        const token = devAdminToken()
        response.setHeader('Content-Type', 'application/json')
        response.setHeader('Cache-Control', 'no-store')
        if (!token) { response.statusCode = 503; return response.end(JSON.stringify({ error: 'Local admin token is not available. Start the backend once to create it.' })) }
        response.end(JSON.stringify({ tenant_id: process.env.SHIELD_DEV_TENANT || 'tenant-a', dev_proxy: true }))
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), shieldLocalSession()],
  server: {
    proxy: {
      '/api': {
        target: process.env.SHIELD_DEV_BACKEND_URL || 'http://127.0.0.1:8421',
        changeOrigin: false,
        configure(proxy) {
          proxy.on('proxyReq', (proxyRequest, request) => {
            if (request.headers['x-shield-dev-auth'] === '1') {
              const token = devAdminToken()
              if (token) proxyRequest.setHeader('Authorization', `Bearer ${token}`)
              proxyRequest.removeHeader('x-shield-dev-auth')
            }
          })
        },
      },
    },
  },
})
