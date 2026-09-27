import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { resolve } from 'node:path'

function devAdminToken() {
  if (process.env.SHIELD_DEV_ADMIN_TOKEN) return process.env.SHIELD_DEV_ADMIN_TOKEN.trim()
  const tenant = process.env.SHIELD_DEV_TENANT || 'tenant-a'
  try { return readFileSync(process.env.SHIELD_DEV_ADMIN_TOKEN_FILE || resolve(homedir(), `.xibalba-shield/${tenant}-admin-token`), 'utf8').trim() } catch { return '' }
}

// Keep Cortex's operator token server-side for local development.  Shield's
// browser must use the same namespace authority as Cortex without receiving a
// bearer token or depending on a cross-app cookie.
function cortexDevToken() {
  const cortexHome = process.env.CORTEX_HOME || resolve(homedir(), '.hermes/xibalba-cortex')
  const tokenFile = process.env.CORTEX_DEV_TOKEN_FILE || resolve(cortexHome, '.viewer-dev.token')
  try { return existsSync(tokenFile) ? readFileSync(tokenFile, 'utf8').trim() : '' } catch { return '' }
}

const devAuthDisabled = ['1', 'true', 'yes', 'on'].includes(String(process.env.SHIELD_DEV_DISABLE_AUTH || '').trim().toLowerCase())

function shieldLocalSession() {
  return {
    name: 'shield-local-session',
    configureServer(server) {
      server.middlewares.use('/__shield_dev/session', (request, response) => {
        if (request.method !== 'POST') { response.statusCode = 405; return response.end() }
        const token = devAdminToken()
        response.setHeader('Content-Type', 'application/json')
        response.setHeader('Cache-Control', 'no-store')
        if (!token && !devAuthDisabled) { response.statusCode = 503; return response.end(JSON.stringify({ error: 'Local admin token is not available. Start the backend once to create it, or explicitly set SHIELD_DEV_DISABLE_AUTH=true for loopback development.' })) }
        response.end(JSON.stringify({ tenant_id: process.env.SHIELD_DEV_TENANT || 'tenant-a', dev_proxy: true, auth_disabled: devAuthDisabled }))
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
        // The legacy Shield control plane on 8765 and the retired validation
        // backend on 8421 are intentionally offline. Dedicated local UI work
        // uses the current backend on 8435 instead.
        target: process.env.SHIELD_DEV_BACKEND_URL || 'http://127.0.0.1:8435',
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
      '/cortex-api': {
        target: process.env.CORTEX_LOCAL_API_URL || 'http://127.0.0.1:8420',
        changeOrigin: false,
        rewrite: (path) => path.replace(/^\/cortex-api/, ''),
        configure(proxy) {
          const token = cortexDevToken()
          if (token) proxy.on('proxyReq', (proxyRequest) => proxyRequest.setHeader('Authorization', `Bearer ${token}`))
        },
      },
    },
  },
})
