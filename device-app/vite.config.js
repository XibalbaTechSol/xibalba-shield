import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Tauri expects a fixed dev port (tauri.conf.json devUrl) and must not lose the Rust build output
// to Vite clearing the screen.
export default defineConfig({
  base: './',
  plugins: [react()],
  clearScreen: false,
  server: { port: 5174, strictPort: true },
})
