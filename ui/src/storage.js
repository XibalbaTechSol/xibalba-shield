// Browser privacy contexts (embedded previews, extensions, and strict iframes) may
// deny Web Storage. UI state must remain usable when that happens.
export function readSession(key, fallback = '') {
  try { return sessionStorage.getItem(key) ?? fallback } catch { return fallback }
}
export function writeSession(key, value) { try { sessionStorage.setItem(key, value) } catch {} }
export function removeSession(key) { try { sessionStorage.removeItem(key) } catch {} }
