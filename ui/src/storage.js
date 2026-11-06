// Browser privacy contexts (embedded previews, extensions, and strict iframes) may
// deny Web Storage. UI state must remain usable when that happens.
const memoryStore = new Map();

export function readSession(key, fallback = '') {
  try {
    const localVal = window.localStorage?.getItem(key);
    if (localVal !== null && localVal !== undefined) return localVal;
    const sessionVal = window.sessionStorage?.getItem(key);
    if (sessionVal !== null && sessionVal !== undefined) {
      try { window.localStorage?.setItem(key, sessionVal); } catch {}
      return sessionVal;
    }
  } catch {}
  return memoryStore.has(key) ? memoryStore.get(key) : fallback;
}

export function writeSession(key, value) {
  const strVal = String(value);
  memoryStore.set(key, strVal);
  try { window.localStorage?.setItem(key, strVal); } catch {}
  try { window.sessionStorage?.setItem(key, strVal); } catch {}
}

export function removeSession(key) {
  memoryStore.delete(key);
  try { window.localStorage?.removeItem(key); } catch {}
  try { window.sessionStorage?.removeItem(key); } catch {}
}
