/* The only door between this UI and the device.
 *
 * Inside the Tauri shell, `invoke` reaches the two Rust commands (`device_overview`,
 * `resume_process`). Outside it (a plain browser tab) there is no device to talk to, and this
 * module says so by returning null. It deliberately ships NO sample data: a screen that shows
 * invented frozen processes would be a silent mock, the failure this project exists to avoid.
 * Tests exercise the real code path by providing `window.__TAURI_INTERNALS__`, exactly as the
 * Tauri runtime does.
 */
import { invoke } from '@tauri-apps/api/core'

export function resolveBridge() {
  if (typeof window === 'undefined' || !window.__TAURI_INTERNALS__) return null
  return {
    overview: () => invoke('device_overview'),
    resume: (pid, eventId) => invoke('resume_process', { pid, eventId: eventId || null }),
  }
}
