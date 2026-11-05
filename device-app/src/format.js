/* Presentation helpers. A freeze's state is CHECKED against the operating system by the Rust
 * core, so the labels say what was checked, not what the log claims. */

export const STATE_LABEL = {
  stopped: 'Stopped (confirmed)',
  running: 'Running (log says frozen)',
  gone: 'Exited',
  unknown: 'Unverified',
}

/** Resume is offered only where it can mean something: the OS shows it stopped, or we cannot
 *  check. A running or exited process has nothing to resume. */
export function canResume(state) {
  return state === 'stopped' || state === 'unknown'
}

export function formatMs(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return 'Not measured'
  const n = Number(value)
  return `${n < 10 ? n.toFixed(2) : n.toFixed(1)} ms`
}

export const EXPORT_LABEL = {
  ok: 'Exported',
  telemetry_only: 'Telemetry only',
  failed: 'Export failed',
  not_attempted: 'Not exported',
}
