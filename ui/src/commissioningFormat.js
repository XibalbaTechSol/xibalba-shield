/* Formatting for the commissioning ladder.
 *
 * Kept out of the component file so the component module only exports components (React fast
 * refresh) and so the rule is stated once: a missing measurement is "Not measured", never 0.
 * A zero would read as "fast" or "perfect"; absence of data is neither.
 */

export const NOT_MEASURED = 'Not measured'

const missing = (value) => value === null || value === undefined || Number.isNaN(Number(value))

/** Milliseconds with sensible precision; null/undefined -> "Not measured", never "0 ms". */
export function formatMs(value) {
  if (missing(value)) return NOT_MEASURED
  const n = Number(value)
  return `${n < 10 ? n.toFixed(2) : n.toFixed(1)} ms`
}

/** A 0..1 ratio as a percentage; null/undefined -> "Not measured". */
export function formatRate(value) {
  if (missing(value)) return NOT_MEASURED
  return `${(Number(value) * 100).toFixed(1)}%`
}

/** An integer count; null/undefined (endpoint gave nothing) -> "Not measured". */
export function formatCount(value) {
  if (value === null || value === undefined) return NOT_MEASURED
  return String(value)
}
