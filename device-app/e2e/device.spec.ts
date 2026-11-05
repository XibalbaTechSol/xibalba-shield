import { test, expect, type Page } from '@playwright/test'

/* The device UI talks to the machine only through Tauri's `invoke`. These tests provide
 * `window.__TAURI_INTERNALS__` the way the Tauri runtime does, so the REAL bridge code runs; the
 * only thing faked is the Rust side, which `device-core`'s own tests cover. */

type Call = { cmd: string; args: Record<string, unknown> }

async function asDeviceApp(page: Page, handler: (call: Call) => unknown | Promise<unknown>) {
  const calls: Call[] = []
  await page.exposeFunction('__shieldInvoke', async (cmd: string, args: Record<string, unknown>) => {
    calls.push({ cmd, args })
    return handler({ cmd, args })
  })
  await page.addInitScript(() => {
    // @ts-expect-error provided by the test as the Tauri runtime would
    window.__TAURI_INTERNALS__ = { invoke: (cmd: string, args: unknown) => window.__shieldInvoke(cmd, args) }
  })
  return calls
}

const OVERVIEW = {
  frozen: [
    { pid: 4242, event_id: 'evt-1', since: '2026-11-05T06:00:01Z', handle_to_contain_ms: 3.2, state: 'stopped' },
    { pid: 5000, event_id: 'evt-2', since: '2026-11-05T06:00:02Z', handle_to_contain_ms: null, state: 'running' },
    { pid: 6000, event_id: 'evt-3', since: '2026-11-05T06:00:03Z', handle_to_contain_ms: 1.5, state: 'gone' },
    { pid: 7000, event_id: 'evt-4', since: '2026-11-05T06:00:04Z', handle_to_contain_ms: 9.9, state: 'unknown' },
  ],
  recent_decisions: [
    { time: '2026-11-05T06:00:04Z', class: 'process_activity', action: 'contain', rule_id: 'r9', severity: 'low', export_status: 'ok' },
    { time: '2026-11-05T06:00:01Z', class: 'file_activity', action: 'allow', rule_id: '', severity: 'low', export_status: 'not_attempted' },
  ],
  notes: ['1 decision line(s) could not be read and were skipped.'],
}

test('outside the device app it says so and shows no device data', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('alert')).toContainText('not running inside the Shield device app')
  await expect(page.locator('table')).toHaveCount(0)
  await expect(page.getByText('4242')).toHaveCount(0)
})

test('counts only OS-confirmed freezes and offers resume only where it means something', async ({ page }) => {
  await asDeviceApp(page, ({ cmd }) => (cmd === 'device_overview' ? OVERVIEW : {}))
  await page.goto('/')

  // Four freezes in the log, but only pid 4242 is actually stopped.
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('1 frozen')
  const row = (pid: number) => page.getByRole('row').filter({ hasText: String(pid) })
  await expect(row(4242)).toContainText('Stopped (confirmed)')
  await expect(row(4242)).toContainText('3.20 ms')
  await expect(row(5000)).toContainText('Running (log says frozen)')
  await expect(row(5000)).toContainText('Not measured')
  await expect(row(6000)).toContainText('Exited')
  await expect(row(7000)).toContainText('Unverified')

  // Resume is offered for the stopped and the unverifiable, and for no other.
  await expect(row(4242).getByRole('button', { name: 'Resume' })).toBeVisible()
  await expect(row(7000).getByRole('button', { name: 'Resume' })).toBeVisible()
  await expect(row(5000).getByRole('button')).toHaveCount(0)
  await expect(row(5000)).toContainText('Already running: nothing to resume')
  await expect(row(6000).getByRole('button')).toHaveCount(0)
  await expect(row(6000)).toContainText('Process has exited')

  // Decisions and notes render, with evidence shown as words.
  await expect(page.getByRole('row').filter({ hasText: 'process_activity' })).toContainText('Exported')
  await expect(page.getByRole('row').filter({ hasText: 'file_activity' })).toContainText('Not exported')
  await expect(page.getByText('1 decision line(s) could not be read and were skipped.')).toBeVisible()
})

test('resume asks for confirmation, sends the pid and event id, and shows what Shield said', async ({ page }) => {
  const calls = await asDeviceApp(page, ({ cmd }) =>
    cmd === 'device_overview' ? OVERVIEW
      : { ok: true, stdout: 'OK   resumed pid 4242 (SIGCONT)', stderr: 'note: no usable --device-config; the backend was not told' })
  await page.goto('/')
  const row = page.getByRole('row').filter({ hasText: '4242' })

  await row.getByRole('button', { name: 'Resume' }).click()
  // Nothing is sent until the operator confirms.
  expect(calls.filter((c) => c.cmd === 'resume_process')).toHaveLength(0)
  await row.getByRole('button', { name: 'Confirm resume 4242' }).click()

  await expect(page.getByText('Resumed pid 4242.')).toBeVisible()
  await expect(page.getByText(/OK\s+resumed pid 4242/)).toBeVisible()
  await expect(page.getByText(/backend was not told/)).toBeVisible()
  const sent = calls.filter((c) => c.cmd === 'resume_process')
  expect(sent).toHaveLength(1)
  expect(sent[0].args).toEqual({ pid: 4242, eventId: 'evt-1' })
})

test('cancelling a resume sends nothing', async ({ page }) => {
  const calls = await asDeviceApp(page, ({ cmd }) => (cmd === 'device_overview' ? OVERVIEW : {}))
  await page.goto('/')
  const row = page.getByRole('row').filter({ hasText: '4242' })
  await row.getByRole('button', { name: 'Resume' }).click()
  await row.getByRole('button', { name: 'Cancel' }).click()
  await expect(row.getByRole('button', { name: 'Resume' })).toBeVisible()
  expect(calls.filter((c) => c.cmd === 'resume_process')).toHaveLength(0)
})

test('a failed resume is reported as a failure with Shield’s own message', async ({ page }) => {
  await asDeviceApp(page, ({ cmd }) =>
    cmd === 'device_overview' ? OVERVIEW
      : { ok: false, stdout: '', stderr: 'shield resume: could not resume pid 4242: [Errno 3] No such process' })
  await page.goto('/')
  const row = page.getByRole('row').filter({ hasText: '4242' })
  await row.getByRole('button', { name: 'Resume' }).click()
  await row.getByRole('button', { name: 'Confirm resume 4242' }).click()
  await expect(page.getByText('Could not resume pid 4242.')).toBeVisible()
  await expect(page.getByText(/No such process/)).toBeVisible()
})

test('a device read failure is shown and nothing is presented as current', async ({ page }) => {
  await asDeviceApp(page, ({ cmd }) => {
    if (cmd === 'device_overview') throw new Error('cannot locate the Shield data directory: set SHIELD_DATA_DIR')
    return {}
  })
  await page.goto('/')
  await expect(page.getByRole('alert')).toContainText('Could not read the device')
  await expect(page.getByRole('alert')).toContainText('SHIELD_DATA_DIR')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Reading device state…')
})

test('a fresh device reads as empty with the reason, not as an error', async ({ page }) => {
  await asDeviceApp(page, () => ({
    frozen: [], recent_decisions: [],
    notes: ['No outcome log yet. Nothing has been frozen on this device, or Shield has not run here.'],
  }))
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Nothing frozen')
  await expect(page.getByText('No open freezes.')).toBeVisible()
  await expect(page.getByText('No decisions recorded yet.')).toBeVisible()
  await expect(page.getByText(/No outcome log yet/)).toBeVisible()
  await expect(page.getByRole('alert')).toHaveCount(0)
})

test('fits a phone width without sideways page scroll', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 })
  await asDeviceApp(page, ({ cmd }) => (cmd === 'device_overview' ? OVERVIEW : {}))
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('1 frozen')
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(1)
})
