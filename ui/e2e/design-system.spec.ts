import { test, expect, type Page } from '@playwright/test'

/* Conformance audit against the Industry design system (ui/src/App.css header).
 * These assertions read *computed* styles, so they fail if any rule anywhere in
 * the cascade overrides a token -- which is how the palette drifted before. */

const CANON = {
  dark: {
    bg: 'rgb(20, 23, 26)',          // #14171a
    panel: 'rgb(27, 31, 35)',       // #1b1f23
    elevated: 'rgb(38, 43, 48)',    // #262b30
    text: 'rgb(238, 240, 241)',     // #eef0f1
    muted: 'rgb(183, 188, 193)',    // #b7bcc1
    dim: 'rgb(154, 161, 168)',      // #9aa1a8
    accent: 'rgb(148, 188, 227)',   // #94bce3  accent-400
    accentHover: 'rgb(181, 217, 253)', // #b5d9fd accent-300
    colorScheme: 'dark',
  },
  light: {
    bg: 'rgb(242, 242, 243)',       // #f2f2f3
    panel: 'rgb(233, 233, 234)',    // #e9e9ea
    text: 'rgb(29, 31, 32)',        // #1d1f20
    accent: 'rgb(89, 128, 166)',    // #5980a6
    colorScheme: 'light',
  },
}

const FORBIDDEN_FONTS = ['Manrope', 'DM Sans', 'Inter', 'Avenir', 'Helvetica']

async function enterConsole(page: Page) {
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-connection', JSON.stringify({
      baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token',
    }))
  })
  await page.route('**/api/**', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
  await page.goto('/')
  await expect(page.locator('main.console')).toBeVisible()
}

/** Resolved value of a custom property on the console element. */
function tokens(page: Page, names: string[]) {
  return page.evaluate((ns) => {
    const el = document.querySelector('main.console')!
    const cs = getComputedStyle(el)
    const out: Record<string, string> = {}
    for (const n of ns) {
      // normalise through a probe element so #hex and var() both come back as rgb()
      const probe = document.createElement('span')
      probe.style.color = cs.getPropertyValue(n).trim()
      el.appendChild(probe)
      out[n] = getComputedStyle(probe).color
      probe.remove()
    }
    return out
  }, names)
}

test.describe('Industry design system conformance', () => {
  test('dark is the default theme, with the canonical graphite palette', async ({ page }) => {
    await enterConsole(page)
    // no theme was ever stored: the console must come up dark
    await expect(page.locator('main.console')).toHaveClass(/theme-command-center/)
    const t = await tokens(page, ['--bg', '--panel', '--panel-elevated', '--text', '--muted', '--dim', '--accent', '--accent-hover'])
    expect(t['--bg']).toBe(CANON.dark.bg)
    expect(t['--panel']).toBe(CANON.dark.panel)
    expect(t['--panel-elevated']).toBe(CANON.dark.elevated)
    expect(t['--text']).toBe(CANON.dark.text)
    expect(t['--muted']).toBe(CANON.dark.muted)
    expect(t['--dim']).toBe(CANON.dark.dim)
    expect(t['--accent']).toBe(CANON.dark.accent)
    expect(t['--accent-hover']).toBe(CANON.dark.accentHover)
    await expect(page.locator('main.console')).toHaveCSS('background-color', CANON.dark.bg)
  })

  test('an unrecognised stored theme still resolves to dark', async ({ page }) => {
    await page.addInitScript(() => {
      sessionStorage.setItem('shield-session', '1')
      sessionStorage.setItem('shield-console-theme', 'some-stale-value')
      sessionStorage.setItem('shield-connection', JSON.stringify({
        baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token',
      }))
    })
    await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
    await page.goto('/')
    await expect(page.locator('main.console')).toHaveClass(/theme-command-center/)
    await expect(page.locator('main.console')).toHaveCSS('background-color', CANON.dark.bg)
  })

  test('the light theme is Industry\'s own ground', async ({ page }) => {
    await page.addInitScript(() => {
      sessionStorage.setItem('shield-session', '1')
      sessionStorage.setItem('shield-console-theme', 'light')
      sessionStorage.setItem('shield-connection', JSON.stringify({
        baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token',
      }))
    })
    await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
    await page.goto('/')
    await expect(page.locator('main.console')).toHaveClass(/theme-light/)
    const t = await tokens(page, ['--bg', '--panel', '--text', '--accent'])
    expect(t['--bg']).toBe(CANON.light.bg)
    expect(t['--panel']).toBe(CANON.light.panel)
    expect(t['--text']).toBe(CANON.light.text)
    expect(t['--accent']).toBe(CANON.light.accent)
  })

  test('type is Barlow Condensed over Barlow, with no drifted faces', async ({ page }) => {
    await enterConsole(page)
    const fonts = await page.evaluate(() => {
      const seen = new Set<string>()
      for (const el of document.querySelectorAll('main.console, main.console *')) {
        seen.add(getComputedStyle(el).fontFamily)
      }
      return [...seen]
    })
    const joined = fonts.join(' | ')
    for (const bad of ['Manrope', 'DM Sans', 'Inter', 'Avenir']) {
      expect(joined, `no ${bad} anywhere in the console`).not.toContain(bad)
    }
    const heading = page.locator('main.console h1, main.console h2').first()
    await expect(heading).toHaveCSS('font-family', /Barlow Condensed/)
    await expect(page.locator('main.console')).toHaveCSS('font-family', /Barlow/)
  })

  test('every component is square', async ({ page }) => {
    await enterConsole(page)
    const rounded = await page.evaluate(() => {
      const bad: string[] = []
      for (const el of document.querySelectorAll('main.console *')) {
        const cs = getComputedStyle(el)
        const radii = [cs.borderTopLeftRadius, cs.borderTopRightRadius,
                       cs.borderBottomLeftRadius, cs.borderBottomRightRadius]
        for (const r of radii) {
          // 50% is the circular indicator/dot form the system does use
          if (r === '0px' || r.endsWith('%')) continue
          bad.push(`${el.tagName.toLowerCase()}.${(el as HTMLElement).className}: ${r}`)
          break
        }
      }
      return [...new Set(bad)]
    })
    expect(rounded, `rounded components found: ${rounded.slice(0, 15).join('; ')}`).toEqual([])
  })

  test('no neutral surface renders a light fill in dark mode', async ({ page }) => {
    // The regression this guards: whole panels (the rail, the top bar, the agent
    // drawer) were hardcoded white and rendered as light boxes on the graphite
    // ground. A *chromatic* light fill is legitimate -- Industry's primary button
    // is a solid accent, and status dots are solid amber/red -- so only
    // near-neutral light fills are a defect.
    await enterConsole(page)
    const pale = await page.evaluate(() => {
      const bad: string[] = []
      for (const el of document.querySelectorAll('main.console *')) {
        const bg = getComputedStyle(el).backgroundColor
        const m = /^rgba?\((\d+), (\d+), (\d+)(?:, ([0-9.]+))?\)$/.exec(bg)
        if (!m) continue
        const [r, g, b] = [+m[1], +m[2], +m[3]]
        const a = m[4] === undefined ? 1 : +m[4]
        if (a < 0.5) continue
        const chroma = Math.max(r, g, b) - Math.min(r, g, b)
        if ((r + g + b) / 3 > 140 && chroma < 26) {
          bad.push(`${el.tagName.toLowerCase()}.${(el as HTMLElement).className}: ${bg}`)
        }
      }
      return [...new Set(bad)]
    })
    expect(pale, `neutral light fills in dark mode: ${pale.slice(0, 15).join('; ')}`).toEqual([])
  })

  for (const [name, width] of [['desktop', 1440], ['mobile', 390]] as const) {
    test(`no horizontal overflow at ${name} width`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      await enterConsole(page)
      const overflow = await page.evaluate(() =>
        document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(overflow).toBeLessThanOrEqual(1)
    })
  }

  /* Every route, not just the landing view: the drifted light palette lived in the
     Agent drawer and the routing panes, which the default Posture view never shows. */
  const ROUTES = ['Posture', 'Agent', 'Network', 'Decisions', 'Evidence', 'Configuration']

  for (const route of ROUTES) {
    test(`${route} conforms: square, tokenised, no neutral light fill`, async ({ page }) => {
      await enterConsole(page)
      if (route !== 'Posture') {
        await page.getByRole('button', { name: route, exact: true }).first().click()
      }
      await page.waitForTimeout(250)
      const report = await page.evaluate(() => {
        const rounded: string[] = []
        const pale: string[] = []
        const badFont: string[] = []
        for (const el of document.querySelectorAll('main.console *')) {
          const cs = getComputedStyle(el)
          const name = `${el.tagName.toLowerCase()}.${(el as HTMLElement).className}`
          for (const r of [cs.borderTopLeftRadius, cs.borderTopRightRadius,
                           cs.borderBottomLeftRadius, cs.borderBottomRightRadius]) {
            if (r !== '0px' && !r.endsWith('%')) { rounded.push(`${name}: ${r}`); break }
          }
          const m = /^rgba?\((\d+), (\d+), (\d+)(?:, ([0-9.]+))?\)$/.exec(cs.backgroundColor)
          if (m) {
            const [r, g, b] = [+m[1], +m[2], +m[3]]
            const a = m[4] === undefined ? 1 : +m[4]
            const chroma = Math.max(r, g, b) - Math.min(r, g, b)
            if (a >= 0.5 && (r + g + b) / 3 > 140 && chroma < 26) pale.push(`${name}: ${cs.backgroundColor}`)
          }
          for (const bad of ['Manrope', 'DM Sans', 'Inter', 'Avenir']) {
            if (cs.fontFamily.includes(bad)) { badFont.push(`${name}: ${cs.fontFamily}`); break }
          }
        }
        const overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth
        return {
          rounded: [...new Set(rounded)], pale: [...new Set(pale)],
          badFont: [...new Set(badFont)], overflow,
        }
      })
      expect(report.rounded, `rounded: ${report.rounded.slice(0, 10).join('; ')}`).toEqual([])
      expect(report.pale, `neutral light fills: ${report.pale.slice(0, 10).join('; ')}`).toEqual([])
      expect(report.badFont, `drifted fonts: ${report.badFont.slice(0, 10).join('; ')}`).toEqual([])
      expect(report.overflow).toBeLessThanOrEqual(1)
    })
  }
})
