import { test, expect, type Page } from '@playwright/test'
import { stubShieldApi } from './shieldFixture'

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

async function enterConsole(page: Page, theme?: 'command-center' | 'light') {
  await stubShieldApi(page, theme)
  await page.goto('/')
  await expect(page.locator('main.console')).toBeVisible()
  // guard against a vacuous sweep: every assertion below quantifies over a set of
  // elements, and an empty set satisfies all of them.
  expect(await page.locator('main.console *').count(),
    'console rendered too little to audit').toBeGreaterThan(100)
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

  /* Every route, in both themes, against the populated control-plane fixture --
     the drifted colour lived in the agent drawer, routing panes, event cards and
     integration badges, which the default empty Posture view never renders. */
  const ROUTES = ['Posture', 'Agent', 'Network', 'Decisions', 'Evidence', 'Configuration']
  const THEMES = ['command-center', 'light'] as const

  for (const theme of THEMES) {
    for (const route of ROUTES) {
      test(`${route} conforms on the ${theme} ground`, async ({ page }) => {
        await enterConsole(page, theme)
        if (route !== 'Posture') {
          await page.getByRole('button', { name: route, exact: true }).first().click()
          await page.waitForTimeout(300)
        }
        const report = await page.evaluate(() => {
          const rounded: string[] = []
          const pale: string[] = []
          const badFont: string[] = []
          const offPalette: string[] = []
          const lowContrast: string[] = []

          const parse = (v: string) => {
            const m = /^rgba?\((\d+), (\d+), (\d+)(?:, ([0-9.]+))?\)$/.exec(v)
            return m ? { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] } : null
          }
          const lum = (c: { r: number; g: number; b: number }) => {
            const f = [c.r, c.g, c.b].map((v) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 })
            return 0.2126 * f[0] + 0.7152 * f[1] + 0.0722 * f[2]
          }
          const contrast = (x: { r: number; g: number; b: number }, y: { r: number; g: number; b: number }) => {
            const [a, b] = [lum(x), lum(y)]
            return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
          }
          const hueOf = (c: { r: number; g: number; b: number }) => {
            const [r, g, b] = [c.r / 255, c.g / 255, c.b / 255]
            const max = Math.max(r, g, b), min = Math.min(r, g, b), d = max - min
            if (d === 0) return -1
            let h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4
            h *= 60; return h < 0 ? h + 360 : h
          }
          /** steel ~195-230, amber ~25-50, red ~0-20 or >350 */
          const onPalette = (h: number) =>
            h < 0 || (h >= 185 && h <= 235) || (h >= 20 && h <= 55) || h <= 15 || h >= 345

          /** the first ancestor whose background is opaque enough to read text against */
          const backdrop = (el: Element) => {
            let n: Element | null = el
            while (n) {
              const c = parse(getComputedStyle(n).backgroundColor)
              if (c && c.a >= 0.85) return c
              n = n.parentElement
            }
            return parse(getComputedStyle(document.body).backgroundColor)
          }
          const hasText = (el: Element) =>
            [...el.childNodes].some((n) => n.nodeType === 3 && (n.textContent || '').trim().length > 1)

          for (const el of document.querySelectorAll('main.console *')) {
            const cs = getComputedStyle(el)
            const name = `${el.tagName.toLowerCase()}.${(el as HTMLElement).className}`.slice(0, 70)
            if (cs.visibility === 'hidden' || cs.display === 'none' || cs.opacity === '0') continue

            for (const r of [cs.borderTopLeftRadius, cs.borderTopRightRadius,
                             cs.borderBottomLeftRadius, cs.borderBottomRightRadius]) {
              if (r !== '0px' && !r.endsWith('%')) { rounded.push(`${name}: ${r}`); break }
            }
            for (const bad of ['Manrope', 'DM Sans', 'Inter', 'Avenir']) {
              if (cs.fontFamily.includes(bad)) { badFont.push(`${name}: ${cs.fontFamily}`); break }
            }

            const bg = parse(cs.backgroundColor)
            if (bg && bg.a >= 0.5) {
              const chroma = Math.max(bg.r, bg.g, bg.b) - Math.min(bg.r, bg.g, bg.b)
              // a neutral light fill on the dark ground is the white-panel defect
              if (document.querySelector('main.console.theme-command-center')
                  && (bg.r + bg.g + bg.b) / 3 > 140 && chroma < 26) pale.push(`${name}: ${cs.backgroundColor}`)
              if (chroma > 24 && !onPalette(hueOf(bg))) offPalette.push(`${name} bg ${cs.backgroundColor}`)
            }
            const fg = parse(cs.color)
            if (fg) {
              const chroma = Math.max(fg.r, fg.g, fg.b) - Math.min(fg.r, fg.g, fg.b)
              if (chroma > 24 && !onPalette(hueOf(fg))) offPalette.push(`${name} fg ${cs.color}`)
              if (hasText(el) && fg.a >= 0.9) {
                const under = backdrop(el)
                if (under) {
                  const size = parseFloat(cs.fontSize)
                  const bold = (parseInt(cs.fontWeight, 10) || 400) >= 700
                  const large = size >= 24 || (size >= 18.66 && bold)
                  const need = large ? 3 : 4.5
                  const got = contrast(fg, under)
                  if (got < need) lowContrast.push(`${name}: ${got.toFixed(2)}:1 (needs ${need}) ${cs.color} on rgb(${under.r}, ${under.g}, ${under.b})`)
                }
              }
            }
          }
          return {
            rounded: [...new Set(rounded)], pale: [...new Set(pale)], badFont: [...new Set(badFont)],
            offPalette: [...new Set(offPalette)], lowContrast: [...new Set(lowContrast)],
            overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          }
        })
        expect(report.rounded, `rounded: ${report.rounded.slice(0, 8).join('; ')}`).toEqual([])
        expect(report.badFont, `drifted fonts: ${report.badFont.slice(0, 8).join('; ')}`).toEqual([])
        expect(report.pale, `neutral light fills: ${report.pale.slice(0, 8).join('; ')}`).toEqual([])
        expect(report.offPalette, `colour outside steel/amber/red: ${report.offPalette.slice(0, 8).join('; ')}`).toEqual([])
        expect(report.lowContrast, `text below AA: ${report.lowContrast.slice(0, 8).join('; ')}`).toEqual([])
        expect(report.overflow).toBeLessThanOrEqual(1)
      })
    }
  }


  /* Overlays. The agent drawer and the expanded event detail were the surfaces
     carrying the hardcoded light palette, and neither renders until opened, so a
     route sweep alone never looks at them. */
  for (const theme of THEMES) {
    test(`the agent drawer and event detail conform on the ${theme} ground`, async ({ page }) => {
      await enterConsole(page, theme)

      await page.getByRole('button', { name: 'Agent', exact: true }).first().click()
      const card = page.locator('button.agent-card').first()
      await expect(card, 'the fixture should render at least one agent card').toBeVisible()
      await card.click()
      const drawer = page.locator('.agent-detail-drawer')
      await expect(drawer).toBeVisible()

      const audit = async (scope: string) => page.evaluate((sel) => {
        const root = document.querySelector(sel)
        if (!root) return null
        const parse = (v: string) => {
          const m = /^rgba?\((\d+), (\d+), (\d+)(?:, ([0-9.]+))?\)$/.exec(v)
          return m ? { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] } : null
        }
        const lum = (c: { r: number; g: number; b: number }) => {
          const f = [c.r, c.g, c.b].map((v) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 })
          return 0.2126 * f[0] + 0.7152 * f[1] + 0.0722 * f[2]
        }
        const backdrop = (el: Element) => {
          let n: Element | null = el
          while (n) { const c = parse(getComputedStyle(n).backgroundColor); if (c && c.a >= 0.85) return c; n = n.parentElement }
          return parse(getComputedStyle(document.body).backgroundColor)
        }
        const dark = !!document.querySelector('main.console.theme-command-center')
        const rounded: string[] = [], pale: string[] = [], low: string[] = []
        const els = [root, ...root.querySelectorAll('*')]
        for (const el of els) {
          const cs = getComputedStyle(el)
          if (cs.display === 'none' || cs.visibility === 'hidden') continue
          const name = `${el.tagName.toLowerCase()}.${(el as HTMLElement).className}`.slice(0, 60)
          for (const r of [cs.borderTopLeftRadius, cs.borderBottomRightRadius]) {
            if (r !== '0px' && !r.endsWith('%')) { rounded.push(`${name}: ${r}`); break }
          }
          const bg = parse(cs.backgroundColor)
          if (dark && bg && bg.a >= 0.5) {
            const chroma = Math.max(bg.r, bg.g, bg.b) - Math.min(bg.r, bg.g, bg.b)
            if ((bg.r + bg.g + bg.b) / 3 > 140 && chroma < 26) pale.push(`${name}: ${cs.backgroundColor}`)
          }
          const fg = parse(cs.color)
          const text = [...el.childNodes].some((n) => n.nodeType === 3 && (n.textContent || '').trim().length > 1)
          if (fg && text) {
            const under = backdrop(el)
            if (under) {
              const size = parseFloat(cs.fontSize)
              const need = size >= 24 || (size >= 18.66 && (parseInt(cs.fontWeight, 10) || 400) >= 700) ? 3 : 4.5
              const la = lum(fg), lb = lum(under)
              const got = (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
              if (got < need) low.push(`${name}: ${got.toFixed(2)}:1 ${cs.color} on rgb(${under.r}, ${under.g}, ${under.b})`)
            }
          }
        }
        return { count: els.length, rounded: [...new Set(rounded)], pale: [...new Set(pale)], low: [...new Set(low)] }
      }, scope)

      const d = await audit('.agent-detail-drawer')
      expect(d, 'drawer not found').not.toBeNull()
      expect(d!.count, 'drawer rendered too little to audit').toBeGreaterThan(10)
      expect(d!.rounded, `drawer rounded: ${d!.rounded.slice(0, 6).join('; ')}`).toEqual([])
      expect(d!.pale, `drawer light fills: ${d!.pale.slice(0, 6).join('; ')}`).toEqual([])
      expect(d!.low, `drawer text below AA: ${d!.low.slice(0, 6).join('; ')}`).toEqual([])

      // and the expanded event detail on Decisions > Event stream.
      // The drawer is aria-modal and its backdrop swallows clicks, so close it first.
      const close = page.locator('.agent-detail-close').first()
      if (await close.count()) await close.click()
      else await page.keyboard.press('Escape')
      await expect(drawer).toBeHidden()
      await page.getByRole('button', { name: 'Decisions', exact: true }).first().click()
      const tab = page.getByRole('tab', { name: 'Event stream' })
      if (await tab.count()) {
        await tab.click()
        const row = page.locator('.event-row, .event-card').first()
        if (await row.count()) {
          await row.click()
          await page.waitForTimeout(200)
          const e = await audit('.event-stream-container')
          if (e) {
            expect(e.rounded, `event detail rounded: ${e.rounded.slice(0, 6).join('; ')}`).toEqual([])
            expect(e.pale, `event detail light fills: ${e.pale.slice(0, 6).join('; ')}`).toEqual([])
            expect(e.low, `event detail text below AA: ${e.low.slice(0, 6).join('; ')}`).toEqual([])
          }
        }
      }
    })
  }

  /* Contrast. Industry warns that the accent-to-ground pair is tuned to 3:1 --
     fine for icons, large text and chrome, not for body copy -- so --accent-text
     exists for paragraph-size accent text and must clear 4.5:1 in both themes. */
  for (const theme of ['command-center', 'light'] as const) {
    test(`text tokens clear WCAG AA on the ${theme} ground`, async ({ page }) => {
      await page.addInitScript((t) => {
        sessionStorage.setItem('shield-session', '1')
        sessionStorage.setItem('shield-console-theme', t)
        sessionStorage.setItem('shield-connection', JSON.stringify({
          baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token',
        }))
      }, theme)
      await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
      await page.goto('/')
      await expect(page.locator('main.console')).toBeVisible()
      const t = await tokens(page, ['--bg', '--text', '--muted', '--dim', '--accent-text', '--amber', '--red'])
      const rgb = (v: string) => (/(\d+), (\d+), (\d+)/.exec(v) ?? []).slice(1).map(Number)
      const lum = (c: number[]) => {
        const f = c.map((v) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 })
        return 0.2126 * f[0] + 0.7152 * f[1] + 0.0722 * f[2]
      }
      const ratio = (a: string, b: string) => {
        const [la, lb] = [lum(rgb(a)), lum(rgb(b))]
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
      }
      for (const name of ['--text', '--muted', '--dim', '--accent-text', '--amber', '--red']) {
        const r = ratio(t[name], t['--bg'])
        expect(r, `${name} on --bg is ${r.toFixed(2)}:1, below AA 4.5:1`).toBeGreaterThanOrEqual(4.5)
      }
    })
  }
})
