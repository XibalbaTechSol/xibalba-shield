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

  test('there is no light theme to fall back to', async ({ page }) => {
    // Industry ships a single light ground and Shield's console is the derived
    // dark counterpart; carrying both meant every rule existed twice and the
    // copies drifted. A stored 'light' preference must now render dark, and no
    // theme control or light rule may survive anywhere in the cascade.
    await page.addInitScript(() => {
      sessionStorage.setItem('shield-session', '1')
      sessionStorage.setItem('shield-console-theme', 'light')
      sessionStorage.setItem('shield-connection', JSON.stringify({
        baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token',
      }))
    })
    await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
    await page.goto('/')
    const console_ = page.locator('main.console')
    await expect(console_).toHaveClass(/theme-command-center/)
    await expect(console_).not.toHaveClass(/theme-light/)
    await expect(console_).toHaveCSS('background-color', CANON.dark.bg)
    expect(await page.locator('.theme-toggle, .theme-choice').count(),
      'a theme control still exists').toBe(0)
    const lightRules = await page.evaluate(() =>
      [...document.styleSheets]
        .flatMap((sh) => { try { return [...sh.cssRules] } catch { return [] } })
        .filter((r) => (r as CSSStyleRule).selectorText && /theme-light/.test((r as CSSStyleRule).selectorText))
        .length)
    expect(lightRules, 'light-theme rules survive in the cascade').toBe(0)
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
  const THEMES = ['command-center'] as const

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
  for (const theme of THEMES) {
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

/* ── Industry grammar, measured in the rendered page ───────────────────────
 * The assertions above check tokens and faces. These check the things a token
 * cannot express: that information stays inside its window, that every frame
 * and its registration crosses are actually visible, and that buttons, type
 * sizes and icon weights are the ones Industry defines.
 *
 * Each rule below exists because the sweep caught a real defect: a sha256
 * digest pushed 33px outside its row at 1280 and shoved a status badge into
 * the copy; a control-plane URL truncated to an ellipsis; the top-bar buttons
 * wore a panel fill Industry has no variant for; the hero heading rendered at
 * 52px, off the fixed scale.
 *
 * Measurement notes that cost real debugging:
 *  - rects must be intersected with every clipping ancestor, or a collapsed
 *    <details> reads as a 314px spill;
 *  - a registration cross is identified by its SIZE (a small square pseudo),
 *    not by merely having a ::before -- the event ledger's status stripe is a
 *    3px x full-height bar;
 *  - replaced elements (input, img, svg) never paint ::before/::after;
 *  - icon weight must be read from the COMPUTED value, because a CSS property
 *    outranks lucide's stroke-width="2" presentation attribute.
 */
test.describe('Industry grammar in the rendered console', () => {
  // Industry's fixed scale, plus the component sizes styles.css defines.
  const SCALE = [10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 25, 32, 42]
  const ROUTES = ['Posture', 'Agent', 'Network', 'Decisions', 'Evidence', 'Configuration']

  const sweep = (page: Page) => page.evaluate((SCALE) => {
    const out: string[] = []
    const root = document.querySelector('main.console')!
    const all = [...root.querySelectorAll('*')] as HTMLElement[]
    const num = (v: string) => parseFloat(v) || 0
    const alpha = (c: string) => { const m = c.match(/[\d.]+/g); return !m ? 0 : (m.length === 4 ? +m[3] : 1) }
    const name = (e: Element) => e.tagName.toLowerCase() + '.' +
      (e.className || '').toString().trim().split(/\s+/).filter(Boolean).slice(0, 2).join('.')
    const shown = all.filter((e) => {
      const s = getComputedStyle(e), r = e.getBoundingClientRect()
      if (!(s.display !== 'none' && s.visibility !== 'hidden' && +s.opacity > 0.01 && r.width > 0 && r.height > 0)) return false
      // display/visibility/opacity do not describe a closed <details>: its rows
      // keep their laid-out boxes and the UA simply does not paint them.
      if (typeof e.checkVisibility === 'function'
        && !e.checkVisibility({ contentVisibilityAuto: true, opacityProperty: true, visibilityProperty: true })) return false
      for (let p = e.parentElement; p; p = p.parentElement) {
        if (p.tagName === 'DETAILS' && !(p as HTMLDetailsElement).open && !e.closest('summary')) return false
      }
      return true
    })
    const clipOf = (e: Element) => {
      let r = { l: 0, t: 0, r: innerWidth, b: innerHeight }
      for (let p = e.parentElement; p; p = p.parentElement) {
        const s = getComputedStyle(p)
        if (s.overflowX === 'visible' && s.overflowY === 'visible') continue
        const pr = p.getBoundingClientRect()
        r = { l: Math.max(r.l, pr.left), t: Math.max(r.t, pr.top), r: Math.min(r.r, pr.right), b: Math.min(r.b, pr.bottom) }
      }
      return r
    }
    /* Scrolling is not clipping: a window below the fold is reachable, so the
       vertical viewport bound is dropped here. The horizontal bounds stay --
       nothing scrolls sideways to reveal a cross past the left or right edge. */
    const clipNoVp = (e: Element) => {
      let r = { l: 0, t: -1e7, r: innerWidth, b: 1e7 }
      for (let p = e.parentElement; p; p = p.parentElement) {
        const s = getComputedStyle(p)
        if (s.overflowX === 'visible' && s.overflowY === 'visible') continue
        const pr = p.getBoundingClientRect()
        r = { l: Math.max(r.l, pr.left), t: Math.max(r.t, pr.top), r: Math.min(r.r, pr.right), b: Math.min(r.b, pr.bottom) }
      }
      return r
    }
    const MARKED = ['.metric', '.panel', '.resource', '.settings-card', '.hybrid-architecture-card',
      '.outbox-status-card', '.policy-bundle-card', '.policy-deploy-panel', '.integration-card',
      '.event-stream-card', '.api-explorer-layout', '.agent-detail-section', '.agent-toolbar',
      '.agent-grid'].join(',')
    const visRect = (e: Element) => {
      const b = e.getBoundingClientRect(), c = clipOf(e)
      const l = Math.max(b.left, c.l), t = Math.max(b.top, c.t)
      const rr = Math.min(b.right, c.r), bb = Math.min(b.bottom, c.b)
      return { left: l, top: t, right: rr, bottom: bb, width: Math.max(0, rr - l), height: Math.max(0, bb - t) }
    }
    const onScreen = (e: Element) => { const v = visRect(e); return v.width > 1 && v.height > 1 }

    // (a) text truncated or clipped by its own box
    for (const e of shown) {
      const s = getComputedStyle(e)
      if (!(['hidden', 'clip'].includes(s.overflowX) || ['hidden', 'clip'].includes(s.overflowY) || s.textOverflow === 'ellipsis')) continue
      // Only elements that hold text of their own: a container's scroll extent
      // includes deliberate slack (these sections clip to a 6px corner-mark
      // bleed) while its text-bearing descendants are each checked here anyway.
      if (![...e.childNodes].some((n) => n.nodeType === 3 && n.textContent!.trim())) continue
      const dw = e.scrollWidth - e.clientWidth, dh = e.scrollHeight - e.clientHeight
      const t = (e.textContent || '').trim()
      if (t && (dw > 1 || dh > 1)) out.push(`clipped ${name(e)} by ${dw}x${dh}px: ${JSON.stringify(t.slice(0, 40))}`)
    }

    // (a2) nothing is permanently out of reach sideways. `auto`/`scroll` is a
    // deliberate sideways scroller; `hidden`/`clip` puts content beyond reach.
    for (const e of [document.documentElement, ...shown]) {
      if (e !== document.documentElement && !/hidden|clip/.test(getComputedStyle(e).overflowX)) continue
      // a form control scrolls its own value natively; the caret still reaches it
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.tagName)) continue
      const over = e.scrollWidth - e.clientWidth
      if (over > 1) out.push(`${name(e)} overflows horizontally by ${over}px`)
    }

    /* (a3) two laid-out things sitting on top of each other.

       Only pairs in the SAME stacking layer are compared. Paint order alone
       cannot tell a deliberate occlusion (a drawer over the console behind it)
       from a real collision, but the z-index layer can: things meant to cover
       each other are put in different layers on purpose, and two boxes that
       collide inside one layer are a layout fault. Containment is skipped for
       the same reason -- a child is supposed to sit on its parent.

       Rects are the CLIPPED ones, so a row scrolled out of a pane does not read
       as colliding with whatever is painted where it would have been. */
    const layer = (e: Element) => {
      for (let p: Element | null = e; p; p = p.parentElement) {
        const st = getComputedStyle(p)
        if (st.position !== 'static' && st.zIndex !== 'auto') {
          const z = parseInt(st.zIndex, 10)
          if (Number.isFinite(z)) return z
        }
      }
      return 0
    }
    const leaves = shown.filter((e) => ['BUTTON', 'A', 'INPUT', 'SELECT'].includes(e.tagName)
      || [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent!.trim()))
    for (let i = 0; i < leaves.length; i++) {
      for (let j = i + 1; j < leaves.length; j++) {
        const a = leaves[i], b = leaves[j]
        if (a.contains(b) || b.contains(a)) continue
        if (layer(a) !== layer(b)) continue
        const ra = visRect(a), rb = visRect(b)
        if (ra.width < 1 || ra.height < 1 || rb.width < 1 || rb.height < 1) continue
        const ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left)
        const oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top)
        if (ox > 2 && oy > 2) out.push(`${name(a)} overlaps ${name(b)} by ${Math.round(ox)}x${Math.round(oy)}px`)
      }
    }

    const framed = shown.filter((e) => {
      const s = getComputedStyle(e)
      return ['Top', 'Right', 'Bottom', 'Left'].every((d) =>
        num(s[('border' + d + 'Width') as any]) > 0 && alpha(s[('border' + d + 'Color') as any]) > 0.02)
    })

    // (b) content escaping its framed window
    for (const f of framed) {
      const fr = f.getBoundingClientRect()
      for (const kid of [...f.querySelectorAll('*')] as HTMLElement[]) {
        if (!onScreen(kid)) continue
        const ks = getComputedStyle(kid)
        if (ks.position === 'fixed' || ks.position === 'absolute') continue
        const kr = visRect(kid)
        const outX = Math.max(0, Math.round(kr.right - fr.right), Math.round(fr.left - kr.left))
        const outY = Math.max(0, Math.round(kr.bottom - fr.bottom), Math.round(fr.top - kr.top))
        if (outX > 2 || outY > 2) { out.push(`escapes ${name(f)}: ${name(kid)} by ${outX}x${outY}px`); break }
      }
    }

    // (c) frames complete, and their registration crosses inside every clip
    const REPLACED = ['INPUT', 'IMG', 'SELECT', 'TEXTAREA', 'VIDEO', 'CANVAS', 'IFRAME', 'BR', 'HR']
    for (const f of framed) {
      const s = getComputedStyle(f), fr = f.getBoundingClientRect()
      const missing = ['Top', 'Right', 'Bottom', 'Left'].filter((d) =>
        num(s[('border' + d + 'Width') as any]) < 0.5 || alpha(s[('border' + d + 'Color') as any]) < 0.03)
      if (missing.length) out.push(`frame ${name(f)} missing border: ${missing.join(',')}`)
      if (REPLACED.includes(f.tagName)) continue
      /* A cross is drawn as eight gradient arms on ONE pseudo inset outside the
         window -- the only way a mark can straddle a corner, since a background
         is clipped to the border box. Identifying it by the pseudo's SIZE (the
         shape of the four-corner-boxes technique) silently matched nothing once
         the arms moved onto an inset pseudo, and this whole check passed over
         every panel without looking at one. */
      const marks = (pe: string) => {
        const st = getComputedStyle(f, pe)
        if (!st.content || st.content === 'none') return null
        const arms = (st.backgroundImage.match(/gradient/g) || []).length
        if (arms < 8) return null
        const inset = -parseFloat(st.top)
        return Number.isFinite(inset) ? { bleed: inset } : null
      }
      const m = marks('::before') || marks('::after')
      if (!m) {
        // Only the window primitives are marked: a tag, a meter track and a
        // status pill all carry a border and none of them carries a cross.
        if (f.matches(MARKED) && fr.width >= 200 && fr.height >= 72)
          out.push(`no registration cross on ${name(f)}`)
        continue
      }
      if (m.bleed < 6) out.push(`cross on ${name(f)} bleeds only ${m.bleed}px; Industry offsets the corner -6px`)
      const c = clipNoVp(f), bleed = m.bleed
      const cut = [[fr.left, fr.top], [fr.right, fr.top], [fr.left, fr.bottom], [fr.right, fr.bottom]]
        .filter(([x, y]) => x - bleed < c.l - 1 || x + bleed > c.r + 1 || y - bleed < c.t - 1 || y + bleed > c.b + 1).length
      if (cut) out.push(`corner crosses clipped on ${name(f)}: ${cut}/4`)
    }

    // (c2) cards are transparent line drawings. Industry: "do not give cards or
    // figures a surface fill -- they are line drawings (the solid accent primary
    // button is the one deliberate exception)". A framed window may therefore
    // paint nothing, or the ground itself; an overlay is exempt because a drawer
    // or dialog must still occlude whatever sits behind it.
    const groundRGB = (getComputedStyle(root).backgroundColor.match(/[\d.]+/g) || []).slice(0, 3).map(Number)
    const OVERLAY = '.event-drawer, .agent-detail, .modal-card, .dialog, [role="dialog"], [aria-modal="true"], .menu, .dropdown, .popover, .toast'
    for (const f of framed) {
      if (f.closest(OVERLAY) || f.matches(OVERLAY)) continue
      // Only windows. Industry's .tag is explicitly a tinted chip, and meter
      // tracks and status pills are small framed objects of the same family --
      // the "no surface fill" rule is about cards and panels.
      const fr0 = f.getBoundingClientRect()
      if (fr0.width < 200 || fr0.height < 72) continue
      const bg = getComputedStyle(f).backgroundColor
      // a translucent wash is a hover/selected state, not a surface fill
      if (alpha(bg) < 0.2) continue
      const rgb = (bg.match(/[\d.]+/g) || []).slice(0, 3).map(Number)
      const isGround = rgb.length === 3 && groundRGB.length === 3 && rgb.every((v, i) => Math.abs(v - groundRGB[i]) <= 2)
      if (!isGround) out.push(`card has a surface fill ${name(f)}: ${bg}`)
    }

    // (d) button grounds: the one solid accent fill, or a transparent object
    const probe = document.createElement('span')
    probe.style.cssText = 'position:absolute;left:-9999px;color:var(--accent)'
    root.appendChild(probe)
    const acc = (getComputedStyle(probe).color.match(/[\d.]+/g) || []).slice(0, 3).map(Number)
    probe.remove()
    const nearAcc = (c: number[], tol: number) => c.length === 3 && acc.length === 3 && c.every((v, i) => Math.abs(v - acc[i]) <= tol)
    const navLike = (e: Element) => !!e.closest('nav, [role="tablist"], .side, .settings-tabs')
      || e.getAttribute('role') === 'tab'
      || /(^|[\s.-])(row|tab|nav-item|endpoint-nav-item)/.test((e.className || '').toString())
    for (const b of shown) {
      if (!(b.tagName === 'BUTTON' || b.getAttribute('role') === 'button')) continue
      if (navLike(b) || !onScreen(b)) continue
      const s = getComputedStyle(b), bg = s.backgroundColor, a = alpha(bg)
      const rgb = (bg.match(/[\d.]+/g) || []).slice(0, 3).map(Number)
      const solid = a > 0.9 && nearAcc(rgb, 26)
      const tint = a <= 0.9 && nearAcc(rgb, 60)
      if (!solid && !(a < 0.12 || tint)) out.push(`button ground ${name(b)}: ${bg} ${JSON.stringify((b.textContent || '').trim().slice(0, 20))}`)
      if (num(s.borderTopLeftRadius) > 2 && s.borderTopLeftRadius !== '50%') out.push(`button rounded ${name(b)}: ${s.borderTopLeftRadius}`)
    }

    // (e) the fixed type scale, and (f) Lucide at 1.5
    for (const e of shown) {
      if (![...e.childNodes].some((n) => n.nodeType === 3 && n.textContent!.trim())) continue
      const px = Math.round(num(getComputedStyle(e).fontSize) * 10) / 10
      if (!SCALE.includes(px)) out.push(`type off scale ${name(e)}: ${px}px ${JSON.stringify((e.textContent || '').trim().slice(0, 24))}`)
    }
    for (const svg of [...root.querySelectorAll('svg')]) {
      if (!onScreen(svg)) continue
      const n = parseFloat(getComputedStyle(svg).strokeWidth)
      if (n && Math.abs(n - 1.5) > 0.01) out.push(`icon stroke ${n}`)
    }
    return [...new Set(out)]
  }, SCALE)

  for (const width of [390, 1280, 1600]) {
    test(`every route keeps its content, frames and grammar at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      await enterConsole(page)
      const problems: string[] = []
      for (const route of ROUTES) {
        // At phone width the rail is behind the menu toggle and the route
        // buttons are not in the document, so without opening it first every
        // route measures the same Posture screen over and over.
        let btn = page.getByRole('button', { name: new RegExp('^' + route, 'i') }).first()
        if (!(await btn.count())) {
          const menu = page.getByRole('button', { name: /toggle navigation menu/i }).first()
          if (await menu.count()) { await menu.click(); await page.waitForTimeout(300) }
          btn = page.getByRole('button', { name: new RegExp('^' + route, 'i') }).first()
        }
        expect(await btn.count(), `route ${route} unreachable at ${width}px`).toBeGreaterThan(0)
        await btn.click(); await page.waitForTimeout(400)
        await page.evaluate(() => document.fonts.ready)
        expect(await page.locator('main.console *').count(),
          `${route} rendered too little to audit`).toBeGreaterThan(80)
        problems.push(...(await sweep(page)).map((p) => `[${route}] ${p}`))
      }
      expect(problems, `Industry grammar violations:\n  ${problems.join('\n  ')}`).toEqual([])
    })
  }
})
