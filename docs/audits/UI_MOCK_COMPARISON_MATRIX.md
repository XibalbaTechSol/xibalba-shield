# Shield UI vs Mock Comparison Matrix

Baseline captured 2026-09-28 after the nested-surface and complete-border pass.

## Reference set

| Reference | Location / evidence | Use |
|---|---|---|
| Mock dark render | `/tmp/shield-mock-aligned-dark.png` | Primary geometry, graphite palette, frame language |
| Mock token audit | `/tmp/shield-mock-token-audit.mjs` | Computed colors, rail, header, content padding, fonts |
| Current route audit | `/tmp/shield-visual-audit.mjs` | Route coverage, desktop/mobile widths, console errors |
| Recent user screenshots | `/home/xibalba/Pictures/Screenshots/Screenshot from 2026-09-28 *.png` | Detail-level comparison for page-specific windows |

Status values: `PASS` = matches the current mock target, `PARTIAL` = implemented but needs pixel comparison, `GAP` = still different, `VERIFY` = requires a supplied/identified mock state.

## Global shell

| Area | Mock target | Current Shield | Status | Gap / next action |
|---|---|---|---|---|
| App background | `#14171a` graphite | `#14171a` | PASS | — |
| Primary window fill | Same continuous graphite field for nested surfaces | Nested windows use `var(--bg)` | PASS | Confirm against every mock state |
| Elevated semantic fill | `#262b30` only where the mock shows an elevated state | Ordinary nested surfaces flattened; semantic states retained | PASS | — |
| Frame line | `rgba(255,255,255,.14)` / computed `#ffffff24` | `var(--line)` | PASS | — |
| Complete card/window borders | One-pixel rectangular rules | Explicit `1px solid var(--line)` on surface classes | PASS | Check drawers/modals in opened states |
| Corner ticks | Short mock ticks at major window corners | Existing frame-tick accents with complete one-pixel frames | PASS | — |
| Body font | Barlow | Barlow | PASS | — |
| Heading font | Barlow Condensed | Barlow Condensed | PASS | — |
| Heading scale | Mock-sized, condensed hierarchy | Shared canonical page/section/panel scale | PASS | — |
| Text colors | `#eef0f1`, `#b7bcc1`, `#9aa1a8` | Matching tokens | PASS | Audit low-contrast small labels |
| Shape language | Square/rectangular controls and cards | `border-radius: 0` system | PASS | Check dynamically rendered components |
| Icon treatment | Transparent icon wells; stroke carries state color | Transparent Lucide icon wells | PASS | Verify drawer/action icons |

## Layout and geometry

| Area | Mock target | Current Shield | Status | Gap / next action |
|---|---|---|---|---|
| Expanded rail | `220px` | `220px` | PASS | — |
| Collapsed rail | `72px` | `72px` | PASS | Verify labels/tooltips in screenshot |
| Header height | `84px` | `84px` | PASS | — |
| Content padding | `34px 42px 72px` desktop | `34px 42px 72px` | PASS | — |
| Mobile content padding | `26px 16px 56px` | Matching responsive rule | PASS | — |
| Top-level page gaps | Mock section rhythm | Shared `20px` workspace rhythm | PASS | — |
| Card internal padding | Mock surface rhythm | Shared `20px` / `14px` compact scale | PASS | — |
| Grid columns | Mock-specific balanced columns | Consolidated responsive grids | PARTIAL | Record each page's exact mock column map |
| Overflow | No horizontal overflow | Desktop/mobile audit widths pass | PASS | Test long identifiers in each detail drawer |

## Verified route evidence

| Route | Dark render | Light render | Mobile render | Console errors | Current verdict |
|---|---|---|---|---|---|
| Posture | `/tmp/shield-dashboard-dark.png` | `/tmp/shield-dashboard-light.png` | `/tmp/shield-dashboard-light-mobile.png` | 0 | PASS on shell; compare populated mock data |
| Agent | route audit passed | `/tmp/shield-agent-light.png` | audit coverage passed | 0 | PARTIAL: compare unified section heights |
| Network | route audit passed | `/tmp/shield-network-light.png` | audit coverage passed | 0 | PARTIAL: compare control/form geometry |
| Decisions | route audit passed | `/tmp/shield-decisions-light.png` | audit coverage passed | 0 | PARTIAL: compare populated event state |
| Evidence | route audit passed | `/tmp/shield-evidence-light.png` | audit coverage passed | 0 | PARTIAL: compare table density |
| Configuration | route audit passed | `/tmp/shield-configuration-light.png` | audit coverage passed | 0 | PARTIAL: compare section ordering and spacing |

The route audit confirms rendering and browser health; `PARTIAL` means the current screenshot and the available mock do not yet share the same data/scroll state for pixel-level equivalence.

## Navigation and header

| Area | Mock target | Current Shield | Status | Gap / next action |
|---|---|---|---|---|
| Header identity | `SHIELD CONTROL PLANE` / `Operator console` / `tenant-a` | Matching | PASS | — |
| Namespace selector | Visible in header | Visible | PASS | Verify opened/select state |
| Theme control | Square icon control | Square | PASS | — |
| Audit export | Rectangular button | Rectangular | PASS | Verify disabled/loading state |
| Active nav | Dark slate selection with thin accent rule | Explicit slate fill + 2px green rule | PASS | — |
| Collapsed nav | Icons only, stable rail | Implemented | PASS | Verify hover affordance |

## Page coverage

| Page / tab | Mock windows expected | Current Shield structure | Status | Gap / next action |
|---|---|---|---|---|
| Posture | Metrics, Runtime health, Responder readiness | Present and bordered | PARTIAL | Compare card heights and metric dividers |
| Agent | Identity boundary, Shield agent, Hermes delivery | Unified page sections | PARTIAL | Compare nested identity rows and delivery metrics |
| Network | Protected zones, routing, controls | Present | VERIFY | Capture matching mock state and compare |
| Decisions / Policy & enforcement | Policy catalog + enforcement | Combined workspace | PARTIAL | Compare stacked section spacing |
| Decisions / Event stream | Toolbar, expandable observation cards, detail panel | Combined event stream | PARTIAL | Normalize populated-state screenshot and compare |
| Decisions / Approvals & guardrails | Approvals + transactions | Combined workspace | PARTIAL | Compare cards and approval state colors |
| Evidence | Evidence/export + detection quality | Unified page sections | PARTIAL | Compare table density and nested panes |
| Configuration | Four continuous sections | Unified page, no nested tabs | PARTIAL | Compare section separators and controls |
| Drawers/modals | Rectangular bordered overlays | Theme rules applied | VERIFY | Open each state and screenshot |

## Event Stream color and frame matrix

| Component | Mock target | Current Shield | Status | Next action |
|---|---|---|---|---|
| Stream toolbar | One neutral surface | Neutral graphite | PASS | — |
| Event card | One neutral surface + frame | Neutral graphite + frame | PASS | Verify populated data |
| Action left rail | Neutral line, not action-colored fill | Neutral line | PASS | — |
| Action pill | Neutral fill/border | Neutral fill/border | PASS | — |
| Severity tag | Neutral fill/border | Neutral fill/border | PASS | — |
| Event class tag | Neutral fill/border | Neutral fill/border | PASS | — |
| Expanded detail grid | Same graphite interior + frame | Same graphite interior + frame | PASS | Verify all cells populated |
| JSON pane | Same graphite interior + frame | Same graphite interior + frame | PASS | Check long JSON wrapping |
| Hover state | Border emphasis only | Border emphasis only | PASS | — |

## Fill-in checklist for final convergence

- [ ] Attach or identify the canonical mock screenshot for each page/tab.
- [ ] Capture Shield and mock at the same viewport and scroll position.
- [ ] Record exact outer bounds for every major window.
- [ ] Record x/y gaps between sibling windows and section headers.
- [ ] Record border presence, thickness, color, and corner tick geometry.
- [ ] Record fill colors for outer, nested, and innermost surfaces.
- [ ] Record heading/body/label font size, weight, line-height, and color.
- [ ] Record active, hover, warning, and disabled states separately.
- [ ] Apply changes in route order: Posture → Agent → Network → Decisions → Evidence → Configuration.
- [ ] Re-run dark/light desktop and mobile screenshot audits after each route group.

## Acceptance gate

The UI is mock-equivalent when every row is `PASS`, every page has a same-state screenshot pair, no surface lacks its frame, no non-semantic fill differs from the mock, and the browser audit reports zero console errors and zero horizontal overflow.
