import { useEffect, useId, useState } from 'react'

let renderQueue = Promise.resolve()

export function MermaidDiagram({ chart, label }) {
  const id = useId().replaceAll(':', '')
  const [svg, setSvg] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    renderQueue = renderQueue.then(() => import('mermaid')).then(({ default: mermaid }) => {
      // Take the diagram's palette from the live design tokens rather than
      // repeating hex values here, so it follows whichever theme is applied.
      const scope = document.querySelector('.console') ?? document.documentElement
      const token = (name, fallback) =>
        getComputedStyle(scope).getPropertyValue(name).trim() || fallback
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: 'base',
        themeVariables: {
          background: token('--panel', '#1b1f23'),
          primaryColor: token('--panel-elevated', '#262b30'),
          primaryTextColor: token('--text', '#eef0f1'),
          primaryBorderColor: token('--neutral-700', '#5d5d60'),
          lineColor: token('--accent', '#94bce3'),
          secondaryColor: token('--panel', '#1b1f23'),
          tertiaryColor: token('--bg', '#14171a'),
          fontFamily: 'Barlow, system-ui, sans-serif',
        },
        flowchart: { curve: 'basis', htmlLabels: true, nodeSpacing: 28, rankSpacing: 42 },
      })
      return mermaid.render(`mermaid-${id}`, chart)
    })
    renderQueue.then(({ svg: rendered }) => { if (active) setSvg(rendered) })
      .catch(() => { if (active) setError('Diagram unavailable') })
    return () => { active = false }
  }, [chart, id])

  return <div className="mermaid-frame" role="img" aria-label={label}>
    {svg ? <div className="mermaid-svg" dangerouslySetInnerHTML={{ __html: svg }} /> : <span className="mermaid-loading">{error || 'Rendering architecture…'}</span>}
  </div>
}
