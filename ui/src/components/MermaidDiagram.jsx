import { useEffect, useId, useState } from 'react'

let renderQueue = Promise.resolve()

export function MermaidDiagram({ chart, label }) {
  const id = useId().replaceAll(':', '')
  const [svg, setSvg] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    renderQueue = renderQueue.then(() => import('mermaid')).then(({ default: mermaid }) => {
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: 'base',
        themeVariables: {
          background: '#0a100d', primaryColor: '#102019', primaryTextColor: '#eaf4ee',
          primaryBorderColor: '#2f7654', lineColor: '#43dc93', secondaryColor: '#121a16',
          tertiaryColor: '#0c1410', fontFamily: 'Inter, ui-sans-serif, system-ui',
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
