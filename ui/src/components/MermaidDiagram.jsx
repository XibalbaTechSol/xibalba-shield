import { useEffect, useId, useState } from 'react'
import { Activity } from 'lucide-react'

let renderQueue = Promise.resolve()

export function MermaidDiagram({ chart, label }) {
  const id = useId().replaceAll(':', '')
  const [svg, setSvg] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    renderQueue = renderQueue.then(() => import('mermaid')).then(({ default: mermaid }) => {
      const scope = document.querySelector('.console') ?? document.documentElement
      const token = (name, fallback) =>
        getComputedStyle(scope).getPropertyValue(name).trim() || fallback
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: 'base',
        themeVariables: {
          background: token('--panel', '#171c22'),
          primaryColor: token('--panel-elevated', '#1f262f'),
          primaryTextColor: token('--text', '#f0f3f6'),
          primaryBorderColor: '#364352',
          lineColor: token('--accent', '#94bce3'),
          secondaryColor: token('--panel', '#171c22'),
          tertiaryColor: token('--bg', '#101418'),
          edgeLabelBackground: '#13181f',
          fontFamily: 'Barlow, system-ui, sans-serif',
          fontSize: '13px',
        },
        flowchart: {
          curve: 'monotoneX',
          htmlLabels: true,
          nodeSpacing: 46,
          rankSpacing: 54,
          padding: 16,
          useMaxWidth: true,
        },
      })
      return mermaid.render(`mermaid-${id}`, chart)
    })
    renderQueue.then(({ svg: rendered }) => { if (active) setSvg(rendered) })
      .catch(() => { if (active) setError('Diagram unavailable') })
    return () => { active = false }
  }, [chart, id])

  return (
    <div className="mermaid-frame" role="img" aria-label={label}>
      <div className="mermaid-frame-header">
        <span className="mermaid-frame-title">
          <Activity size={12} aria-hidden="true" />
          {label || 'Architecture Topology'}
        </span>
        <span className="mermaid-frame-badge">TOPOLOGY SPECIFICATION</span>
      </div>
      {svg ? (
        <div className="mermaid-svg" dangerouslySetInnerHTML={{ __html: svg }} />
      ) : (
        <span className="mermaid-loading">{error || 'Rendering architecture…'}</span>
      )}
    </div>
  )
}
