import { useState, useCallback } from 'react'
import axios from 'axios'

const BASE = 'http://localhost:8000'

// Simple markdown renderer
function RenderText({ text }) {
  if (!text) return null
  const lines = text.split('\n')
  return (
    <div className="space-y-1" style={{ lineHeight: 1.8 }}>
      {lines.map((line, i) => {
        if (line.startsWith('## ')) return (
          <div key={i} className="font-bold text-sm mt-4 mb-1" style={{ color: 'var(--cyan)' }}>
            {line.replace(/^##\s*/, '')}
          </div>
        )
        if (line.startsWith('# ')) return (
          <div key={i} className="font-bold mt-4 mb-2" style={{ color: 'var(--cyan)', fontSize: 15 }}>
            {line.replace(/^#\s*/, '')}
          </div>
        )
        if (line.match(/^[-*•]\s/) || line.match(/^\d+\.\s/)) {
          const content = line.replace(/^[-*•\d.]\s*/, '')
          return (
            <div key={i} className="flex gap-2 text-sm">
              <span style={{ color: 'var(--cyan)', flexShrink: 0 }}>▸</span>
              <span style={{ color: 'var(--text-secondary)' }}
                dangerouslySetInnerHTML={{
                  __html: content.replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>')
                }} />
            </div>
          )
        }
        if (!line.trim()) return <div key={i} className="h-2" />
        return (
          <p key={i} className="text-sm" style={{ color: 'var(--text-secondary)' }}
            dangerouslySetInnerHTML={{
              __html: line.replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>')
            }} />
        )
      })}
    </div>
  )
}

export default function AiSummaryPanel({ events = [] }) {
  const [summary, setSummary] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const hasData = events.length > 0

  const generate = useCallback(async () => {
    if (loading) return
    setLoading(true)
    setError('')
    setSummary('')
    try {
      const res = await axios.post(`${BASE}/api/ai/summary`, {
        events: events.slice(0, 500),
      })
      if (res.data?.error) { setError(res.data.error); return }
      setSummary(res.data?.summary || 'No summary returned.')
    } catch (e) {
      setError(e?.response?.data?.error || 'Failed to generate summary.')
    } finally {
      setLoading(false)
    }
  }, [events, loading])

  return (
    <div className="cyber-card overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3"
        style={{ borderBottom: '1px solid var(--border-dim)', background: 'rgba(0,200,255,0.03)' }}>
        <div className="flex items-center gap-3">
          <span style={{ fontSize: 20 }}>🧠</span>
          <div>
            <div className="font-bold text-sm" style={{ color: 'var(--cyan)' }}>AI Threat Summary</div>
            <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {hasData ? `${events.length.toLocaleString()} events · Groq Llama 3` : 'No data loaded'}
            </div>
          </div>
        </div>
        <button
          onClick={generate}
          disabled={loading || !hasData}
          className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-mono transition-all"
          style={{
            background: (hasData && !loading) ? 'rgba(0,200,255,0.12)' : 'rgba(0,200,255,0.04)',
            border: '1px solid rgba(0,200,255,0.25)',
            color: (hasData && !loading) ? 'var(--cyan)' : 'var(--text-muted)',
            cursor: (hasData && !loading) ? 'pointer' : 'not-allowed',
          }}
        >
          {loading ? '⟳ Generating…' : summary ? '↻ Re-analyze' : '✦ Generate Summary'}
        </button>
      </div>

      {/* Body */}
      <div className="p-5">
        {error && (
          <div className="px-4 py-3 rounded-lg text-xs font-mono mb-4"
            style={{ background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.2)', color: 'var(--red)' }}>
            ⚠ {error}
          </div>
        )}

        {loading && (
          <div className="flex flex-col items-center py-10 gap-3">
            <div className="text-2xl animate-spin">⟳</div>
            <div className="text-xs font-mono animate-pulse" style={{ color: 'var(--text-muted)' }}>
              Analysing {events.length.toLocaleString()} events with Groq…
            </div>
          </div>
        )}

        {!loading && summary && <RenderText text={summary} />}

        {!loading && !summary && !error && (
          <div className="flex flex-col items-center py-10 gap-3">
            <span style={{ fontSize: 40, opacity: 0.3 }}>🧠</span>
            <div className="text-xs font-mono text-center" style={{ color: 'var(--text-muted)', maxWidth: 320 }}>
              {hasData
                ? 'Click "Generate Summary" to get an AI-powered executive threat intelligence report.'
                : 'Load threat data first — upload a file or use simulated/live data.'}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
