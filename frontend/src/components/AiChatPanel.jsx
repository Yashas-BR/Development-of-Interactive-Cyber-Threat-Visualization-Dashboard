import { useState, useCallback } from 'react'
import axios from 'axios'

const BASE = 'http://localhost:8000'

const SUGGESTED = [
  'What are the top 3 most critical threats?',
  'Which countries are most targeted?',
  'Are there any signs of a coordinated attack?',
  'What immediate actions should I take?',
]

// Simple markdown-like renderer (bold, bullet points)
function RenderText({ text }) {
  if (!text) return null
  const lines = text.split('\n')
  return (
    <div className="space-y-1" style={{ lineHeight: 1.7 }}>
      {lines.map((line, i) => {
        // Heading (##)
        if (line.startsWith('## ')) {
          return (
            <div key={i} className="font-bold text-base mt-3 mb-1" style={{ color: 'var(--cyan)' }}>
              {line.replace(/^##\s*/, '')}
            </div>
          )
        }
        // Heading (#)
        if (line.startsWith('# ')) {
          return (
            <div key={i} className="font-bold text-lg mt-4 mb-1" style={{ color: 'var(--cyan)' }}>
              {line.replace(/^#\s*/, '')}
            </div>
          )
        }
        // Bullet / numbered
        if (line.match(/^[-*•]\s/) || line.match(/^\d+\.\s/)) {
          const content = line.replace(/^[-*•\d.]\s*/, '')
          return (
            <div key={i} className="flex gap-2 text-sm">
              <span style={{ color: 'var(--cyan)', flexShrink: 0 }}>▸</span>
              <span style={{ color: 'var(--text-secondary)' }} dangerouslySetInnerHTML={{
                __html: content.replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>')
              }} />
            </div>
          )
        }
        // Empty line
        if (!line.trim()) return <div key={i} className="h-2" />
        // Normal paragraph
        return (
          <p key={i} className="text-sm" style={{ color: 'var(--text-secondary)' }}
            dangerouslySetInnerHTML={{
              __html: line.replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>')
            }}
          />
        )
      })}
    </div>
  )
}

export default function AiChatPanel({ events = [] }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const hasData = events.length > 0

  const send = useCallback(async (text) => {
    const userText = (text || input).trim()
    if (!userText || loading) return
    setInput('')
    setError('')

    const newMessages = [...messages, { role: 'user', content: userText }]
    setMessages(newMessages)
    setLoading(true)

    try {
      const res = await axios.post(`${BASE}/api/ai/chat`, {
        messages: newMessages,
        events: events.slice(0, 500), // cap to avoid huge payloads
      })
      const reply = res.data?.reply || res.data?.error || 'No response.'
      setMessages(prev => [...prev, { role: 'model', content: reply }])
    } catch (e) {
      const msg = e?.response?.data?.error || 'Failed to reach AI agent.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [input, messages, events, loading])

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
  }

  const clearChat = () => { setMessages([]); setError('') }

  return (
    <div className="cyber-card overflow-hidden flex flex-col" style={{ minHeight: 420 }}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3"
        style={{ borderBottom: '1px solid var(--border-dim)', background: 'rgba(0,200,255,0.03)' }}>
        <div className="flex items-center gap-3">
          <span style={{ fontSize: 20 }}>🤖</span>
          <div>
            <div className="font-bold text-sm" style={{ color: 'var(--cyan)' }}>AI Security Agent</div>
            <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {hasData
                ? `Grounded on ${events.length.toLocaleString()} events · Groq Llama 3`
                : 'No data loaded — answers will be general'}
            </div>
          </div>
        </div>
        {messages.length > 0 && (
          <button onClick={clearChat}
            className="text-xs font-mono px-2 py-1 rounded"
            style={{ background: 'rgba(255,51,102,0.08)', color: 'var(--red)', border: '1px solid rgba(255,51,102,0.2)' }}>
            Clear
          </button>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-auto p-4 space-y-3" style={{ maxHeight: 420 }}>
        {messages.length === 0 && (
          <div className="py-6">
            <div className="text-center text-xs font-mono mb-4" style={{ color: 'var(--text-muted)' }}>
              Try asking:
            </div>
            <div className="flex flex-col gap-2">
              {SUGGESTED.map(q => (
                <button key={q} onClick={() => send(q)}
                  className="text-left text-xs px-3 py-2 rounded-lg transition-all"
                  style={{
                    background: 'rgba(0,200,255,0.04)',
                    border: '1px solid rgba(0,200,255,0.12)',
                    color: 'var(--text-secondary)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(0,200,255,0.35)'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(0,200,255,0.12)'}
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className="rounded-xl px-4 py-3 max-w-[85%]"
              style={msg.role === 'user'
                ? { background: 'rgba(0,200,255,0.1)', border: '1px solid rgba(0,200,255,0.2)', color: 'var(--text-primary)' }
                : { background: 'rgba(7,14,24,0.9)', border: '1px solid var(--border-dim)' }
              }
            >
              {msg.role === 'user'
                ? <p className="text-sm">{msg.content}</p>
                : <RenderText text={msg.content} />
              }
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="px-4 py-3 rounded-xl animate-pulse text-sm font-mono"
              style={{ background: 'rgba(7,14,24,0.9)', border: '1px solid var(--border-dim)', color: 'var(--text-muted)' }}>
              ⟳ Analysing…
            </div>
          </div>
        )}

        {error && (
          <div className="px-4 py-2 rounded-lg text-xs font-mono"
            style={{ background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.2)', color: 'var(--red)' }}>
            ⚠ {error}
          </div>
        )}
      </div>

      {/* Input */}
      <div className="px-4 py-3 flex gap-2" style={{ borderTop: '1px solid var(--border-dim)' }}>
        <textarea
          rows={1}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ask anything about the threat data…"
          className="flex-1 rounded-lg px-3 py-2 text-sm font-mono resize-none"
          style={{
            background: 'rgba(0,0,0,0.4)',
            border: '1px solid var(--border-dim)',
            color: 'var(--text-primary)',
            outline: 'none',
          }}
          onFocus={e => e.target.style.borderColor = 'rgba(0,200,255,0.4)'}
          onBlur={e => e.target.style.borderColor = 'var(--border-dim)'}
        />
        <button
          onClick={() => send()}
          disabled={!input.trim() || loading}
          className="px-4 py-2 rounded-lg text-sm font-bold transition-all"
          style={{
            background: (input.trim() && !loading) ? 'rgba(0,200,255,0.15)' : 'rgba(0,200,255,0.04)',
            border: '1px solid rgba(0,200,255,0.25)',
            color: (input.trim() && !loading) ? 'var(--cyan)' : 'var(--text-muted)',
            cursor: (input.trim() && !loading) ? 'pointer' : 'not-allowed',
          }}
        >
          ➤
        </button>
      </div>
    </div>
  )
}
