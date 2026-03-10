import { useState, useEffect } from 'react'
import axios from 'axios'

const BASE = 'http://localhost:8000'

const PROVIDER_META = {
  ismalicious: {
    icon: '🛡',
    color: '#00c8ff',
    hint: 'Requires API Key + API Secret (from Account Settings)',
    placeholder_key: 'Your API Key',
    placeholder_secret: 'Your API Secret',
    tier: 'paid',
    tierLabel: 'PAID PLAN REQUIRED',
  },
  abuseipdb: {
    icon: '🚨',
    color: '#ff8c00',
    hint: 'Requires only API Key',
    placeholder_key: 'Your API Key',
    placeholder_secret: '',
    tier: 'free',
    tierLabel: 'FREE TIER AVAILABLE',
  },
  virustotal: {
    icon: '🦠',
    color: '#a855f7',
    hint: 'Requires only API Key (x-apikey)',
    placeholder_key: 'Your API Key',
    placeholder_secret: '',
    tier: 'free',
    tierLabel: 'FREE TIER AVAILABLE',
  },
  pulsedive: {
    icon: '⚡',
    color: '#00ffaa',
    hint: 'Requires only API Key',
    placeholder_key: 'Your API Key',
    placeholder_secret: '',
    tier: 'free',
    tierLabel: 'FREE API (1k req/day)',
  },
  alienvault: {
    icon: '👽',
    color: '#34d399',
    hint: 'Requires OTX API Key (X-OTX-API-KEY)',
    placeholder_key: 'Your OTX API Key',
    placeholder_secret: '',
    tier: 'free',
    tierLabel: 'FREE TIER AVAILABLE',
  },
}

export default function ApiKeyPanel({ onConfigSaved, savedConfig }) {
  const [providers, setProviders] = useState([])
  const [selected, setSelected] = useState(savedConfig?.provider || 'ismalicious')
  const [apiKey, setApiKey] = useState(savedConfig?.api_key || '')
  const [apiSecret, setApiSecret] = useState(savedConfig?.api_secret || '')
  const [status, setStatus] = useState(savedConfig?.api_key ? 'valid' : null)  // null | 'validating' | 'valid' | 'invalid'
  const [error, setError] = useState('')
  const [showSecret, setShowSecret] = useState(false)

  useEffect(() => {
    axios.get(`${BASE}/api/live/providers`).then(r => setProviders(r.data)).catch(() => { })
  }, [])

  const meta = PROVIDER_META[selected] || {}
  const needsSecret = providers.find(p => p.id === selected)?.auth_type === 'key_secret'

  const validate = async () => {
    if (!apiKey.trim()) { setError('API Key is required'); return }
    setStatus('validating')
    setError('')
    try {
      const r = await axios.post(`${BASE}/api/live/validate`, {
        provider: selected,
        api_key: apiKey.trim(),
        api_secret: apiSecret.trim(),
      })
      if (r.data.valid) {
        setStatus('valid')
        onConfigSaved({ provider: selected, api_key: apiKey.trim(), api_secret: apiSecret.trim() })
      } else {
        setStatus('invalid')
        setError(r.data.error || `HTTP ${r.data.status_code} — check your credentials`)
      }
    } catch (e) {
      setStatus('invalid')
      setError('Could not reach backend. Is the server running?')
    }
  }

  const clear = () => {
    setApiKey('')
    setApiSecret('')
    setStatus(null)
    setError('')
    onConfigSaved(null)
  }

  return (
    <div className="cyber-card p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold" style={{ color: 'var(--cyan)' }}>
            🔑 Live API Integration
          </h2>
          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
            Connect a real threat intelligence API to replace simulated data in the Live Feed.
          </p>
        </div>
        {status === 'valid' && (
          <div className="live-badge" style={{ color: 'var(--green)' }}>
            <span className="pulse-dot" style={{ background: 'var(--green)', width: 6, height: 6 }} />
            Connected
          </div>
        )}
      </div>

      {/* Provider selector */}
      <div>
        <label className="block text-xs font-mono mb-2" style={{ color: 'var(--text-muted)' }}>
          SELECT PROVIDER
        </label>
        <div className="grid grid-cols-3 gap-2">
          {providers.map(p => {
            const pm = PROVIDER_META[p.id] || {}
            const isActive = selected === p.id
            const isFree = pm.tier === 'free'
            return (
              <button
                key={p.id}
                onClick={() => { setSelected(p.id); setStatus(null); setError('') }}
                className="flex flex-col items-start p-3 rounded-xl transition-all relative"
                style={{
                  background: isActive ? `${pm.color}15` : 'rgba(0,200,255,0.03)',
                  border: `1px solid ${isActive ? pm.color + '50' : 'var(--border-dim)'}`,
                  cursor: 'pointer',
                }}
              >
                {/* Free/Paid badge */}
                <span
                  className="text-xs font-mono px-1.5 py-0.5 rounded mb-1.5"
                  style={{
                    background: isFree ? 'rgba(0,255,136,0.12)' : 'rgba(255,150,0,0.12)',
                    color: isFree ? '#00ff88' : '#ffaa00',
                    fontSize: '0.6rem',
                    letterSpacing: '0.04em',
                  }}
                >
                  {isFree ? '✓ FREE' : '$ PAID'}
                </span>
                <span className="text-xl mb-1">{pm.icon}</span>
                <span className="text-sm font-semibold" style={{ color: isActive ? pm.color : 'var(--text-primary)' }}>
                  {p.name}
                </span>
                <span className="text-xs mt-0.5" style={{ color: 'var(--text-muted)', lineHeight: 1.3 }}>
                  {p.description}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      {/* isMalicious paid-plan warning */}
      {selected === 'ismalicious' && (
        <div
          className="flex items-start gap-2 px-3 py-2.5 rounded-lg text-xs"
          style={{
            background: 'rgba(255,150,0,0.08)',
            border: '1px solid rgba(255,150,0,0.3)',
            color: '#ffaa00',
          }}
        >
          <span style={{ fontSize: '1rem', lineHeight: 1 }}>⚠️</span>
          <div>
            <span className="font-semibold">isMalicious FREE plan does not include API access.</span>
            <span style={{ color: 'var(--text-muted)' }}>
              {' '}You need to upgrade to Basic or Pro at{' '}
              <a
                href="https://ismalicious.com/pricing"
                target="_blank"
                rel="noreferrer"
                className="underline"
                style={{ color: '#ffaa00' }}
              >
                ismalicious.com/pricing
              </a>
              , or switch to{' '}
              <button
                onClick={() => { setSelected('abuseipdb'); setStatus(null); setError('') }}
                className="underline font-semibold"
                style={{ background: 'transparent', border: 'none', color: '#ff8c00', cursor: 'pointer', padding: 0 }}
              >
                AbuseIPDB (free)
              </button>
              .
            </span>
          </div>
        </div>
      )}

      {/* AbuseIPDB free-tier highlight */}
      {selected === 'abuseipdb' && (
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
          style={{
            background: 'rgba(0,255,136,0.06)',
            border: '1px solid rgba(0,255,136,0.2)',
            color: '#00ff88',
          }}
        >
          ✅ AbuseIPDB has a free tier with 1,000 checks/day. Get your API key at{' '}
          <a
            href="https://www.abuseipdb.com/register"
            target="_blank"
            rel="noreferrer"
            className="underline opacity-80 hover:opacity-100 ml-1"
            style={{ color: '#00ff88' }}
          >
            abuseipdb.com/register ↗
          </a>
        </div>
      )}

      {/* Hint */}
      {meta.hint && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg text-xs"
          style={{ background: `${meta.color}0d`, border: `1px solid ${meta.color}25`, color: meta.color }}>
          ℹ️ {meta.hint} ·{' '}
          <a
            href={providers.find(p => p.id === selected)?.docs}
            target="_blank"
            rel="noreferrer"
            className="underline opacity-80 hover:opacity-100"
          >
            API Docs ↗
          </a>
        </div>
      )}

      {/* API Key input */}
      <div className="space-y-3">
        <div>
          <label className="block text-xs font-mono mb-1.5" style={{ color: 'var(--text-muted)' }}>
            API KEY *
          </label>
          <input
            type="password"
            value={apiKey}
            onChange={e => { setApiKey(e.target.value); setStatus(null) }}
            placeholder={meta.placeholder_key || 'Enter API Key'}
            className="cyber-input w-full font-mono"
            style={{ letterSpacing: apiKey ? '0.08em' : 'normal' }}
          />
        </div>

        {needsSecret && (
          <div>
            <label className="block text-xs font-mono mb-1.5" style={{ color: 'var(--text-muted)' }}>
              API SECRET *
            </label>
            <div className="relative">
              <input
                type={showSecret ? 'text' : 'password'}
                value={apiSecret}
                onChange={e => { setApiSecret(e.target.value); setStatus(null) }}
                placeholder={meta.placeholder_secret || 'Enter API Secret'}
                className="cyber-input w-full font-mono pr-16"
                style={{ letterSpacing: apiSecret && !showSecret ? '0.08em' : 'normal' }}
              />
              <button
                onClick={() => setShowSecret(s => !s)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-xs px-2 py-1 rounded"
                style={{ color: 'var(--text-muted)', background: 'transparent', cursor: 'pointer', border: 'none', outline: 'none' }}
              >
                {showSecret ? '🙈 Hide' : '👁 Show'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Error message */}
      {error && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg text-xs font-mono"
          style={{ background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.2)', color: 'var(--red)' }}>
          ⚠ {error}
        </div>
      )}

      {/* Buttons */}
      <div className="flex items-center gap-3">
        <button
          onClick={validate}
          disabled={status === 'validating' || !apiKey}
          className="px-5 py-2 rounded-lg text-sm font-semibold transition-all"
          style={{
            background: status === 'validating' ? 'rgba(0,200,255,0.05)' : 'rgba(0,200,255,0.15)',
            border: '1px solid rgba(0,200,255,0.35)',
            color: 'var(--cyan)',
            cursor: status === 'validating' || !apiKey ? 'not-allowed' : 'pointer',
            opacity: !apiKey ? 0.5 : 1,
          }}
        >
          {status === 'validating' ? '⟳ Validating...' : status === 'valid' ? '✓ Validated — Reconnect' : '🔗 Validate & Connect'}
        </button>

        {status === 'valid' && (
          <button
            onClick={clear}
            className="px-4 py-2 rounded-lg text-sm transition-all"
            style={{
              background: 'rgba(255,51,102,0.08)',
              border: '1px solid rgba(255,51,102,0.2)',
              color: 'var(--red)',
              cursor: 'pointer',
            }}
          >
            ✕ Disconnect
          </button>
        )}
      </div>

      {/* Security notice */}
      <div className="text-xs pt-2" style={{ color: 'var(--text-muted)', borderTop: '1px solid var(--border-dim)' }}>
        🔒 Your API keys are sent only to your local backend (localhost:8000) — never stored or logged externally.
      </div>
    </div>
  )
}
