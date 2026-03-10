import { useState } from 'react'

const SEV_COLORS = {
  Critical: { color: '#ff3366', bg: 'rgba(255,51,102,0.12)' },
  High: { color: '#ff8c00', bg: 'rgba(255,140,0,0.12)' },
  Medium: { color: '#ffd700', bg: 'rgba(255,215,0,0.1)' },
  Low: { color: '#00ff9d', bg: 'rgba(0,255,157,0.08)' },
}

const ATTACK_TYPE_SHORT = {
  'SQL Injection': 'SQLi',
  'DDoS': 'DDoS',
  'XSS': 'XSS',
  'Phishing': 'PHiSH',
  'Brute Force': 'BF',
  'Ransomware': 'RANSOM',
  'Zero Day': '0DAY',
}

export default function AttackHistory({ threats, loading, expanded }) {
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('timestamp')

  const filtered = (threats || [])
    .filter(t =>
      !search ||
      t.source_country?.toLowerCase().includes(search.toLowerCase()) ||
      t.target_country?.toLowerCase().includes(search.toLowerCase()) ||
      t.attack_type?.toLowerCase().includes(search.toLowerCase()) ||
      t.source_ip?.includes(search)
    )
    .sort((a, b) => sortBy === 'timestamp'
      ? new Date(b.timestamp) - new Date(a.timestamp)
      : a.severity?.localeCompare(b.severity)
    )
    .slice(0, expanded ? 200 : 15)

  return (
    <div className="cyber-card overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3"
        style={{ borderBottom: '1px solid var(--border-dim)' }}>
        <div className="flex items-center gap-3">
          <span className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
            📋 Attack History
          </span>
          <span className="text-xs font-mono px-2 py-0.5 rounded"
            style={{ background: 'rgba(255,51,102,0.1)', color: 'var(--red)' }}>
            {filtered.length} events
          </span>
        </div>

        <div className="flex items-center gap-2">
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search threats..."
            className="cyber-input"
            style={{ width: 180 }}
          />
          <select
            value={sortBy}
            onChange={e => setSortBy(e.target.value)}
            className="cyber-input"
          >
            <option value="timestamp">Sort: Latest</option>
            <option value="severity">Sort: Severity</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className={`overflow-auto ${expanded ? 'max-h-96' : 'max-h-52'}`}>
        {loading ? (
          <div className="p-8 text-center font-mono text-sm" style={{ color: 'var(--text-muted)' }}>
            Loading attack data...
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-dim)', background: 'rgba(0,200,255,0.03)' }}>
                {['Timestamp', 'Source IP', 'Source', 'Target', 'Attack Type', 'Severity', 'Device'].map(h => (
                  <th key={h} className="px-4 py-2 text-left font-medium font-mono"
                    style={{ color: 'var(--text-muted)' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((t, i) => {
                const sev = SEV_COLORS[t.severity] || SEV_COLORS.Low
                return (
                  <tr key={t.id || i} className="table-row-hover"
                    style={{ borderBottom: '1px solid rgba(0,200,255,0.04)' }}>
                    <td className="px-4 py-2 font-mono" style={{ color: 'var(--text-muted)' }}>
                      {t.timestamp?.slice(0, 16).replace('T', ' ')}
                    </td>
                    <td className="px-4 py-2 font-mono" style={{ color: 'var(--cyan)', opacity: 0.7 }}>
                      {t.source_ip}
                    </td>
                    <td className="px-4 py-2" style={{ color: 'var(--text-secondary)' }}>
                      {t.source_country}
                    </td>
                    <td className="px-4 py-2" style={{ color: 'var(--text-secondary)' }}>
                      {t.target_country}
                    </td>
                    <td className="px-4 py-2">
                      <span className="px-2 py-0.5 rounded font-mono"
                        style={{ background: 'rgba(0,128,255,0.12)', color: '#0080ff', border: '1px solid rgba(0,128,255,0.2)' }}>
                        {ATTACK_TYPE_SHORT[t.attack_type] || t.attack_type}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      <span className="px-2 py-0.5 rounded font-mono text-xs"
                        style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.color}33` }}>
                        {t.severity}
                      </span>
                    </td>
                    <td className="px-4 py-2" style={{ color: 'var(--text-secondary)' }}>
                      {t.device_type}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
