export default function FiltersBar({ filters, setFilters, meta }) {
  const update = (key, val) => setFilters(prev => ({ ...prev, [key]: val }))

  const DAYS_OPTS = [
    { label: 'Last 7 days', val: 7 },
    { label: 'Last 14 days', val: 14 },
    { label: 'Last 30 days', val: 30 },
    { label: 'Last 60 days', val: 60 },
    { label: 'All time', val: 90 },
  ]

  return (
    <div className="flex items-center gap-3 flex-wrap">
      {/* Label */}
      <span className="text-xs font-mono tracking-widest" style={{ color: 'var(--text-muted)' }}>
        FILTERS
      </span>

      {/* Country */}
      <select
        value={filters.country}
        onChange={e => update('country', e.target.value)}
        className="cyber-input"
      >
        <option value="All">🌍 All Countries</option>
        {meta.countries?.map(c => <option key={c} value={c}>{c}</option>)}
      </select>

      {/* Severity */}
      <select
        value={filters.severity}
        onChange={e => update('severity', e.target.value)}
        className="cyber-input"
      >
        <option value="All">⚡ All Severities</option>
        {['Critical', 'High', 'Medium', 'Low'].map(s => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>

      {/* Attack type */}
      <select
        value={filters.attack_type}
        onChange={e => update('attack_type', e.target.value)}
        className="cyber-input"
      >
        <option value="All">🛡 All Attack Types</option>
        {meta.attack_types?.map(t => <option key={t} value={t}>{t}</option>)}
      </select>

      {/* Time range */}
      <select
        value={filters.days}
        onChange={e => update('days', Number(e.target.value))}
        className="cyber-input"
      >
        {DAYS_OPTS.map(o => <option key={o.val} value={o.val}>{o.label}</option>)}
      </select>

      {/* Reset */}
      <button
        onClick={() => setFilters({ country: 'All', severity: 'All', attack_type: 'All', days: 30 })}
        className="px-3 py-1.5 rounded-lg text-xs transition-all hover:opacity-80"
        style={{
          background: 'rgba(255,51,102,0.08)',
          border: '1px solid rgba(255,51,102,0.2)',
          color: 'var(--red)',
          cursor: 'pointer',
        }}
      >
        ✕ Reset
      </button>

      {/* Active filter tags */}
      <div className="flex items-center gap-2 ml-2">
        {filters.country !== 'All' && (
          <FilterTag label={filters.country} onRemove={() => update('country', 'All')} />
        )}
        {filters.severity !== 'All' && (
          <FilterTag label={filters.severity} onRemove={() => update('severity', 'All')} />
        )}
        {filters.attack_type !== 'All' && (
          <FilterTag label={filters.attack_type} onRemove={() => update('attack_type', 'All')} />
        )}
      </div>
    </div>
  )
}

function FilterTag({ label, onRemove }) {
  return (
    <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-mono"
      style={{
        background: 'rgba(0,200,255,0.1)',
        border: '1px solid rgba(0,200,255,0.25)',
        color: 'var(--cyan)',
      }}>
      {label}
      <span onClick={onRemove} className="cursor-pointer opacity-60 hover:opacity-100">×</span>
    </span>
  )
}
