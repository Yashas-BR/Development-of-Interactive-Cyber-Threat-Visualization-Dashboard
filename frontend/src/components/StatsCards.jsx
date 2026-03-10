const SEV_CONFIG = {
  Critical: { color: 'var(--red)', bg: 'rgba(255,51,102,0.12)', icon: '⚠', glow: 'rgba(255,51,102,0.3)' },
  High:     { color: 'var(--orange)', bg: 'rgba(255,140,0,0.12)', icon: '▲', glow: 'rgba(255,140,0,0.3)' },
  'High Risk': { color: 'var(--orange)', bg: 'rgba(255,140,0,0.12)', icon: '◈', glow: 'rgba(255,140,0,0.3)' },
  Countries: { color: 'var(--cyan)', bg: 'rgba(0,200,255,0.12)', icon: '◎', glow: 'rgba(0,200,255,0.3)' },
  Total:    { color: '#a78bfa', bg: 'rgba(167,139,250,0.12)', icon: '⬡', glow: 'rgba(167,139,250,0.3)' },
}

function StatCard({ label, value, colorKey, loading }) {
  const cfg = SEV_CONFIG[colorKey] || SEV_CONFIG.Total
  return (
    <div className="cyber-card p-5 flex items-center gap-4 relative overflow-hidden"
      style={{ borderColor: cfg.glow }}>
      {/* Background glow orb */}
      <div className="absolute -right-4 -top-4 w-20 h-20 rounded-full opacity-20 blur-2xl"
        style={{ background: cfg.color }} />

      {/* Icon */}
      <div className="w-12 h-12 rounded-xl flex items-center justify-center text-2xl flex-shrink-0"
        style={{ background: cfg.bg, border: `1px solid ${cfg.glow}`, color: cfg.color }}>
        {cfg.icon}
      </div>

      {/* Value */}
      <div>
        <div className="stat-number text-3xl font-bold" style={{ color: cfg.color }}>
          {loading ? (
            <span className="text-lg" style={{ color: 'var(--text-muted)' }}>—</span>
          ) : (
            value?.toLocaleString() ?? 0
          )}
        </div>
        <div className="text-xs mt-0.5 font-medium tracking-wide" style={{ color: 'var(--text-secondary)' }}>
          {label}
        </div>
      </div>

      {/* Corner accent */}
      <div className="absolute bottom-0 left-0 right-0 h-px"
        style={{ background: `linear-gradient(90deg, transparent, ${cfg.color}, transparent)`, opacity: 0.4 }} />
    </div>
  )
}

export default function StatsCards({ stats, loading }) {
  const cards = [
    { label: 'Total Threats', value: stats.total_threats, key: 'Total' },
    { label: 'Critical', value: stats.critical_threats, key: 'Critical' },
    { label: 'High Risk', value: stats.high_risk, key: 'High Risk' },
    { label: 'Countries Affected', value: stats.countries_affected, key: 'Countries' },
  ]
  return (
    <div className="grid grid-cols-4 gap-4">
      {cards.map(c => (
        <StatCard key={c.label} label={c.label} value={c.value} colorKey={c.key} loading={loading} />
      ))}
    </div>
  )
}
