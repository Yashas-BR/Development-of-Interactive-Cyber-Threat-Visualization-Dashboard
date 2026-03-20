import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(7,14,24,0.95)', border: '1px solid rgba(0,200,255,0.2)',
      borderRadius: 8, padding: '8px 14px', fontSize: 12, fontFamily: 'monospace',
    }}>
      <div style={{ color: '#6b8caa', marginBottom: 4 }}>{label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.color }}>
          {p.name}: <b style={{ color: '#fff' }}>{typeof p.value === 'number' ? p.value.toFixed(p.dataKey === 'avg' ? 1 : 0) : p.value}</b>
        </div>
      ))}
    </div>
  )
}

export default function AttackTrendChart({ data, loading }) {
  // Compute 5-point moving average for trend line
  const enriched = (data || []).map((d, i, arr) => {
    const window = arr.slice(Math.max(0, i - 2), i + 3)
    const avg = window.reduce((a, b) => a + b.count, 0) / window.length
    return { ...d, avg: parseFloat(avg.toFixed(1)) }
  })

  // Show only every N-th label to avoid crowding
  const labelStep = Math.ceil(enriched.length / 8)

  return (
    <div className="cyber-card p-5 flex flex-col" style={{ minHeight: 280 }}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
          📈 Attack Trends Over Time
        </h3>
        <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
          {enriched.length} data points
        </span>
      </div>

      {loading || !enriched.length ? (
        <div className="flex-1 flex items-center justify-center" style={{ color: 'var(--text-muted)' }}>
          <span className="font-mono text-sm">{loading ? 'Loading...' : 'No data'}</span>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={enriched} margin={{ top: 4, right: 10, bottom: 10, left: 0 }}>
            <defs>
              <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00c8ff" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#00c8ff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,200,255,0.06)" />
            <XAxis
              dataKey="date"
              tick={{ fill: '#6b8caa', fontSize: 9, fontFamily: 'monospace' }}
              tickFormatter={(v, i) => i % labelStep === 0 ? v?.slice(5) : ''}
              axisLine={{ stroke: 'rgba(0,200,255,0.08)' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#6b8caa', fontSize: 10, fontFamily: 'monospace' }}
              axisLine={false}
              tickLine={false}
              width={30}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend
              wrapperStyle={{ fontSize: 10, color: '#6b8caa', fontFamily: 'monospace' }}
            />
            <Area
              type="monotone"
              dataKey="count"
              name="Attacks"
              stroke="#00c8ff"
              strokeWidth={2}
              fill="url(#attackGrad)"
              dot={false}
              activeDot={{ r: 4, fill: '#00c8ff' }}
            />
            <Area
              type="monotone"
              dataKey="avg"
              name="Trend"
              stroke="#00ff9d"
              strokeWidth={1.5}
              strokeDasharray="5 3"
              fill="none"
              dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
