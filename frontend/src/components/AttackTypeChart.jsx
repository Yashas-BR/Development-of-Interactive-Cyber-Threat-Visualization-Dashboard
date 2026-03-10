import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'

const COLORS = ['#ff3366', '#ff8c00', '#00c8ff', '#00c8ff', '#0080c8', '#0080c8', '#0080c8']

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(7,14,24,0.95)', border: '1px solid rgba(0,200,255,0.2)',
      borderRadius: 8, padding: '8px 14px', fontSize: 12, fontFamily: 'monospace',
    }}>
      <div style={{ color: 'var(--cyan)', fontWeight: 700 }}>{payload[0]?.payload?.type}</div>
      <div style={{ color: '#ccc' }}>Count: <b style={{ color: '#fff' }}>{payload[0]?.value}</b></div>
    </div>
  )
}

export default function AttackTypeChart({ data, loading }) {
  const sorted = [...(data || [])].sort((a, b) => b.count - a.count)

  return (
    <div className="cyber-card p-5 flex flex-col" style={{ minHeight: 280 }}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
          ⚔️ Attack Type Frequency
        </h3>
        <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
          {sorted.length} types
        </span>
      </div>

      {loading || !sorted.length ? (
        <div className="flex-1 flex items-center justify-center" style={{ color: 'var(--text-muted)' }}>
          <span className="font-mono text-sm">{loading ? 'Loading...' : 'No data'}</span>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={sorted} margin={{ top: 4, right: 10, bottom: 48, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,200,255,0.06)" vertical={false} />
            <XAxis
              dataKey="type"
              tick={{ fill: '#6b8caa', fontSize: 10, fontFamily: 'monospace' }}
              angle={-25}
              textAnchor="end"
              interval={0}
              axisLine={{ stroke: 'rgba(0,200,255,0.08)' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#6b8caa', fontSize: 10, fontFamily: 'monospace' }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,200,255,0.04)' }} />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {sorted.map((entry, index) => (
                <Cell key={entry.type} fill={COLORS[index % COLORS.length]} opacity={0.85} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
