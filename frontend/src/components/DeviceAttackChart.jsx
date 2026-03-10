import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'

const COLORS = [
  '#00c8ff', '#0080ff', '#a855f7', '#ff8c00', '#00ff9d', '#ff3366', '#ffd700',
]

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(7,14,24,0.95)', border: '1px solid rgba(0,200,255,0.2)',
      borderRadius: 8, padding: '8px 14px', fontSize: 12, fontFamily: 'monospace',
    }}>
      <div style={{ color: 'var(--cyan)', fontWeight: 700 }}>{payload[0]?.payload?.device}</div>
      <div style={{ color: '#ccc' }}>Attacks: <b style={{ color: '#fff' }}>{payload[0]?.value}</b></div>
    </div>
  )
}

export default function DeviceAttackChart({ data, loading }) {
  const sorted = [...(data || [])].sort((a, b) => b.count - a.count)

  return (
    <div className="cyber-card p-5 flex flex-col" style={{ minHeight: 280 }}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
          💻 Device-wise Attacks
        </h3>
        <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
          {sorted.length} device types
        </span>
      </div>

      {loading || !sorted.length ? (
        <div className="flex-1 flex items-center justify-center" style={{ color: 'var(--text-muted)' }}>
          <span className="font-mono text-sm">{loading ? 'Loading...' : 'No data'}</span>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart
            data={sorted}
            layout="vertical"
            margin={{ top: 4, right: 20, bottom: 4, left: 70 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,200,255,0.06)" horizontal={false} />
            <XAxis
              type="number"
              tick={{ fill: '#6b8caa', fontSize: 10, fontFamily: 'monospace' }}
              axisLine={{ stroke: 'rgba(0,200,255,0.08)' }}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="device"
              tick={{ fill: '#6b8caa', fontSize: 10, fontFamily: 'monospace' }}
              axisLine={false}
              tickLine={false}
              width={65}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,200,255,0.04)' }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {sorted.map((entry, index) => (
                <Cell key={entry.device} fill={COLORS[index % COLORS.length]} opacity={0.85} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
