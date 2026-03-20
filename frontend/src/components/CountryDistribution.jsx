import { useState } from 'react'
import Plot from 'react-plotly.js'
import { COMMON_LAYOUT, CONFIG } from './chartConfig.js'

const DONUT_COLORS = [
  '#00c8ff', '#ff3366', '#ff8c00', '#ffd700', '#00ff9d',
  '#a855f7', '#ec4899', '#06b6d4', '#84cc16', '#f97316',
]

export default function CountryDistribution({ data, loading }) {
  const [view, setView] = useState('source')

  const activeData = Array.isArray(data) ? data : (data?.[view] || [])
  const labels = activeData.map(d => d.country) || []
  const values = activeData.map(d => d.count) || []

  return (
    <div className="cyber-card p-5 flex flex-col" style={{ minHeight: 280 }}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
          🌍 Country Distribution
        </h3>
        <div className="flex rounded" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-dim)' }}>
          <button
            onClick={() => setView('source')}
            className="px-3 py-1 text-xs font-mono transition-all"
            style={{
              background: view === 'source' ? 'rgba(0,200,255,0.15)' : 'transparent',
              color: view === 'source' ? '#00c8ff' : 'var(--text-muted)'
            }}
          >
            Attacking
          </button>
          <button
            onClick={() => setView('target')}
            className="px-3 py-1 text-xs font-mono transition-all"
            style={{
              background: view === 'target' ? 'rgba(255,51,102,0.15)' : 'transparent',
              color: view === 'target' ? '#ff3366' : 'var(--text-muted)'
            }}
          >
            Target
          </button>
        </div>
      </div>

      {loading || !activeData?.length ? (
        <div className="flex-1 flex items-center justify-center" style={{ color: 'var(--text-muted)' }}>
          <span className="font-mono text-sm">{loading ? 'Loading...' : 'No data'}</span>
        </div>
      ) : (
        <Plot
          data={[
            {
              type: 'pie',
              labels,
              values,
              hole: 0.55,
              marker: {
                colors: DONUT_COLORS,
                line: { color: '#0b1623', width: 2 },
              },
              textinfo: 'percent',
              textfont: { color: '#ffffff', size: 10 },
              hovertemplate: '<b>%{label}</b><br>%{value} attacks (%{percent})<extra></extra>',
            },
          ]}
          layout={{
            ...COMMON_LAYOUT,
            margin: { t: 10, r: 10, b: 10, l: 10 },
            showlegend: true,
            legend: {
              font: { color: '#6b8caa', size: 10 },
              bgcolor: 'transparent',
              x: 1.05, y: 0.5,
              orientation: 'v',
            },
            annotations: [{
              text: `<b>${values.reduce((a, b) => a + b, 0)}</b>`,
              font: { size: 18, color: '#00c8ff', family: 'JetBrains Mono' },
              showarrow: false,
              x: 0.5, y: 0.5,
            }],
          }}
          config={CONFIG}
          style={{ width: '100%', height: '220px' }}
        />
      )}
    </div>
  )
}
