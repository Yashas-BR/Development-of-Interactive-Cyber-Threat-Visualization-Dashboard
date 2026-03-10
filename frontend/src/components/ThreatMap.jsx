import { ComposableMap, Geographies, Geography, Marker, Line } from 'react-simple-maps'
import { useState, useMemo } from 'react'

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

const SEV_COLOR = {
  Critical: '#ff3366',
  High: '#ff8c00',
  Medium: '#ffd700',
  Low: '#00ff9d',
}

export default function ThreatMap({ threats, loading, fullscreen }) {
  const [tooltip, setTooltip] = useState(null)
  const [hoveredId, setHoveredId] = useState(null)

  const displayThreats = useMemo(() => {
    if (!threats?.length) return []
    // Show a reasonable subset for performance
    return threats.slice(0, 80)
  }, [threats])

  const markers = useMemo(() => {
    const seen = {}
    displayThreats.forEach(t => {
      const srcKey = `${t.source_lat},${t.source_lon}`
      const tgtKey = `${t.target_lat},${t.target_lon}`
      if (!seen[srcKey]) seen[srcKey] = { lat: t.source_lat, lon: t.source_lon, country: t.source_country, count: 0, sevs: [] }
      seen[srcKey].count++
      seen[srcKey].sevs.push(t.severity)
      if (!seen[tgtKey]) seen[tgtKey] = { lat: t.target_lat, lon: t.target_lon, country: t.target_country, count: 0, sevs: [] }
      seen[tgtKey].count++
    })
    return Object.values(seen)
  }, [displayThreats])

  return (
    <div className="cyber-card h-full flex flex-col" style={{ minHeight: fullscreen ? 520 : 380 }}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3"
        style={{ borderBottom: '1px solid var(--border-dim)' }}>
        <div className="flex items-center gap-3">
          <span className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
            🌐 Geospatial Threat Map
          </span>
          <span className="text-xs font-mono px-2 py-0.5 rounded"
            style={{ background: 'rgba(0,200,255,0.1)', color: 'var(--cyan)' }}>
            {displayThreats.length} active vectors
          </span>
        </div>
        {/* Legend */}
        <div className="flex items-center gap-4">
          {Object.entries(SEV_COLOR).map(([k, v]) => (
            <div key={k} className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: v, boxShadow: `0 0 6px ${v}` }} />
              <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{k}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Map */}
      <div className="flex-1 relative overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-full" style={{ color: 'var(--text-muted)' }}>
            <span className="font-mono text-sm">Loading threat data...</span>
          </div>
        ) : (
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{ scale: 130, center: [10, 20] }}
            style={{ width: '100%', height: '100%' }}
          >
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map(geo => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    style={{
                      default: { fill: '#0d1f33', stroke: '#0a2640', strokeWidth: 0.5, outline: 'none' },
                      hover: { fill: '#112840', stroke: '#0d3355', strokeWidth: 0.5, outline: 'none' },
                      pressed: { fill: '#0d1f33', outline: 'none' },
                    }}
                  />
                ))
              }
            </Geographies>

            {/* Attack lines */}
            {displayThreats.map((t, i) => (
              <Line
                key={`line-${i}`}
                from={[t.source_lon, t.source_lat]}
                to={[t.target_lon, t.target_lat]}
                stroke={SEV_COLOR[t.severity] || '#00c8ff'}
                strokeWidth={hoveredId === i ? 2 : 0.8}
                strokeOpacity={hoveredId === i ? 0.9 : 0.35}
                strokeDasharray="4 3"
                style={{ animation: `dash ${1.5 + (i % 3) * 0.5}s linear infinite` }}
                strokeLinecap="round"
              />
            ))}

            {/* Markers */}
            {markers.map((m, i) => (
              <Marker key={`m-${i}`} coordinates={[m.lon, m.lat]}>
                <circle
                  r={Math.min(3 + m.count * 0.6, 8)}
                  fill="rgba(0,200,255,0.15)"
                  stroke="#00c8ff"
                  strokeWidth={1}
                  style={{ cursor: 'pointer', filter: 'drop-shadow(0 0 4px #00c8ff)' }}
                  onMouseEnter={() => setTooltip(m)}
                  onMouseLeave={() => setTooltip(null)}
                />
                <circle r={2} fill="#00c8ff" />
              </Marker>
            ))}
          </ComposableMap>
        )}

        {/* Tooltip */}
        {tooltip && (
          <div className="absolute top-4 right-4 p-3 rounded-lg text-xs font-mono z-10"
            style={{
              background: 'rgba(7,14,24,0.95)',
              border: '1px solid var(--border-glow)',
              color: 'var(--text-primary)',
              backdropFilter: 'blur(8px)',
            }}>
            <div className="font-bold mb-1" style={{ color: 'var(--cyan)' }}>{tooltip.country}</div>
            <div style={{ color: 'var(--text-secondary)' }}>Involvement: {tooltip.count} events</div>
            <div style={{ color: 'var(--text-muted)' }}>
              Coords: {tooltip.lat?.toFixed(2)}, {tooltip.lon?.toFixed(2)}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
