import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import axios from 'axios'
import { api } from './api/api.js'
import StatsCards from './components/StatsCards.jsx'
import ThreatMap from './components/ThreatMap.jsx'
import AttackTypeChart from './components/AttackTypeChart.jsx'
import CountryDistribution from './components/CountryDistribution.jsx'
import AttackTrendChart from './components/AttackTrendChart.jsx'
import DeviceAttackChart from './components/DeviceAttackChart.jsx'
import FiltersBar from './components/FiltersBar.jsx'
import AttackHistory from './components/AttackHistory.jsx'
import Sidebar from './components/Sidebar.jsx'
import ApiKeyPanel from './components/ApiKeyPanel.jsx'

const TABS = ['Overview', 'Analytics', 'Threat Map', 'Live Feed', 'API Status']
const BASE = 'http://localhost:8000'


export default function App() {
  const [activeTab, setActiveTab] = useState('Overview')
  const [filters, setFilters] = useState({ country: 'All', severity: 'All', attack_type: 'All', days: 30 })
  const [meta, setMeta] = useState({ countries: [], attack_types: [], severities: [], days_options: [] })
  const [stats, setStats] = useState({})
  const [threats, setThreats] = useState([])
  const [types, setTypes] = useState([])
  const [countries, setCountries] = useState([])
  const [trends, setTrends] = useState([])
  const [devices, setDevices] = useState([])
  const [severity, setSeverity] = useState([])
  const [loading, setLoading] = useState(true)
  const [connected, setConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [simulating, setSimulating] = useState(false)

  // Live API integration state
  const [liveApiConfig, setLiveApiConfig] = useState(null)      // { provider, api_key, api_secret }
  const [liveThreats, setLiveThreats] = useState([])            // real threats fetched from API
  const [liveFetching, setLiveFetching] = useState(false)
  const [liveError, setLiveError] = useState('')
  const [liveLastFetch, setLiveLastFetch] = useState(null)
  const liveIntervalRef = useRef(null)

  // Derive analytics data directly from liveThreats array (for Overview + Analytics when live)
  const deriveLiveAnalytics = useCallback((events) => {
    if (!events.length) {
      return {
        liveStats: { total_threats: 0, critical_threats: 0, high_risk: 0, countries_affected: 0 },
        liveTypes: [],
        liveCountries: [],
        liveTrends: [],
        liveDevices: []
      }
    }

    // Stats
    const liveStats = {
      total_threats: events.length,
      critical_threats: events.filter(e => e.severity === 'Critical').length,
      high_risk: events.filter(e => e.severity === 'High').length,
      countries_affected: new Set(events.map(e => e.source_country).filter(Boolean)).size,
    }

    // Attack types
    const typeCounts = {}
    events.forEach(e => { typeCounts[e.attack_type] = (typeCounts[e.attack_type] || 0) + 1 })
    const liveTypes = Object.entries(typeCounts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)

    // Country distribution
    const countryCounts = {}
    events.forEach(e => {
      if (e.source_country) countryCounts[e.source_country] = (countryCounts[e.source_country] || 0) + 1
    })
    const liveCountries = Object.entries(countryCounts)
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15)

    // Time trends (group by minute for live data — shows recent activity within the session)
    const minuteCounts = {}
    events.forEach(e => {
      const minute = (e.timestamp || '').slice(0, 16).replace('T', ' ')  // 'YYYY-MM-DD HH:MM'
      if (minute) minuteCounts[minute] = (minuteCounts[minute] || 0) + 1
    })
    const liveTrends = Object.entries(minuteCounts)
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date))

    // Device types
    const deviceCounts = {}
    events.forEach(e => {
      const d = e.device_type || 'Unknown'
      deviceCounts[d] = (deviceCounts[d] || 0) + 1
    })
    const liveDevices = Object.entries(deviceCounts)
      .map(([device, count]) => ({ device, count }))
      .sort((a, b) => b.count - a.count)

    return { liveStats, liveTypes, liveCountries, liveTrends, liveDevices }
  }, [])

  // Compute live analytics whenever liveThreats or filters change
  const liveAnalytics = useMemo(() => {
    if (!liveApiConfig || !liveThreats.length) return null
    let filtered = [...liveThreats]

    // Apply global filters to live threats
    if (filters.country && filters.country !== 'All') {
      filtered = filtered.filter(e => e.source_country === filters.country || e.target_country === filters.country)
    }
    if (filters.severity && filters.severity !== 'All') {
      filtered = filtered.filter(e => e.severity === filters.severity)
    }
    if (filters.attack_type && filters.attack_type !== 'All') {
      filtered = filtered.filter(e => e.attack_type === filters.attack_type)
    }
    // Note: 'days' filter usually doesn't apply to the live buffer,
    // as live data is typically from the current session.

    return deriveLiveAnalytics(filtered)
  }, [liveApiConfig, liveThreats, filters, deriveLiveAnalytics])

  // Active data: prefer live when connected, fall back to simulated
  const activeStats = liveAnalytics ? liveAnalytics.liveStats : stats
  const activeTypes = liveAnalytics ? liveAnalytics.liveTypes : types
  const activeCountries = liveAnalytics ? liveAnalytics.liveCountries : countries
  const activeTrends = liveAnalytics ? liveAnalytics.liveTrends : trends
  const activeDevices = liveAnalytics ? liveAnalytics.liveDevices : devices

  // Also filter the raw live threats for the map/history
  const activeThreats = useMemo(() => {
    if (liveApiConfig && liveThreats.length) {
      let filtered = [...liveThreats]
      if (filters.country && filters.country !== 'All') {
        filtered = filtered.filter(e => e.source_country === filters.country || e.target_country === filters.country)
      }
      if (filters.severity && filters.severity !== 'All') {
        filtered = filtered.filter(e => e.severity === filters.severity)
      }
      if (filters.attack_type && filters.attack_type !== 'All') {
        filtered = filtered.filter(e => e.attack_type === filters.attack_type)
      }
      return filtered
    }
    return threats
  }, [liveApiConfig, liveThreats, threats, filters])

  const fetchAll = useCallback(async () => {
    try {
      const [
        statsRes, threatsRes, typesRes, countriesRes,
        trendsRes, devicesRes, sevRes
      ] = await Promise.all([
        api.getStats(filters),
        api.getThreats({ ...filters, limit: 200 }),
        api.getTypes(filters),
        api.getCountries(filters),
        api.getTrends(filters),
        api.getDevices(filters),
        api.getSeverity(filters),
      ])
      setStats(statsRes.data)
      setThreats(threatsRes.data)
      setTypes(typesRes.data)
      setCountries(countriesRes.data)
      setTrends(trendsRes.data)
      setDevices(devicesRes.data)
      setSeverity(sevRes.data)
      setConnected(true)
      setLastUpdate(new Date())
    } catch (e) {
      setConnected(false)
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => {
    api.getMeta().then(r => setMeta(r.data)).catch(() => { })
    fetchAll()
  }, [])

  useEffect(() => {
    if (!loading) fetchAll()
  }, [filters])

  // Auto-refresh or simulate every 30s
  useEffect(() => {
    const interval = setInterval(() => {
      if (!liveApiConfig) {
        handleSimulate() // Automatically generate new simulated data
      } else {
        fetchAll() // Just refresh db data if connected to live
      }
    }, 30000)
    return () => clearInterval(interval)
  }, [fetchAll, liveApiConfig])

  // When Analytics tab becomes active, nudge Plotly to recalculate chart widths.
  // Bar/line charts render with 0-width on first paint inside a CSS Grid that just
  // became visible; a resize event gives the browser time to lay out and Plotly's
  // useResizeHandler will redraw correctly.
  useEffect(() => {
    if (activeTab === 'Analytics') {
      const timer = setTimeout(() => window.dispatchEvent(new Event('resize')), 120)
      return () => clearTimeout(timer)
    }
  }, [activeTab])

  const handleSimulate = useCallback(async () => {
    setSimulating(true)
    try {
      await api.simulate(250)
      await fetchAll()
    } catch (e) { }
    setSimulating(false)
  }, [fetchAll])

  // Fetch live threats from real API
  const fetchLiveThreats = useCallback(async (config) => {
    if (!config?.api_key) return
    setLiveFetching(true)
    setLiveError('')
    try {
      const r = await axios.post(`${BASE}/api/live/fetch`, {
        provider: config.provider,
        api_key: config.api_key,
        api_secret: config.api_secret || '',
        limit: 15,
      })
      const events = r.data?.events || []
      setLiveThreats(prev => {
        // prepend new events, deduplicate by id, keep last 200
        const all = [...events, ...prev]
        const seen = new Set()
        return all.filter(e => { if (seen.has(e.id)) return false; seen.add(e.id); return true }).slice(0, 200)
      })
      setLiveLastFetch(new Date())
    } catch (e) {
      setLiveError('Failed to fetch live data. Check your API key or try again.')
    } finally {
      setLiveFetching(false)
    }
  }, [])

  // Start/stop live polling when config changes
  useEffect(() => {
    if (liveIntervalRef.current) clearInterval(liveIntervalRef.current)
    if (liveApiConfig) {
      fetchLiveThreats(liveApiConfig)
      liveIntervalRef.current = setInterval(() => fetchLiveThreats(liveApiConfig), 45000)
    } else {
      setLiveThreats([])
    }
    return () => { if (liveIntervalRef.current) clearInterval(liveIntervalRef.current) }
  }, [liveApiConfig, fetchLiveThreats])

  return (
    <div className="flex h-screen w-screen overflow-hidden grid-bg" style={{ background: 'var(--bg-primary)' }}>
      <div className="scanline" />

      {/* Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} tabs={TABS} />

      {/* Main content */}
      <div className="flex flex-col flex-1 overflow-hidden">

        {/* Top bar */}
        <header className="flex items-center justify-between px-6 py-3 border-b"
          style={{ background: 'rgba(7,14,24,0.95)', borderColor: 'var(--border-dim)', backdropFilter: 'blur(12px)' }}>

          {/* Tab navigation */}
          <nav className="flex items-center gap-1">
            {TABS.map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${activeTab === tab
                  ? 'text-white'
                  : 'text-gray-500 hover:text-gray-300'
                  }`}
                style={activeTab === tab ? {
                  background: 'rgba(0,200,255,0.12)',
                  color: 'var(--cyan)',
                  border: '1px solid rgba(0,200,255,0.25)',
                } : {}}
              >
                {tab}
              </button>
            ))}
          </nav>

          {/* Right status */}
          <div className="flex items-center gap-4">
            <button
              onClick={handleSimulate}
              disabled={simulating}
              className="px-3 py-1.5 rounded-lg text-xs font-mono transition-all"
              style={{
                background: simulating ? 'rgba(0,200,255,0.05)' : 'rgba(0,200,255,0.1)',
                border: '1px solid rgba(0,200,255,0.25)',
                color: 'var(--cyan)',
                cursor: simulating ? 'not-allowed' : 'pointer',
              }}
            >
              {simulating ? '⟳ Generating...' : '⚡ Simulate'}
            </button>

            <div className="live-badge">
              <span className="pulse-dot" style={{ width: 6, height: 6 }} />
              {connected ? 'LIVE' : 'OFFLINE'}
            </div>

            {lastUpdate && (
              <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                {lastUpdate.toLocaleTimeString()}
              </span>
            )}
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-5 space-y-5">

          {/* Filters */}
          <FiltersBar
            filters={filters}
            setFilters={setFilters}
            meta={meta}
          />

          {/* Overview Tab */}
          {activeTab === 'Overview' && (
            <>
              {liveAnalytics && (
                <div className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono"
                  style={{ background: 'rgba(0,255,157,0.06)', border: '1px solid rgba(0,255,157,0.2)', color: 'var(--green)' }}>
                  <span className="pulse-dot" style={{ background: 'var(--green)', width: 6, height: 6, borderRadius: '50%', display: 'inline-block' }} />
                  Showing LIVE data from {liveApiConfig?.provider?.toUpperCase()} · {liveThreats.length} real events collected
                </div>
              )}
              <StatsCards stats={activeStats} loading={loading} />
              <div style={{ height: '400px' }}>
                <ThreatMap threats={activeThreats} loading={loading} />
              </div>
              <AttackHistory threats={activeThreats} loading={loading} />
            </>
          )}

          {/* Analytics Tab */}
          {activeTab === 'Analytics' && (
            <>
              {liveAnalytics && (
                <div className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono"
                  style={{ background: 'rgba(0,255,157,0.06)', border: '1px solid rgba(0,255,157,0.2)', color: 'var(--green)' }}>
                  <span className="pulse-dot" style={{ background: 'var(--green)', width: 6, height: 6, borderRadius: '50%', display: 'inline-block' }} />
                  Showing LIVE data from {liveApiConfig?.provider?.toUpperCase()} · {liveThreats.length} real events collected
                </div>
              )}
              <StatsCards stats={activeStats} loading={loading} />
              <div className="grid grid-cols-2 gap-5">
                <AttackTypeChart data={activeTypes} loading={loading} />
                <CountryDistribution data={activeCountries} loading={loading} />
                <AttackTrendChart data={activeTrends} loading={loading} />
                <DeviceAttackChart data={activeDevices} loading={loading} />
              </div>
            </>
          )}

          {/* Threat Map Tab */}
          {activeTab === 'Threat Map' && (
            <>
              {liveAnalytics && (
                <div className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono"
                  style={{ background: 'rgba(0,255,157,0.06)', border: '1px solid rgba(0,255,157,0.2)', color: 'var(--green)' }}>
                  <span className="pulse-dot" style={{ background: 'var(--green)', width: 6, height: 6, borderRadius: '50%', display: 'inline-block' }} />
                  Showing LIVE data from {liveApiConfig?.provider?.toUpperCase()} · {activeThreats.length} real events collected
                </div>
              )}
              <StatsCards stats={activeStats} loading={loading} />
              <div style={{ height: '520px' }}>
                <ThreatMap threats={activeThreats} loading={loading} fullscreen />
              </div>
            </>
          )}

          {/* Live Feed Tab */}
          {activeTab === 'Live Feed' && (
            <LiveFeedTab
              liveApiConfig={liveApiConfig}
              setLiveApiConfig={setLiveApiConfig}
              liveThreats={liveThreats}
              liveFetching={liveFetching}
              liveError={liveError}
              liveLastFetch={liveLastFetch}
              simulatedThreats={threats}
              fetchLiveThreats={fetchLiveThreats}
            />
          )}

          {/* API Status Tab */}
          {activeTab === 'API Status' && (
            <ApiStatus connected={connected} stats={stats} lastUpdate={lastUpdate} />
          )}

        </main>
      </div>
    </div>
  )
}

function LiveFeedTab({
  liveApiConfig, setLiveApiConfig,
  liveThreats, liveFetching, liveError, liveLastFetch,
  simulatedThreats, fetchLiveThreats,
}) {
  const isConnected = !!liveApiConfig
  const displayThreats = isConnected ? liveThreats : simulatedThreats

  const SEV_COLORS = {
    Critical: { color: '#ff3366', bg: 'rgba(255,51,102,0.12)' },
    High: { color: '#ff8c00', bg: 'rgba(255,140,0,0.12)' },
    Medium: { color: '#ffd700', bg: 'rgba(255,215,0,0.1)' },
    Low: { color: '#00ff9d', bg: 'rgba(0,255,157,0.08)' },
  }

  return (
    <div className="space-y-5">
      {/* API Key Panel */}
      <ApiKeyPanel
        savedConfig={liveApiConfig}
        onConfigSaved={setLiveApiConfig}
      />

      {/* Status / mode banner */}
      <div className="flex items-center justify-between px-4 py-3 rounded-xl"
        style={{
          background: isConnected ? 'rgba(0,255,157,0.06)' : 'rgba(0,200,255,0.04)',
          border: `1px solid ${isConnected ? 'rgba(0,255,157,0.2)' : 'rgba(0,200,255,0.1)'}`,
        }}>
        <div className="flex items-center gap-3">
          <span className="text-xl">{isConnected ? '🌐' : '🤖'}</span>
          <div>
            <div className="text-sm font-semibold" style={{ color: isConnected ? 'var(--green)' : 'var(--cyan)' }}>
              {isConnected
                ? `Live Feed — ${liveApiConfig.provider.toUpperCase()}`
                : 'Simulated Mode — No API Key Connected'}
            </div>
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {isConnected
                ? `${liveThreats.length} real threats collected · Last fetch: ${liveLastFetch?.toLocaleTimeString() || 'fetching...'} · auto-refreshes every 45s`
                : 'Connect an API key above to switch to live threat intelligence data'}
            </div>
          </div>
        </div>

        {isConnected && (
          <button
            onClick={() => fetchLiveThreats(liveApiConfig)}
            disabled={liveFetching}
            className="px-3 py-1.5 rounded-lg text-xs font-mono"
            style={{
              background: liveFetching ? 'rgba(0,200,255,0.05)' : 'rgba(0,200,255,0.1)',
              border: '1px solid rgba(0,200,255,0.25)',
              color: 'var(--cyan)',
              cursor: liveFetching ? 'not-allowed' : 'pointer',
            }}
          >
            {liveFetching ? '⟳ Fetching...' : '↻ Refresh Now'}
          </button>
        )}
      </div>

      {/* Error message */}
      {liveError && (
        <div className="px-4 py-2 rounded-lg text-xs font-mono"
          style={{ background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.2)', color: 'var(--red)' }}>
          ⚠ {liveError}
        </div>
      )}

      {/* Threat table */}
      <div className="cyber-card overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3"
          style={{ borderBottom: '1px solid var(--border-dim)' }}>
          <span className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
            {isConnected ? '🔴 Real-Time Threat Events' : '📋 Simulated Threat Events'}
          </span>
          <span className="text-xs font-mono px-2 py-0.5 rounded"
            style={{
              background: isConnected ? 'rgba(0,255,157,0.1)' : 'rgba(0,200,255,0.08)',
              color: isConnected ? 'var(--green)' : 'var(--cyan)',
            }}>
            {displayThreats.length} events
          </span>
        </div>

        <div className="overflow-auto max-h-96">
          {liveFetching && liveThreats.length === 0 ? (
            <div className="p-10 text-center font-mono text-sm animate-pulse" style={{ color: 'var(--text-muted)' }}>
              ⟳ Fetching live threats from {liveApiConfig?.provider}...
            </div>
          ) : displayThreats.length === 0 ? (
            <div className="p-10 text-center font-mono text-sm" style={{ color: 'var(--text-muted)' }}>
              {isConnected ? 'No threats found in latest batch.' : 'No data loaded yet.'}
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-dim)', background: 'rgba(0,200,255,0.03)' }}>
                  {['Timestamp', 'Source IP', 'Country', 'Attack Type', 'Severity',
                    isConnected ? 'Risk Score' : 'Device', 'Source'].map(h => (
                      <th key={h} className="px-4 py-2 text-left font-mono"
                        style={{ color: 'var(--text-muted)' }}>{h}</th>
                    ))}
                </tr>
              </thead>
              <tbody>
                {displayThreats.map((t, i) => {
                  const sev = SEV_COLORS[t.severity] || SEV_COLORS.Low
                  return (
                    <tr key={t.id || i} className="table-row-hover"
                      style={{ borderBottom: '1px solid rgba(0,200,255,0.04)' }}>
                      <td className="px-4 py-2 font-mono" style={{ color: 'var(--text-muted)' }}>
                        {(t.timestamp || '').slice(0, 16).replace('T', ' ')}
                      </td>
                      <td className="px-4 py-2 font-mono" style={{ color: 'var(--cyan)', opacity: 0.8 }}>
                        {t.source_ip}
                      </td>
                      <td className="px-4 py-2" style={{ color: 'var(--text-secondary)' }}>
                        {t.source_country}
                        {t.city ? ` · ${t.city}` : ''}
                      </td>
                      <td className="px-4 py-2">
                        <span className="px-2 py-0.5 rounded font-mono text-xs"
                          style={{ background: 'rgba(0,128,255,0.12)', color: '#0080ff', border: '1px solid rgba(0,128,255,0.2)' }}>
                          {t.attack_type}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <span className="px-2 py-0.5 rounded font-mono text-xs"
                          style={{ background: sev.bg, color: sev.color, border: `1px solid ${sev.color}33` }}>
                          {t.severity}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-mono" style={{ color: 'var(--text-secondary)' }}>
                        {isConnected ? (t.risk_score ?? '—') : (t.device_type || '—')}
                      </td>
                      <td className="px-4 py-2">
                        <span className="text-xs font-mono px-1.5 py-0.5 rounded"
                          style={{
                            background: isConnected ? 'rgba(0,255,157,0.1)' : 'rgba(0,200,255,0.08)',
                            color: isConnected ? 'var(--green)' : 'var(--text-muted)',
                          }}>
                          {t.source || 'simulated'}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

function ApiStatus({ connected, stats, lastUpdate }) {
  const endpoints = [
    { path: '/api/threats', desc: 'Threat Events', status: connected },
    { path: '/api/stats', desc: 'Dashboard Stats', status: connected },
    { path: '/api/trends', desc: 'Attack Trends', status: connected },
    { path: '/api/types', desc: 'Attack Types', status: connected },
    { path: '/api/devices', desc: 'Device Distribution', status: connected },
    { path: '/api/countries', desc: 'Country Data', status: connected },
    { path: '/api/severity', desc: 'Severity Breakdown', status: connected },
    { path: '/api/simulate', desc: 'Data Simulator', status: connected },
  ]
  return (
    <div className="cyber-card p-6 space-y-4">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-lg font-bold" style={{ color: 'var(--cyan)' }}>API Health Monitor</h2>
        <div className={`live-badge ${connected ? '' : 'opacity-50'}`}
          style={{ color: connected ? 'var(--green)' : 'var(--red)' }}>
          <span className="pulse-dot" style={{ background: connected ? 'var(--green)' : 'var(--red)', width: 6, height: 6 }} />
          {connected ? 'Backend Connected' : 'Backend Offline'}
        </div>
      </div>
      <div className="text-xs font-mono mb-4" style={{ color: 'var(--text-muted)' }}>
        Base URL: http://localhost:8000 · Last sync: {lastUpdate ? lastUpdate.toLocaleTimeString() : 'Never'}
      </div>
      <div className="space-y-2">
        {endpoints.map(ep => (
          <div key={ep.path} className="flex items-center justify-between p-3 rounded-lg"
            style={{ background: 'rgba(0,200,255,0.03)', border: '1px solid var(--border-dim)' }}>
            <div>
              <span className="font-mono text-sm" style={{ color: 'var(--cyan)' }}>{ep.path}</span>
              <span className="ml-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{ep.desc}</span>
            </div>
            <span className={`text-xs font-mono px-2 py-1 rounded`}
              style={{
                color: ep.status ? 'var(--green)' : 'var(--red)',
                background: ep.status ? 'rgba(0,255,157,0.1)' : 'rgba(255,51,102,0.1)',
              }}>
              {ep.status ? '● ONLINE' : '● OFFLINE'}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-4 p-3 rounded-lg font-mono text-xs"
        style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-dim)', color: 'var(--text-secondary)' }}>
        Total Events: {stats.total_threats || 0} · Critical: {stats.critical_threats || 0} ·
        High Risk: {stats.high_risk || 0} · Countries: {stats.countries_affected || 0}
      </div>
    </div>
  )
}
