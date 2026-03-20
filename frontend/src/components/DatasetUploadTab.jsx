import { useState, useRef, useMemo, useCallback } from 'react'
import axios from 'axios'
import StatsCards from './StatsCards.jsx'
import ThreatMap from './ThreatMap.jsx'
import AttackTypeChart from './AttackTypeChart.jsx'
import CountryDistribution from './CountryDistribution.jsx'
import AttackTrendChart from './AttackTrendChart.jsx'
import DeviceAttackChart from './DeviceAttackChart.jsx'
import AttackHistory from './AttackHistory.jsx'
import AiSummaryPanel from './AiSummaryPanel.jsx'
import AiChatPanel from './AiChatPanel.jsx'

const BASE = 'http://localhost:8000'

const ACCEPTED = '.csv,.xlsx,.xls,.json,.tsv'

const SEV_COLORS = {
    Critical: { color: '#ff3366', bg: 'rgba(255,51,102,0.12)' },
    High: { color: '#ff8c00', bg: 'rgba(255,140,0,0.12)' },
    Medium: { color: '#ffd700', bg: 'rgba(255,215,0,0.10)' },
    Low: { color: '#00ff9d', bg: 'rgba(0,255,157,0.08)' },
}

function deriveAnalytics(events) {
    if (!events.length) return {
        stats: { total_threats: 0, critical_threats: 0, high_risk: 0, countries_affected: 0 },
        types: [], countries: [], trends: [], devices: [],
    }

    const stats = {
        total_threats: events.length,
        critical_threats: events.filter(e => e.severity === 'Critical').length,
        high_risk: events.filter(e => e.severity === 'High').length,
        countries_affected: new Set(events.map(e => e.source_country).filter(Boolean)).size,
    }

    const typeCounts = {}
    events.forEach(e => { typeCounts[e.attack_type] = (typeCounts[e.attack_type] || 0) + 1 })
    const types = Object.entries(typeCounts).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count)

    const countryCounts = {}
    events.forEach(e => { if (e.source_country) countryCounts[e.source_country] = (countryCounts[e.source_country] || 0) + 1 })
    const countries = Object.entries(countryCounts).map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count).slice(0, 15)

    const minuteCounts = {}
    events.forEach(e => {
        const minute = (e.timestamp || '').slice(0, 16).replace('T', ' ')
        if (minute) minuteCounts[minute] = (minuteCounts[minute] || 0) + 1
    })
    const trends = Object.entries(minuteCounts).map(([date, count]) => ({ date, count })).sort((a, b) => a.date.localeCompare(b.date))

    const deviceCounts = {}
    events.forEach(e => { const d = e.device_type || 'Unknown'; deviceCounts[d] = (deviceCounts[d] || 0) + 1 })
    const devices = Object.entries(deviceCounts).map(([device, count]) => ({ device, count })).sort((a, b) => b.count - a.count)

    return { stats, types, countries, trends, devices }
}

export default function DatasetUploadTab({ filters = {} }) {
    const [dragging, setDragging] = useState(false)
    const [uploading, setUploading] = useState(false)
    const [error, setError] = useState('')
    const [warnings, setWarnings] = useState([])
    const [fileName, setFileName] = useState('')
    const [colsDetected, setColsDetected] = useState(null)
    const [events, setEvents] = useState([])
    const inputRef = useRef(null)

    const filteredEvents = useMemo(() => {
        let filtered = [...events]
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
    }, [events, filters])

    const analytics = useMemo(() => deriveAnalytics(filteredEvents), [filteredEvents])

    const handleFile = useCallback(async (file) => {
        if (!file) return
        setError('')
        setWarnings([])
        setUploading(true)
        setFileName(file.name)

        const form = new FormData()
        form.append('file', file)
        try {
            const res = await axios.post(`${BASE}/api/upload`, form, {
                headers: { 'Content-Type': 'multipart/form-data' },
            })
            const data = res.data
            if (data.error) { setError(data.error); setUploading(false); return }
            setEvents(data.events || [])
            setColsDetected(data.columns_detected || {})
            setWarnings(data.warnings || [])
        } catch (e) {
            setError(e?.response?.data?.error || 'Upload failed. Check file format and try again.')
        } finally {
            setUploading(false)
        }
    }, [])

    const onDrop = useCallback((e) => {
        e.preventDefault()
        setDragging(false)
        const file = e.dataTransfer?.files?.[0]
        if (file) handleFile(file)
    }, [handleFile])

    const onInputChange = useCallback((e) => {
        const file = e.target.files?.[0]
        if (file) handleFile(file)
        e.target.value = ''
    }, [handleFile])

    const hasData = events.length > 0

    return (
        <div className="space-y-5">
            {/* Upload Zone */}
            <div
                onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                style={{
                    border: `2px dashed ${dragging ? 'var(--cyan)' : 'rgba(0,200,255,0.25)'}`,
                    borderRadius: 16,
                    background: dragging ? 'rgba(0,200,255,0.06)' : 'rgba(7,14,24,0.7)',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    padding: '40px 24px',
                    textAlign: 'center',
                }}
            >
                <input ref={inputRef} type="file" accept={ACCEPTED} style={{ display: 'none' }} onChange={onInputChange} />

                <div style={{ fontSize: 48, marginBottom: 12 }}>
                    {uploading ? '⟳' : hasData ? '✅' : '📂'}
                </div>

                {uploading ? (
                    <div className="font-mono text-sm animate-pulse" style={{ color: 'var(--cyan)' }}>
                        Parsing <strong>{fileName}</strong>…
                    </div>
                ) : hasData ? (
                    <div>
                        <div className="font-semibold text-sm" style={{ color: 'var(--green)' }}>
                            {fileName} — {events.length.toLocaleString()} events loaded
                        </div>
                        <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                            Click or drag a new file to replace
                        </div>
                    </div>
                ) : (
                    <div>
                        <div className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
                            Drop your dataset here or click to browse
                        </div>
                        <div className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
                            Supports&nbsp;
                            {['CSV', 'Excel (.xlsx)', 'JSON', 'TSV'].map(f => (
                                <span key={f} className="mx-1 px-2 py-0.5 rounded font-mono"
                                    style={{ background: 'rgba(0,200,255,0.1)', color: 'var(--cyan)', fontSize: 11 }}>
                                    {f}
                                </span>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            {/* Error */}
            {error && (
                <div className="px-4 py-3 rounded-xl text-sm font-mono"
                    style={{ background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.2)', color: 'var(--red)' }}>
                    ⚠ {error}
                </div>
            )}

            {/* Warnings */}
            {warnings.length > 0 && (
                <div className="px-4 py-3 rounded-xl text-xs font-mono space-y-1"
                    style={{ background: 'rgba(255,215,0,0.06)', border: '1px solid rgba(255,215,0,0.2)', color: '#ffd700' }}>
                    {warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
                </div>
            )}

            {/* Column detection summary */}
            {colsDetected && (
                <div className="px-4 py-3 rounded-xl"
                    style={{ background: 'rgba(0,200,255,0.04)', border: '1px solid rgba(0,200,255,0.12)' }}>
                    <div className="text-xs font-bold mb-2" style={{ color: 'var(--cyan)' }}>🔍 Columns Detected</div>
                    <div className="flex flex-wrap gap-2">
                        {Object.entries(colsDetected).map(([canonical, original]) => (
                            <span key={canonical}
                                className="px-2 py-0.5 rounded text-xs font-mono"
                                style={original
                                    ? { background: 'rgba(0,255,157,0.1)', color: 'var(--green)', border: '1px solid rgba(0,255,157,0.2)' }
                                    : { background: 'rgba(255,51,102,0.08)', color: 'var(--red)', border: '1px solid rgba(255,51,102,0.15)' }
                                }>
                                {original ? `✓ ${canonical} ← "${original}"` : `✗ ${canonical} (fallback)`}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Dashboard */}
            {hasData && (
                <>
                    {/* Banner */}
                    <div className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono"
                        style={{ background: 'rgba(0,128,255,0.06)', border: '1px solid rgba(0,128,255,0.2)', color: '#60a5fa' }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#60a5fa', display: 'inline-block' }} />
                        Showing UPLOADED data from <strong className="mx-1">{fileName}</strong> · {filteredEvents.length.toLocaleString()} events
                    </div>

                    <StatsCards stats={analytics.stats} loading={false} />

                    <div style={{ height: 420 }}>
                        <ThreatMap threats={filteredEvents} loading={false} />
                    </div>

                    <div className="grid grid-cols-2 gap-5">
                        <AttackTypeChart data={analytics.types} loading={false} />
                        <CountryDistribution data={analytics.countries} loading={false} />
                        <AttackTrendChart data={analytics.trends} loading={false} />
                        <DeviceAttackChart data={analytics.devices} loading={false} />
                    </div>

                    <AttackHistory threats={filteredEvents} loading={false} />

                    {/* AI Section */}
                    <div className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono"
                        style={{ background: 'rgba(147,51,234,0.06)', border: '1px solid rgba(147,51,234,0.2)', color: '#a855f7' }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#a855f7', display: 'inline-block' }} />
                        AI Agent — analysing uploaded dataset · {filteredEvents.length.toLocaleString()} events
                    </div>
                    <AiSummaryPanel events={filteredEvents} />
                    <AiChatPanel events={filteredEvents} />
                </>
            )}

            {/* Empty hint */}
            {!hasData && !uploading && !error && (
                <div className="text-center py-10 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                    Upload a file above to instantly visualise your threat data.
                </div>
            )}
        </div>
    )
}
