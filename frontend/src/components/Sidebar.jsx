const ICONS = {
  Overview: (
    <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
      <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
  ),
  Analytics: (
    <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  ),
  'Threat Map': (
    <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  ),
  'Live Feed': (
    <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49"/>
      <path d="M7.76 16.24a6 6 0 0 1 0-8.49"/><path d="M20.07 4a10 10 0 0 1 0 16"/>
      <path d="M3.93 20a10 10 0 0 1 0-16"/>
    </svg>
  ),
  'API Status': (
    <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
      <path d="M5 12h14"/><path d="M12 5l7 7-7 7"/>
    </svg>
  ),
}

const SECTIONS = [
  { label: 'MONITORING', items: ['Overview', 'Analytics', 'Threat Map'] },
  { label: 'INTELLIGENCE', items: ['Live Feed', 'API Status'] },
]

export default function Sidebar({ activeTab, setActiveTab }) {
  return (
    <aside className="flex flex-col w-52 flex-shrink-0 overflow-y-auto py-4"
      style={{
        background: 'rgba(7,14,24,0.95)',
        borderRight: '1px solid var(--border-dim)',
        backdropFilter: 'blur(12px)',
      }}>

      {/* Logo */}
      <div className="px-4 mb-6">
        <div className="flex items-center gap-2">
          <div className="relative">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: 'rgba(0,200,255,0.15)', border: '1px solid rgba(0,200,255,0.3)' }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00c8ff" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full"
              style={{ background: 'var(--green)', boxShadow: '0 0 6px var(--green)' }}/>
          </div>
          <div>
            <div className="text-xs font-bold tracking-widest" style={{ color: 'var(--cyan)' }}>CYBERTHREAT</div>
            <div className="text-xs" style={{ color: 'var(--text-muted)' }}>INTELLIGENCE</div>
          </div>
        </div>
      </div>

      {/* Nav sections */}
      {SECTIONS.map(sec => (
        <div key={sec.label} className="mb-4">
          <div className="px-4 mb-1 text-xs font-bold tracking-widest"
            style={{ color: 'var(--text-muted)' }}>
            {sec.label}
          </div>
          {sec.items.map(item => (
            <div key={item}
              className={`sidebar-item mx-2 ${activeTab === item ? 'active' : ''}`}
              onClick={() => setActiveTab(item)}>
              <span style={{ color: activeTab === item ? 'var(--cyan)' : 'var(--text-secondary)' }}>
                {ICONS[item]}
              </span>
              <span className="text-sm">{item}</span>
              {item === 'Live Feed' && (
                <span className="ml-auto text-xs px-1.5 py-0.5 rounded font-mono"
                  style={{ background: 'rgba(255,51,102,0.15)', color: 'var(--red)', fontSize: 10 }}>
                  LIVE
                </span>
              )}
            </div>
          ))}
        </div>
      ))}

      {/* Bottom info */}
      <div className="mt-auto px-4 pt-4" style={{ borderTop: '1px solid var(--border-dim)' }}>
        <div className="text-xs font-mono space-y-1" style={{ color: 'var(--text-muted)' }}>
          <div>v1.0.0 · CTI Platform</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>
            {new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}
          </div>
        </div>
      </div>
    </aside>
  )
}
