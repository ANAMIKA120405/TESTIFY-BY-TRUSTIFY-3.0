import { NavLink, Outlet } from 'react-router-dom'

const navItems = [
  { label: 'Dashboard',         to: '/',                 icon: 'diamond-fill' },
  { label: 'URL Scanner',       to: '/url-scanner',      icon: 'diamond' },
  { label: 'Image Processor',   to: '/image-processor',  icon: 'diamond' },
  { label: 'Scan History',      to: '/history',          icon: 'circle-dot' },
  { label: 'Tools',             to: '/tools',            icon: 'diamond' },
  { label: 'Attack Surface Map',to: '/attack-surface-map', icon: 'circle-dot' },
  { label: 'Dark Web Monitor',  to: '/dark-web-monitor', icon: 'diamond' },
  { label: 'Security Box',      to: '/security-box',     icon: 'circle-dot' },
]

function NavIcon({ type, active }: { type: string; active: boolean }) {
  const color = active ? '#22d3ee' : '#64748b'
  if (type === 'diamond-fill')
    return (
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <rect x="6" y="0.5" width="7.5" height="7.5" rx="1" transform="rotate(45 6 0.5)" fill={color} />
      </svg>
    )
  if (type === 'circle-dot')
    return (
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <circle cx="6" cy="6" r="5" stroke={color} strokeWidth="1.5" />
        <circle cx="6" cy="6" r="2" fill={color} />
      </svg>
    )
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <rect x="6" y="0.5" width="7.5" height="7.5" rx="1" transform="rotate(45 6 0.5)" stroke={color} strokeWidth="1.5" />
    </svg>
  )
}

export function AppLayout() {
  return (
    <div className="flex min-h-screen bg-[#0B1120] text-slate-100">
      {/* Sidebar */}
      <aside
        className="flex w-64 shrink-0 flex-col border-r border-slate-800/60 bg-[#0d1117]"
        style={{ minHeight: '100vh' }}
      >
        {/* Brand */}
        <div className="border-b border-slate-800/60 px-5 py-5">
          <p className="text-2xl font-bold text-cyan-400 tracking-tight">Testify</p>
          <p className="text-sm text-slate-400">by Trustify</p>
        </div>

        {/* Nav */}
        <nav className="flex-1 space-y-0.5 px-3 py-4">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                [
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition',
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300'
                    : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-100',
                ].join(' ')
              }
            >
              {({ isActive }) => (
                <>
                  <NavIcon type={item.icon} active={isActive} />
                  {item.label}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* AI Assistant */}
        <div className="border-t border-slate-800/60 px-3 py-3">
          <NavLink
            to="/ai-assistant"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-400 transition hover:bg-slate-800/60 hover:text-slate-100"
          >
            <span className="text-base">🤖</span>
            AI Assistant
          </NavLink>
        </div>

        {/* Footer */}
        <div className="border-t border-slate-800/60 px-5 py-4">
          <p className="text-xs text-slate-500">© 2026 Trustify</p>
          <p className="text-xs text-slate-600">Secure by Design</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto p-6 lg:p-8">
        <Outlet />
      </main>
    </div>
  )
}
