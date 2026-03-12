import { useNavigate } from 'react-router-dom'

type StatCard = {
  label: string
  value: string
  badge: string
  badgeColor: string
  barPct: number
}

const stats: StatCard[] = [
  { label: 'URLs Scanned', value: '0', badge: '+0%', badgeColor: 'bg-cyan-500/20 text-cyan-300', barPct: 0 },
  { label: 'Threats Detected', value: '0', badge: '+0%', badgeColor: 'bg-cyan-500/20 text-cyan-300', barPct: 0 },
  { label: 'Active Monitors', value: '0', badge: '+0', badgeColor: 'bg-cyan-500/20 text-cyan-300', barPct: 0 },
  { label: 'Secured Assets', value: '0', badge: '+0%', badgeColor: 'bg-cyan-500/20 text-cyan-300', barPct: 0 },
  { label: 'Dark Web Alerts', value: '0', badge: '+0', badgeColor: 'bg-red-500/20 text-red-400', barPct: 0 },
  { label: 'Security Score', value: '0/100', badge: '+0', badgeColor: 'bg-cyan-500/20 text-cyan-300', barPct: 0 },
]

export function DashboardPage() {
  const navigate = useNavigate()

  return (
    <section className="space-y-8">
      {/* Hero */}
      <div className="rounded-2xl border border-slate-800/60 bg-[#0f172a] p-8">
        <h2 className="text-5xl font-bold tracking-tight text-slate-100">
          Securing the{' '}
          <span className="text-cyan-400">Digital Frontier</span>
        </h2>
        <p className="mt-4 max-w-xl text-slate-300">
          Real-time threat intelligence and comprehensive security monitoring for your digital infrastructure.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <button
            onClick={() => navigate('/url-scanner')}
            className="rounded-xl bg-cyan-500 px-6 py-2.5 text-sm font-semibold text-white transition hover:bg-cyan-400"
          >
            Start Scan
          </button>
          <button
            onClick={() => navigate('/dark-web-monitor')}
            className="rounded-xl border border-slate-700 bg-slate-800/60 px-6 py-2.5 text-sm font-semibold text-slate-200 transition hover:bg-slate-700"
          >
            View Reports
          </button>
        </div>
      </div>

      {/* Platform Overview */}
      <div>
        <h3 className="text-xl font-semibold text-slate-100">Platform Overview</h3>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {stats.map((item) => (
            <article key={item.label} className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <div className="flex items-center justify-between">
                <p className="text-sm text-slate-400">{item.label}</p>
                <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${item.badgeColor}`}>{item.badge}</span>
              </div>
              <p className="mt-3 text-4xl font-bold text-slate-100">{item.value}</p>
              <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-slate-700/50">
                <div
                  className="h-full rounded-full bg-cyan-500 transition-all"
                  style={{ width: `${item.barPct}%` }}
                />
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
