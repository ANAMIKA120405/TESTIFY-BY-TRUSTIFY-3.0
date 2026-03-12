import { useState } from 'react'

type AlertSetting = {
  id: string
  label: string
  description: string
  defaultOn: boolean
}

const alertSettings: AlertSetting[] = [
  { id: 'email', label: 'Email Monitoring', description: 'Get notified of email breaches', defaultOn: true },
  { id: 'domain', label: 'Domain Monitoring', description: 'Track domain appearances', defaultOn: true },
  { id: 'critical', label: 'Critical Alerts Only', description: 'Only high-severity breaches', defaultOn: false },
  { id: 'realtime', label: 'Real-time Notifications', description: 'Instant breach notifications', defaultOn: true },
]

function Toggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <button
      type="button"
      onClick={onChange}
      className={[
        'relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200',
        on ? 'bg-cyan-500' : 'bg-slate-600',
      ].join(' ')}
      role="switch"
      aria-checked={on}
    >
      <span
        className={[
          'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform transition-transform duration-200',
          on ? 'translate-x-5' : 'translate-x-0',
        ].join(' ')}
      />
    </button>
  )
}

export function DarkWebMonitorPage() {
  const [emailQuery, setEmailQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [toggles, setToggles] = useState<Record<string, boolean>>(
    Object.fromEntries(alertSettings.map((s) => [s.id, s.defaultOn])),
  )

  const statCards = [
    { label: 'Total Breaches', value: '0', color: 'text-slate-100' },
    { label: 'Critical Alerts', value: '0', color: 'text-red-400' },
    { label: 'Exposed Records', value: '0', color: 'text-orange-400' },
    { label: 'Monitored Assets', value: '0', color: 'text-cyan-400' },
  ]

  return (
    <section className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-slate-100">Dark Web Monitor</h2>
        <p className="mt-1 text-slate-400">Track data breaches and exposed credentials from the dark web</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        {statCards.map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
            <p className="text-sm text-slate-400">{card.label}</p>
            <p className={`mt-2 text-4xl font-bold ${card.color}`}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* Search panel */}
      <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-6 space-y-4">
        {/* Inputs row */}
        <div className="flex flex-col gap-4 sm:flex-row">
          <div className="flex-1">
            <label className="mb-1.5 block text-sm font-medium text-slate-300">Check Email/Domain</label>
            <input
              type="text"
              value={emailQuery}
              onChange={(e) => setEmailQuery(e.target.value)}
              placeholder="user@example.com or example.com"
              className="w-full rounded-xl border border-slate-700/60 bg-slate-900/60 px-4 py-3 text-sm text-slate-100 outline-none ring-cyan-400/40 placeholder:text-slate-500 focus:ring"
            />
          </div>
          <div className="shrink-0">
            <label className="mb-1.5 block text-sm font-medium text-slate-300">Filter by Severity</label>
            <div className="flex gap-2">
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="rounded-xl border border-slate-700/60 bg-slate-800 px-4 py-3 text-sm text-slate-100 outline-none focus:ring focus:ring-cyan-400/40"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
              </select>
              <button
                type="button"
                className="rounded-xl border border-slate-700/60 bg-slate-700 px-5 py-3 text-sm font-semibold text-slate-100 transition hover:bg-slate-600"
              >
                Search
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Breaches */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-xl font-bold text-slate-100">Recent Breaches</h3>
          <span className="text-sm text-slate-500">0 results</span>
        </div>
        <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] py-14 text-center">
          <p className="text-slate-500">No breaches detected. Monitoring active.</p>
        </div>
      </div>

      {/* Alert Settings */}
      <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-6">
        <h3 className="text-xl font-bold text-slate-100">Alert Settings</h3>
        <p className="mt-1 text-sm text-slate-400">
          Configure alerts for specific domains, email addresses, or keywords
        </p>
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          {alertSettings.map((setting) => (
            <div
              key={setting.id}
              className="flex items-center justify-between rounded-xl border border-slate-800/60 bg-slate-900/40 px-5 py-4"
            >
              <div>
                <p className="font-medium text-slate-100">{setting.label}</p>
                <p className="mt-0.5 text-sm text-slate-400">{setting.description}</p>
              </div>
              <Toggle
                on={toggles[setting.id]}
                onChange={() => setToggles((prev) => ({ ...prev, [setting.id]: !prev[setting.id] }))}
              />
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
