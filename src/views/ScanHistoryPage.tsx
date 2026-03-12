import { useState } from 'react'
import { getHistory, clearHistory, type HistoryEntry } from '../lib/scanHistory'

/* ── Style helpers ───────────────────────────────────────────────────────────── */

const statusBadge: Record<string, string> = {
  Safe:                'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  Suspicious:          'bg-amber-500/15  text-amber-300  border-amber-500/30',
  Malicious:           'bg-red-500/15    text-red-400    border-red-500/30',
  'Network Unreachable':'bg-slate-500/15 text-slate-400  border-slate-500/30',
  'Suspicious Pattern':'bg-amber-500/20  text-amber-400  border-amber-500/40',
  'Confirmed Phishing':'bg-rose-500/20   text-rose-500   border-rose-500/40',
  Unknown:             'bg-slate-500/15  text-slate-400  border-slate-500/30',
}

const statusIcon: Record<string, string> = {
  Safe: '✅', Suspicious: '⚠️', Malicious: '🚫',
  'Network Unreachable': '🔌', 'Suspicious Pattern': '🕵️',
  'Confirmed Phishing': '☠️', Unknown: '❓',
}

const statusStyle: Record<string, string> = {
  Safe:                'text-emerald-400',
  Suspicious:          'text-amber-300',
  Malicious:           'text-red-400',
  'Network Unreachable':'text-slate-400',
  'Suspicious Pattern':'text-amber-400',
  'Confirmed Phishing':'text-rose-500',
  Unknown:             'text-slate-400',
}

function categoryScoreColor(score: number) {
  if (score <= 10) return 'text-emerald-400'
  if (score <= 30) return 'text-amber-300'
  return 'text-red-400'
}
function categoryBarColor(score: number) {
  if (score <= 10) return 'bg-emerald-500'
  if (score <= 30) return 'bg-amber-400'
  return 'bg-red-500'
}
function findingColor(f: string) {
  if (f.startsWith('✅')) return 'text-emerald-400'
  if (f.startsWith('❌')) return 'text-red-400'
  if (f.startsWith('⚠️')) return 'text-amber-300'
  if (f.startsWith('🚨')) return 'text-red-300'
  if (f.startsWith('ℹ️')) return 'text-slate-400'
  return 'text-slate-300'
}

function formatDate(iso: string) {
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function groupByDate(entries: HistoryEntry[]) {
  const groups: Record<string, HistoryEntry[]> = {}
  entries.forEach(e => {
    const day = new Date(e.timestamp).toLocaleDateString(undefined, {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    })
    if (!groups[day]) groups[day] = []
    groups[day].push(e)
  })
  return groups
}

/* ── Component ───────────────────────────────────────────────────────────────── */

export function ScanHistoryPage() {
  const [entries, setEntries] = useState<HistoryEntry[]>(() => getHistory())
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)

  const total     = entries.length
  const safe      = entries.filter(e => e.status === 'Safe').length
  const threats   = entries.filter(e => e.status !== 'Safe' && e.status !== 'Network Unreachable').length
  const urlSrc    = entries.filter(e => e.source === 'URL Scanner').length
  const imgSrc    = entries.filter(e => e.source === 'Image Processor').length

  const handleClear = () => {
    if (!confirmClear) { setConfirmClear(true); return }
    clearHistory()
    setEntries([])
    setConfirmClear(false)
  }

  const groups = groupByDate(entries)

  return (
    <section className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold text-slate-100">Scan History</h2>
          <p className="mt-1 text-slate-400">
            All previously analysed URLs — persisted locally in your browser.
          </p>
        </div>
        {entries.length > 0 && (
          <button
            type="button"
            onClick={handleClear}
            className={`shrink-0 rounded-xl px-4 py-2 text-sm font-semibold transition ${
              confirmClear
                ? 'bg-red-500 text-white hover:bg-red-400'
                : 'border border-red-500/30 text-red-400 hover:bg-red-500/10'
            }`}
          >
            {confirmClear ? 'Confirm Clear All' : 'Clear History'}
          </button>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        {[
          { label: 'Total Checked',    value: total,   color: 'text-cyan-400' },
          { label: 'Safe',             value: safe,    color: 'text-emerald-400' },
          { label: 'Threats Detected', value: threats, color: 'text-red-400' },
          { label: 'URL Scanner',      value: urlSrc,  color: 'text-cyan-300' },
          { label: 'Image Processor',  value: imgSrc,  color: 'text-violet-400' },
        ].map(s => (
          <div key={s.label} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-center">
            <p className={`text-3xl font-bold ${s.color}`}>{s.value}</p>
            <p className="mt-1 text-xs text-slate-400">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Empty state */}
      {entries.length === 0 && (
        <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] py-16 text-center">
          <p className="text-3xl mb-3">🗂️</p>
          <p className="text-slate-400 font-medium">No scans yet.</p>
          <p className="text-slate-500 text-sm mt-1">Scans from the URL Scanner and Image Processor will appear here automatically.</p>
        </div>
      )}

      {/* Grouped entries */}
      {Object.entries(groups).map(([day, dayEntries]) => (
        <div key={day} className="space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-500 border-b border-slate-800/60 pb-1">
            {day} · {dayEntries.length} scan(s)
          </h3>

          {dayEntries.map(entry => {
            const isExpanded = expandedId === entry.id
            const badge = statusBadge[entry.status] ?? statusBadge.Unknown
            const icon  = statusIcon[entry.status]  ?? '❓'
            const sStyle = statusStyle[entry.status] ?? 'text-slate-400'

            return (
              <div key={entry.id} className="rounded-xl border border-slate-800/60 bg-[#0f172a] overflow-hidden">
                {/* Row */}
                <button
                  type="button"
                  onClick={() => setExpandedId(isExpanded ? null : entry.id)}
                  className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-slate-800/30 transition"
                >
                  {/* Score badge */}
                  <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border font-bold text-lg ${badge}`}>
                    {entry.score}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="font-mono text-sm text-slate-200 truncate max-w-xs">{entry.url}</span>
                      <span className={`font-semibold text-sm ${sStyle}`}>{icon} {entry.status}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${
                        entry.confidence === 'High'   ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'   :
                        entry.confidence === 'Medium' ? 'bg-amber-500/15 text-amber-300 border-amber-500/30' :
                                                        'bg-slate-700/50 text-slate-400 border-slate-600/30'
                      }`}>{entry.confidence} confidence</span>
                      {entry.trusted && (
                        <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          ✅ Trusted
                        </span>
                      )}
                      <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800/60 text-slate-400 border border-slate-700/40">
                        {entry.source}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 truncate">{entry.summary}</p>
                  </div>

                  <div className="shrink-0 text-right">
                    <p className="text-xs text-slate-500">{formatDate(entry.timestamp)}</p>
                    <p className="text-xs text-cyan-400 mt-1">{isExpanded ? '▲ Collapse' : '▼ Full Report'}</p>
                  </div>
                </button>

                {/* Expanded report */}
                {isExpanded && (
                  <div className="border-t border-slate-800/60 px-5 py-5 space-y-5">
                    {entry.trusted && (
                      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-400">
                        ✅ Verified trusted domain. Deep scan was bypassed to prevent false positives.
                      </div>
                    )}

                    {entry.criticalFindings?.length > 0 && (
                      <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 space-y-1">
                        <p className="text-sm font-semibold text-red-400 mb-2">Critical Issues ({entry.criticalFindings.length})</p>
                        {entry.criticalFindings.map((f, i) => (
                          <p key={i} className="text-sm text-red-300">{f}</p>
                        ))}
                      </div>
                    )}

                    {entry.warningFindings?.length > 0 && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 space-y-1">
                        <p className="text-sm font-semibold text-amber-300 mb-2">Warnings ({entry.warningFindings.length})</p>
                        {entry.warningFindings.map((f, i) => (
                          <p key={i} className="text-sm text-amber-200">{f}</p>
                        ))}
                      </div>
                    )}

                    {/* Category cards */}
                    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                      {entry.categories?.map(cat => (
                        <div key={cat.name} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-2">
                              <span className="text-lg">{cat.icon}</span>
                              <span className="text-sm font-semibold text-slate-200">{cat.name}</span>
                            </div>
                            <span className={`text-sm font-bold ${categoryScoreColor(cat.score)}`}>
                              {cat.score}/100
                            </span>
                          </div>
                          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700/60 mb-3">
                            <div
                              className={`h-full rounded-full ${categoryBarColor(cat.score)}`}
                              style={{ width: `${Math.max(cat.score, 2)}%` }}
                            />
                          </div>
                          <div className="space-y-1.5 max-h-[200px] overflow-y-auto pr-1">
                            {cat.findings.map((f, i) => (
                              <p key={i} className={`text-xs leading-relaxed ${findingColor(f)}`}>{f}</p>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      ))}
    </section>
  )
}
