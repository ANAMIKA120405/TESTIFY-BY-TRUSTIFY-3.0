import { type FormEvent, useState } from 'react'
import { addToHistory } from '../lib/scanHistory'

/* ── Types ───────────────────────────────────────────────────────────────────── */

type CategoryResult = {
  name: string
  icon: string
  score: number
  findings: string[]
}

type ScanRecord = {
  id: number
  url: string
  score: number
  status: 'Safe' | 'Suspicious' | 'Malicious' | 'Network Unreachable' | 'Suspicious Pattern' | 'Confirmed Phishing'
  confidence: 'High' | 'Medium' | 'Low'
  trusted: boolean
  categories: CategoryResult[]
  criticalFindings: string[]
  warningFindings: string[]
  summary: string
  timestamp: string
  cached?: boolean
  cachedAt?: string
}

/* ── Style helpers ───────────────────────────────────────────────────────────── */

const statusStyle: Record<ScanRecord['status'], string> = {
  Safe: 'text-emerald-400',
  Suspicious: 'text-amber-300',
  Malicious: 'text-red-400',
  'Network Unreachable': 'text-slate-400',
  'Suspicious Pattern': 'text-amber-400',
  'Confirmed Phishing': 'text-rose-500',
}

const statusBadge: Record<ScanRecord['status'], string> = {
  Safe: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  Suspicious: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  Malicious: 'bg-red-500/15 text-red-400 border-red-500/30',
  'Network Unreachable': 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  'Suspicious Pattern': 'bg-amber-500/20 text-amber-400 border-amber-500/40',
  'Confirmed Phishing': 'bg-rose-500/20 text-rose-500 border-rose-500/40',
}

const statusIcon: Record<ScanRecord['status'], string> = {
  Safe: '✅',
  Suspicious: '⚠️',
  Malicious: '🚫',
  'Network Unreachable': '🔌',
  'Suspicious Pattern': '🕵️',
  'Confirmed Phishing': '☠️',
}

const confidenceStyle: Record<ScanRecord['confidence'], string> = {
  High:   'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30',
  Medium: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
  Low:    'bg-slate-700/50 text-slate-400 border border-slate-600/30',
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

function findingColor(finding: string) {
  if (finding.startsWith('✅')) return 'text-emerald-400'
  if (finding.startsWith('❌')) return 'text-red-400'
  if (finding.startsWith('⚠️')) return 'text-amber-300'
  if (finding.startsWith('🚨')) return 'text-red-300'
  if (finding.startsWith('ℹ️')) return 'text-slate-400'
  if (finding.startsWith('  ')) return 'text-slate-500'
  return 'text-slate-300'
}

const LOADING_STEPS = [
  '🚨 Threat Intel', '🔤 Homograph', '🎭 Typosquatting',
  '🌐 DNS', '🔒 SSL/TLS', '🛡️ Headers',
  '🔗 Redirects', '📄 Page Content', '📋 WHOIS', '🔍 Heuristics',
]

/* ── Component ───────────────────────────────────────────────────────────────── */

export function UrlScannerPage() {
  const [url, setUrl]           = useState('')
  const [scans, setScans]       = useState<ScanRecord[]>([])
  const [error, setError]       = useState<string | null>(null)
  const [loading, setLoading]   = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)

  const totalScans  = scans.length
  const safeUrls    = scans.filter((s) => s.status === 'Safe').length
  const threatsFound = scans.filter((s) => s.status !== 'Safe').length

  const handleScan = async (event: FormEvent) => {
    event.preventDefault()
    if (!url.trim()) return
    setError(null)
    setLoading(true)
    try {
      const res = await fetch('/api/scan-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error ?? 'Scan failed')

      const record: ScanRecord = {
        id:              Date.now(),
        url:             data.url,
        score:           data.threatScore,
        status:          data.riskLevel as ScanRecord['status'],
        confidence:      (data.confidence as ScanRecord['confidence']) ?? 'Medium',
        trusted:         data.trusted ?? false,
        categories:      data.categories ?? [],
        criticalFindings: data.criticalFindings ?? [],
        warningFindings: data.warningFindings ?? [],
        summary:         data.summary ?? '',
        timestamp:       new Date(data.timestamp).toLocaleString(),
        cached:          data.cached ?? false,
        cachedAt:        data.cachedAt ? new Date(data.cachedAt).toLocaleString() : undefined,
      }
      setScans((prev) => [record, ...prev].slice(0, 20))
      setExpandedId(record.id)
      setUrl('')
      addToHistory({
        source:          'URL Scanner',
        url:             record.url,
        score:           record.score,
        status:          record.status,
        confidence:      record.confidence,
        trusted:         record.trusted,
        categories:      record.categories,
        criticalFindings: record.criticalFindings,
        warningFindings: record.warningFindings,
        summary:         record.summary,
        timestamp:       new Date().toISOString(),
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-slate-100">URL Scanner</h2>
        <p className="mt-1 text-slate-400">
          4-layer security analysis — Threat Intel, DNS, SSL/TLS, headers, redirects, content scanning &amp; heuristics
        </p>
      </div>

      {/* Scan form */}
      <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-6">
        <p className="mb-2 text-sm font-medium text-slate-300">Enter URL to scan</p>
        <form onSubmit={handleScan} className="flex gap-3">
          <input
            type="url"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="flex-1 rounded-xl border border-slate-700/60 bg-slate-900/60 px-4 py-3 text-slate-100 outline-none ring-cyan-400/40 placeholder:text-slate-500 focus:ring"
          />
          <button
            type="submit"
            disabled={loading}
            className="rounded-xl bg-cyan-500 px-6 py-3 text-sm font-bold text-white transition hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                Scanning…
              </span>
            ) : 'Scan URL'}
          </button>
        </form>
        {error && (
          <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {/* Quick stats */}
        <div className="mt-5 grid grid-cols-3 gap-4">
          {[
            { label: 'Total Scans', value: totalScans, color: 'text-cyan-400' },
            { label: 'Safe URLs',   value: safeUrls,   color: 'text-emerald-400' },
            { label: 'Threats Found', value: threatsFound, color: 'text-red-400' },
          ].map((s) => (
            <div key={s.label} className="rounded-xl border border-slate-800/60 bg-slate-900/40 py-4 text-center">
              <p className={`text-3xl font-bold ${s.color}`}>{s.value}</p>
              <p className="mt-1 text-xs text-slate-400">{s.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Loading indicator */}
      {loading && (
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-6">
          <div className="flex items-center gap-4">
            <div className="h-10 w-10 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
            <div>
              <p className="font-semibold text-cyan-400">4-Layer Deep Security Scan in Progress…</p>
              <p className="mt-1 text-sm text-slate-400">
                Running threat intelligence, DNS, SSL/TLS, content scan, headers, redirects, WHOIS &amp; heuristics
              </p>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
            {LOADING_STEPS.map((step) => (
              <div key={step} className="flex items-center gap-2 rounded-lg bg-slate-800/60 px-3 py-2 text-xs text-slate-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400" />
                {step}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      <div className="space-y-4">
        <h3 className="text-xl font-bold text-slate-100">Scan Results</h3>

        {scans.length === 0 && !loading && (
          <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] py-14 text-center">
            <p className="text-2xl mb-2">🛡️</p>
            <p className="text-slate-400">No scans yet. Enter a URL above to start your security analysis.</p>
          </div>
        )}

        {scans.map((scan) => {
          const isExpanded = scan.id === expandedId

          return (
            <div key={scan.id} className="rounded-xl border border-slate-800/60 bg-[#0f172a] overflow-hidden">

              {/* Header row */}
              <button
                type="button"
                onClick={() => setExpandedId(isExpanded ? null : scan.id)}
                className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-slate-800/30 transition"
              >
                {/* Score badge */}
                <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border font-bold text-lg ${statusBadge[scan.status]}`}>
                  {scan.score}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm text-slate-200 truncate max-w-[340px]">{scan.url}</span>
                    {/* Risk level */}
                    <span className={`font-semibold text-sm ${statusStyle[scan.status]}`}>
                      {statusIcon[scan.status]} {scan.status}
                    </span>
                    {/* Confidence badge */}
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${confidenceStyle[scan.confidence]}`}>
                      {scan.confidence} confidence
                    </span>
                    {/* Trusted badge */}
                    {scan.trusted && (
                      <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        ✅ Trusted Domain
                      </span>
                    )}
                    {/* Cache badge */}
                    {scan.cached && (
                      <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                        ⚡ Cached
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-slate-400">{scan.summary}</p>
                </div>

                <div className="shrink-0 text-right">
                  <p className="text-xs text-slate-500">{scan.timestamp}</p>
                  <p className="text-xs text-cyan-400 mt-1">{isExpanded ? '▲ Collapse' : '▼ Expand'}</p>
                </div>
              </button>

              {/* Expanded detail panel */}
              {isExpanded && (
                <div className="border-t border-slate-800/60 px-5 py-5 space-y-5">

                  {/* Cached notice */}
                  {scan.cached && (
                    <div className="rounded-lg border border-purple-500/30 bg-purple-500/5 px-4 py-2 text-xs text-purple-400">
                      ⚡ This result was served from cache. Last scanned at: {scan.cachedAt}. Re-run in 30 minutes for a fresh scan.
                    </div>
                  )}

                  {/* Trusted domain shortcut notice */}
                  {scan.trusted && (
                    <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-400">
                      ✅ This is a verified trusted domain. Deep scan was bypassed to prevent false positives.
                    </div>
                  )}

                  {/* Critical findings */}
                  {scan.criticalFindings.length > 0 && (
                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 space-y-1">
                      <p className="text-sm font-semibold text-red-400 mb-2">Critical Issues ({scan.criticalFindings.length})</p>
                      {scan.criticalFindings.map((f, i) => (
                        <p key={i} className="text-sm text-red-300">{f}</p>
                      ))}
                    </div>
                  )}

                  {/* Warnings */}
                  {scan.warningFindings.length > 0 && (
                    <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 space-y-1">
                      <p className="text-sm font-semibold text-amber-300 mb-2">Warnings ({scan.warningFindings.length})</p>
                      {scan.warningFindings.map((f, i) => (
                        <p key={i} className="text-sm text-amber-200">{f}</p>
                      ))}
                    </div>
                  )}

                  {/* Category breakdown */}
                  <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                    {scan.categories.map((cat) => (
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

                        {/* Score bar */}
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700/60 mb-3">
                          <div
                            className={`h-full rounded-full transition-all ${categoryBarColor(cat.score)}`}
                            style={{ width: `${Math.max(cat.score, 2)}%` }}
                          />
                        </div>

                        {/* Findings */}
                        <div className="space-y-1.5 max-h-[200px] overflow-y-auto pr-1">
                          {cat.findings.map((finding, i) => (
                            <p key={i} className={`text-xs leading-relaxed ${findingColor(finding)}`}>
                              {finding}
                            </p>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Overall threat score bar */}
                  <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-sm font-semibold text-slate-300">Overall Threat Score</span>
                      <div className="flex items-center gap-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${confidenceStyle[scan.confidence]}`}>
                          {scan.confidence} confidence
                        </span>
                        <span className={`text-xl font-bold ${statusStyle[scan.status]}`}>
                          {scan.score}/100
                        </span>
                      </div>
                    </div>
                    <div className="h-3 w-full overflow-hidden rounded-full bg-slate-700/50">
                      <div
                        className={`h-full rounded-full transition-all ${
                          ['Suspicious', 'Suspicious Pattern'].includes(scan.status) ? 'bg-amber-400' :
                          ['Malicious', 'Confirmed Phishing'].includes(scan.status) ? 'bg-red-500' :
                          scan.status === 'Safe' ? 'bg-emerald-500' : 'bg-slate-500'
                        }`}
                        style={{ width: `${Math.max(scan.score, 2)}%` }}
                      />
                    </div>
                    <div className="mt-2 flex justify-between text-xs text-slate-500">
                      <span>0 — Safe</span>
                      <span>21</span>
                      <span>51</span>
                      <span>100 — Malicious</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}
