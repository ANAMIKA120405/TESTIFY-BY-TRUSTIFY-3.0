import { useState } from 'react'

// All /api calls are proxied to Express via Vite — no hardcoded port needed.
const BACKEND = ''

type Tool = {
  name: string
  description: string
  icon: string
  category: string
  inputLabel: string
  placeholder: string
}

type PortResult = {
  port: number
  service: string
  status: 'open' | 'closed'
}

type PortScanData = {
  target: string
  resolvedIP: string
  scannedPorts: PortResult[]
  exposureScore: number
  exposureLevel: string
  timestamp: string
}

type HashData = {
  originalTextLength: number
  algorithm: string
  hash: string
  timestamp: string
}

type SslData = {
  domain: string
  httpsAvailable: boolean
  subject: string | null
  issuer: string | null
  validFrom: string | null
  validTo: string | null
  isExpired: boolean | null
  riskLevel: 'Secure' | 'Medium Risk' | 'High Risk'
  error?: string
  timestamp: string
}

type MxRecord = { exchange: string; priority: number }

type DnsData = {
  domain: string
  records: {
    A: string[]
    AAAA: string[]
    MX: MxRecord[]
    NS: string[]
  }
  timestamp: string
}

type WhoisData = {
  domain: string
  registrar: string | null
  country: string | null
  creationDate: string | null
  expirationDate: string | null
  updatedDate: string | null
  domainAgeInDays: number | null
  daysUntilExpiration: number | null
  isRecentlyRegistered: boolean
  isExpired: boolean
  riskLevel: 'Low Risk' | 'Medium Risk' | 'High Risk'
  timestamp: string
}

type IpGeoData = {
  ip: string
  country: string | null
  region: string | null
  city: string | null
  latitude: number | null
  longitude: number | null
  isp: string | null
  organization: string | null
  riskLevel: 'Valid' | 'Invalid IP'
  error?: string
  timestamp: string
}

const HASH_ALGORITHMS = ['md5', 'sha1', 'sha256'] as const

const tools: Tool[] = [
  { name: 'Port Scanner', description: 'Scan network ports to identify open services and potential vulnerabilities', icon: '⚡', category: 'Network', inputLabel: 'Target Host', placeholder: 'example.com' },
  { name: 'Hash Generator', description: 'Generate cryptographic hashes (MD5, SHA-1, SHA-256) for data integrity', icon: '#', category: 'Cryptography', inputLabel: 'Plain Text', placeholder: 'Enter text to hash' },
  { name: 'SSL Checker', description: 'Verify SSL/TLS certificates and identify security issues', icon: '🔒', category: 'Security', inputLabel: 'Domain', placeholder: 'secure.example.com' },
  { name: 'DNS Lookup', description: 'Query DNS records and resolve domain information', icon: '🌐', category: 'Network', inputLabel: 'Hostname', placeholder: 'api.example.com' },
  { name: 'WHOIS Lookup', description: 'Retrieve domain registration and ownership information', icon: '📋', category: 'Intelligence', inputLabel: 'Domain', placeholder: 'trustify.io' },
  { name: 'IP Geolocation', description: 'Locate geographical position and details of IP addresses', icon: '📍', category: 'Intelligence', inputLabel: 'IP Address', placeholder: '8.8.8.8' },
]

const exposureLevelStyle: Record<string, string> = {
  'Low Exposure':    'text-emerald-400',
  'Medium Exposure': 'text-amber-300',
  'High Exposure':   'text-red-400',
}

export function ToolsPage() {
  const [active, setActive] = useState<string | null>(null)
  const [inputs, setInputs] = useState<Record<string, string>>({})
  const [outputs, setOutputs] = useState<Record<string, string>>({})
  const [portData, setPortData] = useState<PortScanData | null>(null)
  const [portError, setPortError] = useState<string | null>(null)
  const [portLoading, setPortLoading] = useState(false)
  const [hashData, setHashData] = useState<HashData | null>(null)
  const [hashError, setHashError] = useState<string | null>(null)
  const [hashLoading, setHashLoading] = useState(false)
  const [hashAlgo, setHashAlgo] = useState<'md5' | 'sha1' | 'sha256'>('sha256')
  const [sslData, setSslData] = useState<SslData | null>(null)
  const [sslError, setSslError] = useState<string | null>(null)
  const [sslLoading, setSslLoading] = useState(false)
  const [dnsData, setDnsData] = useState<DnsData | null>(null)
  const [dnsError, setDnsError] = useState<string | null>(null)
  const [dnsLoading, setDnsLoading] = useState(false)
  const [whoisData, setWhoisData] = useState<WhoisData | null>(null)
  const [whoisError, setWhoisError] = useState<string | null>(null)
  const [whoisLoading, setWhoisLoading] = useState(false)
  const [ipGeoData, setIpGeoData] = useState<IpGeoData | null>(null)
  const [ipGeoError, setIpGeoError] = useState<string | null>(null)
  const [ipGeoLoading, setIpGeoLoading] = useState(false)

  const selectedTool = tools.find((t) => t.name === active)

  async function runPortScan() {
    const target = (inputs['Port Scanner'] ?? '').trim()
    if (!target) return
    setPortData(null)
    setPortError(null)
    setPortLoading(true)
    try {
      const res = await fetch(`${BACKEND}/api/scan-ports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      })
      const data = await res.json() as PortScanData & { error?: string; message?: string }
      if (!res.ok) {
        setPortError(data.message ?? data.error ?? `Server error ${res.status}`)
      } else {
        setPortData(data)
      }
    } catch {
      setPortError('Could not reach the backend. Make sure the server is running on port 4000.\n\nStart it with: cd backend && node server.js')
    } finally {
      setPortLoading(false)
    }
  }

  async function runHashGenerator() {
    const text = (inputs['Hash Generator'] ?? '').trim()
    if (!text) return
    setHashData(null)
    setHashError(null)
    setHashLoading(true)
    try {
      const res = await fetch(`${BACKEND}/api/generate-hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, algorithm: hashAlgo }),
      })
      const data = await res.json() as HashData & { error?: string }
      if (!res.ok) {
        setHashError(data.error ?? `Server error ${res.status}`)
      } else {
        setHashData(data)
      }
    } catch {
      setHashError('Could not reach the backend. Make sure the server is running on port 4000.')
    } finally {
      setHashLoading(false)
    }
  }

  async function runSSLCheck() {
    const domain = (inputs['SSL Checker'] ?? '').trim()
    if (!domain) return
    setSslData(null)
    setSslError(null)
    setSslLoading(true)
    try {
      const res = await fetch(`${BACKEND}/api/check-ssl`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      })
      const data = await res.json() as SslData & { error?: string; message?: string }
      if (!res.ok) {
        setSslError(data.message ?? data.error ?? `Server error ${res.status}`)
      } else {
        setSslData(data)
      }
    } catch {
      setSslError('Could not reach the backend. Make sure the server is running.')
    } finally {
      setSslLoading(false)
    }
  }

  async function runDnsLookup() {
    const domain = (inputs['DNS Lookup'] ?? '').trim()
    if (!domain) return
    setDnsData(null)
    setDnsError(null)
    setDnsLoading(true)
    try {
      const res = await fetch(`${BACKEND}/api/dns-lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      })
      const data = await res.json() as DnsData & { error?: string }
      if (!res.ok) {
        setDnsError(data.error ?? `Server error ${res.status}`)
      } else {
        setDnsData(data)
      }
    } catch {
      setDnsError('Could not reach the backend. Make sure the server is running.')
    } finally {
      setDnsLoading(false)
    }
  }

  async function runWhoisLookup() {
    const domain = (inputs['WHOIS Lookup'] ?? '').trim()
    if (!domain) return
    setWhoisData(null)
    setWhoisError(null)
    setWhoisLoading(true)
    try {
      const res = await fetch(`${BACKEND}/api/whois-lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      })
      const data = await res.json() as WhoisData & { error?: string }
      if (!res.ok) {
        setWhoisError(data.error ?? `Server error ${res.status}`)
      } else {
        setWhoisData(data)
      }
    } catch {
      setWhoisError('Could not reach the backend. Make sure the server is running.')
    } finally {
      setWhoisLoading(false)
    }
  }

  async function runIpGeolocation() {
    const ip = (inputs['IP Geolocation'] ?? '').trim()
    if (!ip) return
    setIpGeoData(null)
    setIpGeoError(null)
    setIpGeoLoading(true)
    try {
      const res = await fetch(`${BACKEND}/api/ip-geolocation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      })
      const data = await res.json() as IpGeoData & { error?: string }
      if (!res.ok) {
        setIpGeoError(data.error ?? `Server error ${res.status}`)
      } else {
        setIpGeoData(data)
      }
    } catch {
      setIpGeoError('Could not reach the backend. Make sure the server is running.')
    } finally {
      setIpGeoLoading(false)
    }
  }

  function runGenericTool(name: string) {
    setOutputs((p) => ({
      ...p,
      [name]: `${name} completed at ${new Date().toLocaleTimeString()} — no anomalies found.`,
    }))
  }

  function isRealTool(name: string) {
    return ['Port Scanner', 'Hash Generator', 'SSL Checker', 'DNS Lookup', 'WHOIS Lookup', 'IP Geolocation'].includes(name)
  }

  return (
    <section className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-slate-100">Security Tools</h2>
        <p className="mt-1 text-slate-400">Professional-grade security testing and analysis tools</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {tools.map((tool) => (
          <article
            key={tool.name}
            onClick={() => {
              setActive(active === tool.name ? null : tool.name)
              setPortData(null)
              setPortError(null)
              setHashData(null)
              setHashError(null)
              setSslData(null)
              setSslError(null)
              setDnsData(null)
              setDnsError(null)
              setWhoisData(null)
              setWhoisError(null)
              setIpGeoData(null)
              setIpGeoError(null)
            }}
            className={[
              'cursor-pointer rounded-2xl border p-6 transition select-none',
              active === tool.name
                ? 'border-cyan-400/40 bg-cyan-500/10'
                : 'border-slate-800/60 bg-[#0f172a] hover:border-slate-700',
            ].join(' ')}
          >
            <div className="flex items-start gap-4">
              <span className="text-3xl leading-none">{tool.icon}</span>
              <div className="flex-1">
                <h3 className="text-lg font-bold text-slate-100">{tool.name}</h3>
                <p className="mt-1 text-sm text-slate-400">{tool.description}</p>
                <span className="mt-3 inline-block rounded-full bg-cyan-500/15 px-3 py-0.5 text-xs font-medium text-cyan-300">
                  {tool.category}
                </span>
              </div>
            </div>
          </article>
        ))}
      </div>

      {/* ── Expanded tool panel ─────────────────────────────────────────── */}
      {selectedTool && (
        <div className="rounded-2xl border border-cyan-400/20 bg-[#0f172a] p-6 space-y-4">
          <div className="flex items-center gap-3">
            <span className="text-2xl">{selectedTool.icon}</span>
            <h3 className="text-xl font-bold text-slate-100">{selectedTool.name}</h3>
          </div>

          {/* Input row */}
          <div>
            <label className="block text-sm text-slate-400 mb-2">{selectedTool.inputLabel}</label>
            <div className="flex gap-3">
              <input
                className="flex-1 rounded-xl border border-slate-700/60 bg-slate-900/60 px-4 py-2.5 text-sm text-slate-100 outline-none ring-cyan-400/40 placeholder:text-slate-500 focus:ring"
                placeholder={selectedTool.placeholder}
                value={inputs[selectedTool.name] ?? ''}
                onChange={(e) => setInputs((p) => ({ ...p, [selectedTool.name]: e.target.value }))}
                onKeyDown={(e) => {
                  if (e.key !== 'Enter') return
                  if (selectedTool.name === 'Port Scanner') runPortScan()
                  else if (selectedTool.name === 'Hash Generator') runHashGenerator()
                  else if (selectedTool.name === 'SSL Checker') runSSLCheck()
                  else if (selectedTool.name === 'DNS Lookup') runDnsLookup()
                  else if (selectedTool.name === 'WHOIS Lookup') runWhoisLookup()
                  else if (selectedTool.name === 'IP Geolocation') runIpGeolocation()
                  else runGenericTool(selectedTool.name)
                }}
              />
              {/* Algorithm selector — only for Hash Generator */}
              {selectedTool.name === 'Hash Generator' && (
                <select
                  value={hashAlgo}
                  onChange={(e) => setHashAlgo(e.target.value as typeof hashAlgo)}
                  className="rounded-xl border border-slate-700/60 bg-slate-900/60 px-3 py-2.5 text-sm text-slate-100 outline-none focus:ring focus:ring-cyan-400/40 uppercase"
                >
                  {HASH_ALGORITHMS.map((a) => (
                    <option key={a} value={a}>{a.toUpperCase()}</option>
                  ))}
                </select>
              )}
              <button
                type="button"
                disabled={
                  (portLoading && selectedTool.name === 'Port Scanner') ||
                  (hashLoading && selectedTool.name === 'Hash Generator') ||
                  (sslLoading && selectedTool.name === 'SSL Checker') ||
                  (dnsLoading && selectedTool.name === 'DNS Lookup') ||
                  (whoisLoading && selectedTool.name === 'WHOIS Lookup') ||
                  (ipGeoLoading && selectedTool.name === 'IP Geolocation')
                }
                onClick={() => {
                  if (selectedTool.name === 'Port Scanner') runPortScan()
                  else if (selectedTool.name === 'Hash Generator') runHashGenerator()
                  else if (selectedTool.name === 'SSL Checker') runSSLCheck()
                  else if (selectedTool.name === 'DNS Lookup') runDnsLookup()
                  else if (selectedTool.name === 'WHOIS Lookup') runWhoisLookup()
                  else if (selectedTool.name === 'IP Geolocation') runIpGeolocation()
                  else runGenericTool(selectedTool.name)
                }}
                className="rounded-xl bg-cyan-500 px-5 py-2.5 text-sm font-bold text-white hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed min-w-[80px]"
              >
                {(
                  (portLoading && selectedTool.name === 'Port Scanner') ||
                  (hashLoading && selectedTool.name === 'Hash Generator') ||
                  (sslLoading && selectedTool.name === 'SSL Checker') ||
                  (dnsLoading && selectedTool.name === 'DNS Lookup') ||
                  (whoisLoading && selectedTool.name === 'WHOIS Lookup') ||
                  (ipGeoLoading && selectedTool.name === 'IP Geolocation')
                ) ? 'Running…' : 'Run'}
              </button>
            </div>
          </div>

          {/* ── Port Scanner results ──────────────────────────────────── */}
          {selectedTool.name === 'Port Scanner' && (
            <>
              {portError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400 whitespace-pre-wrap">
                  {portError}
                </div>
              )}

              {portData && (
                <div className="space-y-4">
                  {/* Summary bar */}
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    {[
                      { label: 'Target',         value: portData.target,    color: 'text-slate-100' },
                      { label: 'Resolved IP',    value: portData.resolvedIP, color: 'text-cyan-400' },
                      { label: 'Exposure Score', value: String(portData.exposureScore), color: 'text-slate-100' },
                      { label: 'Exposure Level', value: portData.exposureLevel,
                        color: exposureLevelStyle[portData.exposureLevel] ?? 'text-slate-100' },
                    ].map((s) => (
                      <div key={s.label} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3">
                        <p className="text-xs text-slate-500">{s.label}</p>
                        <p className={`mt-1 text-sm font-semibold truncate ${s.color}`}>{s.value}</p>
                      </div>
                    ))}
                  </div>

                  {/* Port table */}
                  <div className="rounded-xl border border-slate-800/60 overflow-hidden">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-slate-800/60 bg-slate-900/40">
                          {['Port', 'Service', 'Status'].map((h) => (
                            <th key={h} className="px-5 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {portData.scannedPorts.map((p) => (
                          <tr key={p.port} className="border-b border-slate-800/40 last:border-0">
                            <td className="px-5 py-3 text-slate-300 font-mono">{p.port}</td>
                            <td className="px-5 py-3 text-slate-300">{p.service}</td>
                            <td className="px-5 py-3">
                              <span
                                className={[
                                  'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold',
                                  p.status === 'open'
                                    ? 'bg-emerald-500/15 text-emerald-400'
                                    : 'bg-slate-700/40 text-slate-500',
                                ].join(' ')}
                              >
                                <span className={`h-1.5 w-1.5 rounded-full ${p.status === 'open' ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                                {p.status === 'open' ? 'Open' : 'Closed'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <p className="text-xs text-slate-600">
                    Scanned at {new Date(portData.timestamp).toLocaleString()}
                  </p>
                </div>
              )}
            </>
          )}

          {/* ── Hash Generator results ────────────────────────────────── */}
          {selectedTool.name === 'Hash Generator' && (
            <>
              {hashError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  {hashError}
                </div>
              )}
              {hashData && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                    {[
                      { label: 'Algorithm',    value: hashData.algorithm.toUpperCase(), color: 'text-cyan-400' },
                      { label: 'Input Length', value: `${hashData.originalTextLength} chars`, color: 'text-slate-100' },
                      { label: 'Generated At', value: new Date(hashData.timestamp).toLocaleTimeString(), color: 'text-slate-300' },
                    ].map((s) => (
                      <div key={s.label} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3">
                        <p className="text-xs text-slate-500">{s.label}</p>
                        <p className={`mt-1 text-sm font-semibold ${s.color}`}>{s.value}</p>
                      </div>
                    ))}
                  </div>
                  <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                    <p className="text-xs text-slate-500 mb-2">Hash Output</p>
                    <p className="font-mono text-sm text-emerald-400 break-all select-all">{hashData.hash}</p>
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── SSL Checker results ────────────────────────────────────── */}
          {selectedTool.name === 'SSL Checker' && (
            <>
              {sslError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  {sslError}
                </div>
              )}
              {sslData && (() => {
                const riskColor =
                  sslData.riskLevel === 'Secure'      ? 'text-emerald-400' :
                  sslData.riskLevel === 'Medium Risk' ? 'text-amber-300'   : 'text-red-400'
                const riskBg =
                  sslData.riskLevel === 'Secure'      ? 'bg-emerald-500/15 border-emerald-500/30' :
                  sslData.riskLevel === 'Medium Risk' ? 'bg-amber-500/15 border-amber-500/30'     : 'bg-red-500/15 border-red-500/30'
                return (
                  <div className="space-y-4">
                    {/* Risk badge */}
                    <div className={`inline-flex items-center gap-2 rounded-xl border px-4 py-2 ${riskBg}`}>
                      <span className={`text-lg ${riskColor}`}>
                        {sslData.riskLevel === 'Secure' ? '✅' : sslData.riskLevel === 'Medium Risk' ? '⚠️' : '🚫'}
                      </span>
                      <span className={`font-bold ${riskColor}`}>{sslData.riskLevel}</span>
                    </div>

                    {/* Summary cards */}
                    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                      {[
                        { label: 'Domain',       value: sslData.domain,                               color: 'text-slate-100' },
                        { label: 'HTTPS',        value: sslData.httpsAvailable ? 'Available' : 'Not Available', color: sslData.httpsAvailable ? 'text-emerald-400' : 'text-red-400' },
                        { label: 'Issuer',       value: sslData.issuer ?? '—',                        color: 'text-cyan-400'  },
                        { label: 'Subject (CN)', value: sslData.subject ?? '—',                       color: 'text-slate-100' },
                        { label: 'Valid From',   value: sslData.validFrom ? new Date(sslData.validFrom).toLocaleDateString() : '—', color: 'text-slate-300' },
                        { label: 'Valid To',     value: sslData.validTo   ? new Date(sslData.validTo).toLocaleDateString()   : '—',
                          color: sslData.isExpired ? 'text-red-400' : 'text-emerald-400' },
                      ].map((s) => (
                        <div key={s.label} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3">
                          <p className="text-xs text-slate-500">{s.label}</p>
                          <p className={`mt-1 text-sm font-semibold truncate ${s.color}`}>{s.value}</p>
                        </div>
                      ))}
                    </div>

                    {sslData.isExpired && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-sm text-amber-300">
                        ⚠️ Certificate has expired. Renew it to restore a secure connection.
                      </div>
                    )}

                    {sslData.error && (
                      <p className="text-xs text-slate-500">Note: {sslData.error}</p>
                    )}

                    <p className="text-xs text-slate-600">
                      Checked at {new Date(sslData.timestamp).toLocaleString()}
                    </p>
                  </div>
                )
              })()}
            </>
          )}

          {/* ── DNS Lookup results ─────────────────────────────────── */}
          {selectedTool.name === 'DNS Lookup' && (
            <>
              {dnsError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  {dnsError}
                </div>
              )}
              {dnsData && (
                <div className="space-y-4">
                  {/* Record type sections */}
                  {(['A', 'AAAA', 'NS'] as const).map((type) => (
                    <div key={type} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
                        {type} Records
                        <span className="ml-2 rounded-full bg-slate-700/60 px-2 py-0.5 text-slate-400">
                          {dnsData.records[type].length}
                        </span>
                      </p>
                      {dnsData.records[type].length === 0 ? (
                        <p className="text-sm text-slate-600 italic">No records found</p>
                      ) : (
                        <div className="flex flex-wrap gap-2">
                          {dnsData.records[type].map((v, i) => (
                            <span key={i} className="font-mono text-sm text-emerald-400 bg-emerald-500/10 rounded-lg px-3 py-1">
                              {v}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}

                  {/* MX Records — separate layout to show priority */}
                  <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
                    <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
                      MX Records
                      <span className="ml-2 rounded-full bg-slate-700/60 px-2 py-0.5 text-slate-400">
                        {dnsData.records.MX.length}
                      </span>
                    </p>
                    {dnsData.records.MX.length === 0 ? (
                      <p className="text-sm text-slate-600 italic">No records found</p>
                    ) : (
                      <div className="space-y-1">
                        {[...dnsData.records.MX]
                          .sort((a, b) => a.priority - b.priority)
                          .map((mx, i) => (
                            <div key={i} className="flex items-center gap-3">
                              <span className="w-10 text-right font-mono text-xs text-amber-300">{mx.priority}</span>
                              <span className="font-mono text-sm text-cyan-400">{mx.exchange}</span>
                            </div>
                          ))}
                      </div>
                    )}
                  </div>

                  <p className="text-xs text-slate-600">
                    Queried at {new Date(dnsData.timestamp).toLocaleString()}
                  </p>
                </div>
              )}
            </>
          )}

          {/* ── WHOIS Lookup results ─────────────────────────────────── */}
          {selectedTool.name === 'WHOIS Lookup' && (
            <>
              {whoisError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  {whoisError}
                </div>
              )}
              {whoisData && (() => {
                const riskColor =
                  whoisData.riskLevel === 'Low Risk'    ? 'text-emerald-400' :
                  whoisData.riskLevel === 'Medium Risk' ? 'text-amber-300'   : 'text-red-400'
                const riskBg =
                  whoisData.riskLevel === 'Low Risk'    ? 'bg-emerald-500/15 border-emerald-500/30' :
                  whoisData.riskLevel === 'Medium Risk' ? 'bg-amber-500/15 border-amber-500/30'     : 'bg-red-500/15 border-red-500/30'
                const riskIcon =
                  whoisData.riskLevel === 'Low Risk' ? '✅' :
                  whoisData.riskLevel === 'Medium Risk' ? '⚠️' : '🚨'

                return (
                  <div className="space-y-4">
                    {/* Risk badge */}
                    <div className={`inline-flex items-center gap-2 rounded-xl border px-4 py-2 ${riskBg}`}>
                      <span className="text-lg">{riskIcon}</span>
                      <span className={`font-bold ${riskColor}`}>{whoisData.riskLevel}</span>
                    </div>

                    {/* Info cards */}
                    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                      {[
                        { label: 'Domain',       value: whoisData.domain,    color: 'text-slate-100' },
                        { label: 'Registrar',    value: whoisData.registrar ?? '—', color: 'text-cyan-400' },
                        { label: 'Country',      value: whoisData.country   ?? '—', color: 'text-slate-300' },
                        { label: 'Created',      value: whoisData.creationDate   ? new Date(whoisData.creationDate).toLocaleDateString()   : '—', color: 'text-slate-300' },
                        { label: 'Expires',      value: whoisData.expirationDate ? new Date(whoisData.expirationDate).toLocaleDateString() : '—', color: whoisData.isExpired ? 'text-red-400' : 'text-slate-300' },
                        { label: 'Last Updated', value: whoisData.updatedDate    ? new Date(whoisData.updatedDate).toLocaleDateString()    : '—', color: 'text-slate-300' },
                      ].map((s) => (
                        <div key={s.label} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3">
                          <p className="text-xs text-slate-500">{s.label}</p>
                          <p className={`mt-1 text-sm font-semibold truncate ${s.color}`}>{s.value}</p>
                        </div>
                      ))}
                    </div>

                    {/* Age + expiry stats */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3">
                        <p className="text-xs text-slate-500">Domain Age</p>
                        <p className="mt-1 text-sm font-semibold text-slate-100">
                          {whoisData.domainAgeInDays !== null
                            ? whoisData.domainAgeInDays >= 365
                              ? `${Math.floor(whoisData.domainAgeInDays / 365)} yr${Math.floor(whoisData.domainAgeInDays / 365) !== 1 ? 's' : ''}`
                              : `${whoisData.domainAgeInDays} days`
                            : '—'}
                        </p>
                      </div>
                      <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3">
                        <p className="text-xs text-slate-500">Days Until Expiry</p>
                        <p className={`mt-1 text-sm font-semibold ${
                          whoisData.isExpired ? 'text-red-400' :
                          (whoisData.daysUntilExpiration ?? 999) <= 30 ? 'text-amber-300' : 'text-emerald-400'
                        }`}>
                          {whoisData.isExpired ? 'Expired' : whoisData.daysUntilExpiration !== null ? `${whoisData.daysUntilExpiration} days` : '—'}
                        </p>
                      </div>
                    </div>

                    {whoisData.isRecentlyRegistered && (
                      <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm text-red-300">
                        🚨 Domain registered less than 90 days ago — commonly associated with phishing or fraud.
                      </div>
                    )}

                    <p className="text-xs text-slate-600">
                      Queried at {new Date(whoisData.timestamp).toLocaleString()}
                    </p>
                  </div>
                )
              })()}
            </>
          )}

          {/* ── IP Geolocation results ────────────────────────────────── */}
          {selectedTool.name === 'IP Geolocation' && (
            <>
              {ipGeoError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  {ipGeoError}
                </div>
              )}
              {ipGeoData && (
                <div className="space-y-4">
                  {/* Status badge */}
                  <div className={`inline-flex items-center gap-2 rounded-xl border px-4 py-2 ${
                    ipGeoData.riskLevel === 'Valid'
                      ? 'bg-emerald-500/15 border-emerald-500/30'
                      : 'bg-red-500/15 border-red-500/30'
                  }`}>
                    <span className="text-lg">{ipGeoData.riskLevel === 'Valid' ? '📍' : '❌'}</span>
                    <span className={`font-bold ${ipGeoData.riskLevel === 'Valid' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {ipGeoData.riskLevel}
                    </span>
                  </div>

                  {ipGeoData.riskLevel === 'Valid' ? (
                    <>
                      {/* Info cards */}
                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                        {[
                          { label: 'IP Address',   value: ipGeoData.ip,            color: 'text-slate-100' },
                          { label: 'Country',      value: ipGeoData.country ?? '—', color: 'text-cyan-400'  },
                          { label: 'Region',       value: ipGeoData.region  ?? '—', color: 'text-slate-300' },
                          { label: 'City',         value: ipGeoData.city    ?? '—', color: 'text-slate-300' },
                          { label: 'ISP',          value: ipGeoData.isp      ?? '—', color: 'text-slate-300' },
                          { label: 'Organization', value: ipGeoData.organization ?? '—', color: 'text-slate-300' },
                        ].map((s) => (
                          <div key={s.label} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3">
                            <p className="text-xs text-slate-500">{s.label}</p>
                            <p className={`mt-1 text-sm font-semibold truncate ${s.color}`}>{s.value}</p>
                          </div>
                        ))}
                      </div>

                      {/* Coordinates */}
                      {ipGeoData.latitude !== null && ipGeoData.longitude !== null && (
                        <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 flex items-center gap-4">
                          <span className="text-2xl">🗺️</span>
                          <div>
                            <p className="text-xs text-slate-500 mb-1">Coordinates</p>
                            <p className="font-mono text-sm text-emerald-400">
                              {ipGeoData.latitude}, {ipGeoData.longitude}
                            </p>
                            <a
                              href={`https://www.openstreetmap.org/?mlat=${ipGeoData.latitude}&mlon=${ipGeoData.longitude}&zoom=12`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="mt-1 inline-block text-xs text-cyan-400 hover:underline"
                            >
                              View on map ↗
                            </a>
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <p className="text-sm text-slate-400">{ipGeoData.error ?? 'The IP address could not be geolocated.'}</p>
                  )}

                  <p className="text-xs text-slate-600">
                    Queried at {new Date(ipGeoData.timestamp).toLocaleString()}
                  </p>
                </div>
              )}
            </>
          )}

          {/* ── Generic tool output ───────────────────────────────────── */}
          {!isRealTool(selectedTool.name) && outputs[selectedTool.name] && (
            <p className="rounded-lg border border-slate-700/40 bg-slate-900/40 px-4 py-2.5 text-sm text-slate-300">
              {outputs[selectedTool.name]}
            </p>
          )}
        </div>
      )}
    </section>
  )
}
