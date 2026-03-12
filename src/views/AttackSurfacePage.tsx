import { useState } from 'react'

type NodeType = {
  id: string
  name: string
  x: number
  y: number
  risk: 'Low' | 'Medium' | 'High' | 'Critical'
  details: string
}

type Vulnerability = { id: number; name: string; severity: string; asset: string }

const riskColor: Record<NodeType['risk'], string> = {
  Critical: '#EF4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22d3ee',
}

export function AttackSurfacePage() {
  const [domain, setDomain] = useState('')
  const [nodes, setNodes] = useState<NodeType[]>([])
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])

  const activeNode = nodes.find((n) => n.id === activeNodeId) ?? null

  const stats = [
    { label: 'Total Assets', value: nodes.length, colorClass: 'text-slate-100' },
    { label: 'Critical Risk', value: nodes.filter((n) => n.risk === 'Critical').length, colorClass: 'text-red-400' },
    { label: 'High Risk', value: nodes.filter((n) => n.risk === 'High').length, colorClass: 'text-orange-400' },
    { label: 'Exposed Ports', value: 0, colorClass: 'text-yellow-400' },
  ]

  function handleScan() {
    if (!domain.trim()) return
    // placeholder: domain scan would populate nodes/vulnerabilities
    setNodes([])
    setVulnerabilities([])
    setActiveNodeId(null)
  }

  const sevStyle: Record<string, string> = {
    Critical: 'text-red-400',
    High: 'text-orange-400',
    Medium: 'text-yellow-300',
    Low: 'text-cyan-400',
  }

  return (
    <section className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-slate-100">Attack Surface Map</h2>
        <p className="mt-1 text-slate-400">Visualize your infrastructure and identify exposed assets</p>
      </div>

      {/* Domain scan input */}
      <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-4">
        <div className="flex gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            placeholder="Enter domain to scan (e.g., example.com)"
            className="flex-1 rounded-lg border border-slate-700/60 bg-slate-800/60 px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30"
          />
          <button
            onClick={handleScan}
            className="rounded-lg bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-900 hover:bg-cyan-400 transition-colors"
          >
            Scan Domain
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        {stats.map((s) => (
          <div key={s.label} className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
            <p className="text-sm text-slate-400">{s.label}</p>
            <p className={`mt-2 text-4xl font-bold ${s.colorClass}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Network Topology + Asset Details */}
      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        {/* Map canvas */}
        <div className="rounded-2xl border border-slate-800/60 bg-[#0f172a] overflow-hidden">
          <div className="px-5 pt-5 pb-3">
            <h3 className="text-lg font-bold text-slate-100">Network Topology</h3>
          </div>

          <div className="relative h-[360px] overflow-auto mx-4 mb-0 rounded-lg border border-slate-800/60 bg-[#0d1117]">
            {nodes.length === 0 ? (
              <>
                <svg className="absolute inset-0 h-full w-full" viewBox="0 0 760 360" preserveAspectRatio="none">
                  {Array.from({ length: 20 }, (_, i) => (
                    <line key={`v${i}`} x1={i * 40} y1={0} x2={i * 40} y2={360} stroke="rgba(148,163,184,0.06)" />
                  ))}
                  {Array.from({ length: 10 }, (_, i) => (
                    <line key={`h${i}`} x1={0} y1={i * 40} x2={760} y2={i * 40} stroke="rgba(148,163,184,0.06)" />
                  ))}
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <p className="text-sm text-slate-500">No assets discovered yet</p>
                </div>
              </>
            ) : (
              <svg className="absolute inset-0 h-full w-full" style={{ minWidth: 720 }} viewBox="0 0 760 360">
                {Array.from({ length: 20 }, (_, i) => (
                  <line key={`v${i}`} x1={i * 40} y1={0} x2={i * 40} y2={360} stroke="rgba(148,163,184,0.06)" />
                ))}
                {Array.from({ length: 10 }, (_, i) => (
                  <line key={`h${i}`} x1={0} y1={i * 40} x2={760} y2={i * 40} stroke="rgba(148,163,184,0.06)" />
                ))}
                {nodes.map((node) => {
                  const isActive = node.id === activeNodeId
                  return (
                    <g key={node.id} onClick={() => setActiveNodeId(node.id)} style={{ cursor: 'pointer' }}>
                      <circle
                        cx={node.x} cy={node.y} r={isActive ? 18 : 14}
                        fill={riskColor[node.risk]}
                        opacity={isActive ? 1 : 0.85}
                        stroke={isActive ? '#22d3ee' : 'rgba(255,255,255,0.15)'}
                        strokeWidth={isActive ? 2.5 : 1}
                      />
                      {isActive && (
                        <circle cx={node.x} cy={node.y} r={26} fill="none" stroke="#22d3ee" strokeWidth={1} opacity={0.4} />
                      )}
                      <text x={node.x + 22} y={node.y + 5} fill="#e2e8f0" fontSize={12} fontFamily="inherit">{node.name}</text>
                    </g>
                  )
                })}
              </svg>
            )}
          </div>

          {/* Legend */}
          <div className="flex flex-wrap justify-center gap-6 px-5 py-4">
            {(['Low', 'Medium', 'High', 'Critical'] as const).map((r) => (
              <span key={r} className="flex items-center gap-2 text-xs text-slate-300">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: riskColor[r] }} />
                {r} Risk
              </span>
            ))}
          </div>
        </div>

        {/* Asset Details panel */}
        <aside className="rounded-2xl border border-slate-800/60 bg-[#0f172a] p-5">
          <h3 className="text-lg font-bold text-slate-100">Asset Details</h3>
          {activeNode ? (
            <div className="mt-4 space-y-4">
              <h4 className="text-xl font-bold text-slate-100">{activeNode.name}</h4>
              <p className="text-sm text-slate-400">{activeNode.details}</p>
              <div className="rounded-xl border border-slate-700/50 bg-slate-900/40 p-3">
                <p className="text-xs text-slate-500">Risk Level</p>
                <p className={`mt-1 text-lg font-bold ${sevStyle[activeNode.risk]}`}>{activeNode.risk}</p>
              </div>
            </div>
          ) : (
            <div className="flex h-[calc(100%-2.5rem)] min-h-[280px] items-center justify-center">
              <p className="text-sm text-slate-500">Click on a node to view details</p>
            </div>
          )}
        </aside>
      </div>

      {/* Recent Vulnerabilities */}
      <div>
        <h3 className="mb-3 text-xl font-bold text-slate-100">Recent Vulnerabilities</h3>
        <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] overflow-hidden">
          {vulnerabilities.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-500">No vulnerabilities detected</p>
          ) : (
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-800/60">
                  {['Vulnerability', 'Severity', 'Affected Asset'].map((h) => (
                    <th key={h} className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-slate-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {vulnerabilities.map((v) => (
                  <tr key={v.id} className="border-b border-slate-800/40 last:border-0">
                    <td className="px-5 py-3.5 text-slate-200">{v.name}</td>
                    <td className={`px-5 py-3.5 font-semibold ${sevStyle[v.severity]}`}>{v.severity}</td>
                    <td className="px-5 py-3.5 text-slate-400">{v.asset}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </section>
  )
}
