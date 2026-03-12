import { type FormEvent, useState, useRef } from 'react'
import { addToHistory } from '../lib/scanHistory'

/* ── Types ───────────────────────────────────────────────────────────────────── */



type CategoryResult = {
  name: string
  icon: string
  score: number
  findings: string[]
}

type ScanRecord = {
  id?: number
  url: string
  score: number
  status: 'Safe' | 'Suspicious' | 'Malicious' | 'Network Unreachable' | 'Suspicious Pattern' | 'Confirmed Phishing' | 'Unknown'
  confidence: 'High' | 'Medium' | 'Low'
  trusted: boolean
  categories: CategoryResult[]
  criticalFindings: string[]
  warningFindings: string[]
  summary: string
  timestamp: string
  cached?: boolean
  cachedAt?: string
  error?: boolean
  message?: string
}

type ImageProcessorResponse = {
  extractedText: string
  providedText: string
  suspiciousKeywords: string[]
  financialKeywords: string[]
  urlsFound: number
  scanResults: ScanRecord[]
  aiAnalysis?: {
    isScam: boolean | null
    confidence: 'High' | 'Medium' | 'Low' | 'None'
    reasoning: string
  } | null
}

/* ── Style helpers ───────────────────────────────────────────────────────────── */

const statusStyle: Record<string, string> = {
  Safe: 'text-emerald-400',
  Suspicious: 'text-amber-300',
  Malicious: 'text-red-400',
  'Network Unreachable': 'text-slate-400',
  'Suspicious Pattern': 'text-amber-400',
  'Confirmed Phishing': 'text-rose-500',
  Unknown: 'text-slate-400',
}

const statusBadge: Record<string, string> = {
  Safe: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  Suspicious: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  Malicious: 'bg-red-500/15 text-red-400 border-red-500/30',
  'Network Unreachable': 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  'Suspicious Pattern': 'bg-amber-500/20 text-amber-400 border-amber-500/40',
  'Confirmed Phishing': 'bg-rose-500/20 text-rose-500 border-rose-500/40',
  Unknown: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
}

const statusIcon: Record<string, string> = {
  Safe: '✅',
  Suspicious: '⚠️',
  Malicious: '🚫',
  'Network Unreachable': '🔌',
  'Suspicious Pattern': '🕵️',
  'Confirmed Phishing': '☠️',
  Unknown: '❓',
}

const confidenceStyle: Record<string, string> = {
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



/* ── Component ───────────────────────────────────────────────────────────────── */

export function ImageProcessorPage() {
  const [text, setText] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (f: File | null) => {
    if (previewUrl) URL.revokeObjectURL(previewUrl)
    if (f) {
      setFile(f)
      setPreviewUrl(URL.createObjectURL(f))
    } else {
      setFile(null)
      setPreviewUrl(null)
    }
  }

  const removeFile = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl)
    setFile(null)
    setPreviewUrl(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const [response, setResponse] = useState<ImageProcessorResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [expandedUrl, setExpandedUrl] = useState<string | null>(null)

  const handleProcess = async (event: FormEvent) => {
    event.preventDefault()
    if (!text.trim() && !file) return
    
    setError(null)
    setLoading(true)
    setResponse(null)
    
    try {
      const formData = new FormData()
      if (text.trim()) formData.append('text', text.trim())
      if (file) formData.append('image', file)

      const res = await fetch('/api/scan-image', {
        method: 'POST',
        body: formData, // fetch will auto-set the correct multipart/form-data boundary
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error ?? 'Processing failed')

      setResponse(data)
      // Persist each individual URL scan to history
      const now = new Date().toISOString()
      if (data.scanResults) {
        for (const scan of data.scanResults) {
          if (!scan.error) {
            addToHistory({
              source:          'Image Processor',
              url:              scan.url,
              score:            scan.score ?? 0,
              status:           scan.status ?? 'Unknown',
              confidence:       scan.confidence ?? 'Low',
              trusted:          scan.trusted ?? false,
              categories:       scan.categories ?? [],
              criticalFindings: scan.criticalFindings ?? [],
              warningFindings:  scan.warningFindings ?? [],
              summary:          scan.summary ?? '',
              timestamp:        now,
            })
          }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Processing failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-slate-100">Image & Text Processor</h2>
        <p className="mt-1 text-slate-400">
          Upload screenshots or paste text to extract and seamlessly analyze embedded URLs using our robust heuristics and threat intel databases.
        </p>
      </div>

      {/* Input form */}
      <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-6">
        <form onSubmit={handleProcess} className="flex flex-col gap-4">
          <div>
            <p className="mb-2 text-sm font-medium text-slate-300">Image Upload</p>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
              className="w-full text-slate-300 file:mr-4 file:rounded-full file:border-0 file:bg-cyan-500/10 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-cyan-400 hover:file:bg-cyan-500/20"
            />
          </div>
          
          {/* Image Preview */}
          {previewUrl && (
            <div className="relative w-full rounded-xl border border-slate-700/60 bg-slate-900/60 overflow-hidden">
              <img
                src={previewUrl}
                alt="Attached preview"
                className="max-h-64 w-full object-contain"
              />
              <div className="absolute top-2 right-2 flex items-center gap-2">
                <span className="text-xs font-medium text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 backdrop-blur-sm">
                  {file?.name || 'Pasted Image'}
                </span>
                <button
                  type="button"
                  onClick={removeFile}
                  className="flex items-center justify-center h-6 w-6 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/40 transition text-xs font-bold"
                  title="Remove image"
                >
                  ✕
                </button>
              </div>
            </div>
          )}

          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium text-slate-300">Paste Text, Image URL, or Image</p>
            </div>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              onPaste={(e) => {
                const items = e.clipboardData?.items
                if (!items) return
                for (const item of items) {
                  if (item.type.includes('image')) {
                    const pastedFile = item.getAsFile()
                    if (pastedFile) {
                      handleFileChange(pastedFile)
                      e.preventDefault() // prevent pasting image blob string representation
                      break
                    }
                  }
                }
              }}
              placeholder="Paste email content, an SMS, a direct image URL, or paste an image directly (Ctrl+V) here..."
              rows={4}
              className="w-full rounded-xl border border-slate-700/60 bg-slate-900/60 px-4 py-3 text-slate-100 outline-none ring-cyan-400/40 placeholder:text-slate-500 focus:ring"
            />
          </div>
          
          <button
            type="submit"
            disabled={loading || (!text.trim() && !file)}
            className="self-start rounded-xl bg-cyan-500 px-6 py-3 text-sm font-bold text-white transition hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                Processing…
              </span>
            ) : 'Process Content'}
          </button>
        </form>
        {error && (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}
      </div>

      {/* Loading indicator */}
      {loading && (
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-6">
          <div className="flex items-center gap-4">
            <div className="h-10 w-10 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
            <div>
              <p className="font-semibold text-cyan-400">Processing Image & Text…</p>
              <p className="mt-1 text-sm text-slate-400">
                Running Tesseract OCR for text extraction and simultaneously scanning identified URLs.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Results Overview */}
      {response && !loading && (() => {
        const successfulScans = response.scanResults.filter((s: ScanRecord) => !s.error)
        const overallScore = successfulScans.length > 0
          ? Math.max(...successfulScans.map((s: ScanRecord) => s.score))
          : 0
        const threatCount = successfulScans.filter(
          (s: ScanRecord) => s.status !== 'Safe' && s.status !== 'Network Unreachable' && !s.trusted
        ).length
        const overallStatus =
          overallScore <= 20 ? 'Safe' :
          overallScore <= 50 ? 'Suspicious' : 'Malicious'
        const overallBg =
          overallStatus === 'Safe'       ? 'bg-emerald-500/10 border-emerald-500/30' :
          overallStatus === 'Suspicious' ? 'bg-amber-500/10  border-amber-500/30'  :
                                           'bg-red-500/10    border-red-500/30'
        const overallTextColor =
          overallStatus === 'Safe'       ? 'text-emerald-400' :
          overallStatus === 'Suspicious' ? 'text-amber-300'   : 'text-red-400'
        const overallBarColor =
          overallStatus === 'Safe'       ? 'bg-emerald-500' :
          overallStatus === 'Suspicious' ? 'bg-amber-400'   : 'bg-red-500'
        const overallIcon =
          overallStatus === 'Safe' ? '✅' : overallStatus === 'Suspicious' ? '⚠️' : '🚫'
        const linksScanned = response.scanResults.length
        const linksFound   = Math.max(response.urlsFound ?? 0, linksScanned)

        return (
        <div className="space-y-6">

          {/* ── Overall Risk Score Banner ─────────────────────────────── */}
          {successfulScans.length > 0 && (
            <div className={`rounded-xl border p-5 ${overallBg}`}>
              <div className="flex flex-col sm:flex-row sm:items-center gap-4">
                {/* Big score circle */}
                <div className={`flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl border-2 font-black text-3xl mx-auto sm:mx-0 ${
                  overallStatus === 'Safe'       ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400' :
                  overallStatus === 'Suspicious' ? 'border-amber-400/50  bg-amber-400/10  text-amber-300'  :
                                                   'border-red-500/50    bg-red-500/10    text-red-400'
                }`}>
                  {overallScore}
                </div>

                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xl">{overallIcon}</span>
                    <h3 className={`text-xl font-bold ${overallTextColor}`}>
                      Overall Risk: {overallStatus}
                    </h3>
                  </div>
                  <p className="text-sm text-slate-400 mb-3">
                    {threatCount === 0
                      ? `All ${linksScanned} link(s) appear safe — no threats detected.`
                      : `${threatCount} of ${linksScanned} link(s) flagged as suspicious or malicious.`}
                    {response.aiAnalysis?.isScam === true && ' AI analysis also flagged this content as suspicious.'}
                  </p>
                  {/* Score bar */}
                  <div className="h-2 w-full overflow-hidden rounded-full bg-slate-700/60">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${overallBarColor}`}
                      style={{ width: `${Math.max(overallScore, 2)}%` }}
                    />
                  </div>
                  <div className="mt-1 flex justify-between text-xs text-slate-500">
                    <span>0 — Safe</span>
                    <span>50 — Suspicious</span>
                    <span>100 — Malicious</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-center">
              <p className="text-3xl font-bold text-cyan-400">{linksFound}</p>
              <p className="mt-1 text-xs text-slate-400">URLs Detected</p>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-center">
              <p className="text-3xl font-bold text-emerald-400">{linksScanned}</p>
              <p className="mt-1 text-xs text-slate-400">Links Tested</p>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-center">
              <p className="text-3xl font-bold text-amber-400">{response.suspiciousKeywords.length}</p>
              <p className="mt-1 text-xs text-slate-400">Suspicious Keywords</p>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 text-center">
              <p className="text-3xl font-bold text-amber-400">{response.financialKeywords.length}</p>
              <p className="mt-1 text-xs text-slate-400">Financial Keywords</p>
            </div>
          </div>

          {/* AI Content Analysis Results */}
          {response.aiAnalysis && (
            <div className={`rounded-xl border p-5 ${
              response.aiAnalysis.isScam === null
                ? 'bg-slate-800/50 border-slate-600/30'
                : response.aiAnalysis.isScam 
                  ? 'bg-red-500/10 border-red-500/30' 
                  : 'bg-emerald-500/10 border-emerald-500/30'
            }`}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xl">
                    {response.aiAnalysis.isScam === null ? 'ℹ️' : response.aiAnalysis.isScam ? '🚨' : '✅'}
                  </span>
                  <h3 className={`text-lg font-bold ${
                    response.aiAnalysis.isScam === null ? 'text-slate-300' : response.aiAnalysis.isScam ? 'text-red-400' : 'text-emerald-400'
                  }`}>
                    AI Risk Evaluation: {response.aiAnalysis.isScam === null ? 'Disabled (API key not configured)' : response.aiAnalysis.isScam ? 'Suspicious (Possible phishing context)' : 'Safe'}
                  </h3>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                  response.aiAnalysis.confidence === 'High' ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' :
                  response.aiAnalysis.confidence === 'Medium' ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30' :
                  'bg-slate-700/50 text-slate-400 border border-slate-600/30'
                }`}>
                  AI Confidence Level: {response.aiAnalysis.confidence}
                </span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">
                {response.aiAnalysis.reasoning}
              </p>
            </div>
          )}

          {/* Extracted Text */}
          {response.extractedText && (
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-2">OCR Extracted Text</h3>
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800/60 max-h-48 overflow-y-auto">
                <pre className="text-xs text-slate-400 whitespace-pre-wrap font-mono">
                  {response.extractedText}
                </pre>
              </div>
            </div>
          )}

          {/* Keywords Flags */}
          {(response.suspiciousKeywords.length > 0 || response.financialKeywords.length > 0) && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-5">
              <h3 className="text-sm font-semibold text-amber-400 mb-2">Keyword Flags</h3>
              <div className="flex flex-wrap gap-2">
                {response.financialKeywords.map(kw => (
                  <span key={kw} className="px-2 py-1 text-xs font-medium rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    💰 {kw}
                  </span>
                ))}
                {response.suspiciousKeywords.map(kw => (
                  <span key={kw} className="px-2 py-1 text-xs font-medium rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    ⚠️ {kw}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* URL Scan Results */}
          <div className="space-y-4">
            <h3 className="text-xl font-bold text-slate-100">URL Analytics</h3>
            {response.scanResults.length === 0 ? (
              <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] py-8 text-center text-slate-400">
                No URLs were detected in the source content.
              </div>
            ) : response.scanResults.map((scan, idx) => {
              const uStatus = scan.status || 'Unknown'
              const uScore = scan.score || 0
              const isExpanded = expandedUrl === scan.url + idx

              return (
              <div key={idx} className="rounded-xl border border-slate-800/60 bg-[#0f172a] overflow-hidden">
                <button
                  type="button"
                  onClick={() => setExpandedUrl(isExpanded ? null : scan.url + idx)}
                  className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-slate-800/30 transition"
                >
                  {/* Score badge */}
                  <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border font-bold text-lg ${statusBadge[uStatus] || statusBadge.Unknown}`}>
                    {scan.error ? 'Err' : uScore}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="font-mono text-sm text-slate-200 truncate max-w-[340px]">{scan.url}</span>
                      
                      {!scan.error && (
                        <>
                          <span className={`font-semibold text-sm ${statusStyle[uStatus]}`}>
                            {statusIcon[uStatus]} {uStatus}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${confidenceStyle[scan.confidence] || confidenceStyle.Low}`}>
                            {scan.confidence || 'Low'} confidence
                          </span>
                          {/* Trusted badge */}
                          {scan.trusted && (
                            <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              ✅ Trusted Domain
                            </span>
                          )}
                        </>
                      )}
                      {scan.error && (
                        <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                          Scan Failed
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 truncate">
                      {scan.error ? scan.message : scan.summary}
                    </p>
                  </div>

                  {!scan.error && (
                    <div className="shrink-0 text-right">
                      <p className="text-xs text-slate-500">{scan.timestamp}</p>
                      <p className="text-xs text-cyan-400 mt-1">{isExpanded ? '▲ Collapse' : '▼ Expand'}</p>
                    </div>
                  )}
                </button>

                {/* Expanded detail panel */}
                {!scan.error && isExpanded && (
                  <div className="border-t border-slate-800/60 px-5 py-5 space-y-5">
                    
                    {/* Trusted domain shortcut notice */}
                    {scan.trusted && (
                      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-400">
                        ✅ This is a verified trusted domain. Deep scan was bypassed to prevent false positives.
                      </div>
                    )}

                    {/* Critical findings */}
                    {scan.criticalFindings && scan.criticalFindings.length > 0 && (
                      <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 space-y-1">
                        <p className="text-sm font-semibold text-red-400 mb-2">Critical Issues ({scan.criticalFindings.length})</p>
                        {scan.criticalFindings.map((f, i) => (
                          <p key={i} className="text-sm text-red-300">{f}</p>
                        ))}
                      </div>
                    )}

                    {/* Warnings */}
                    {scan.warningFindings && scan.warningFindings.length > 0 && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 space-y-1">
                        <p className="text-sm font-semibold text-amber-300 mb-2">Warnings ({scan.warningFindings.length})</p>
                        {scan.warningFindings.map((f, i) => (
                          <p key={i} className="text-sm text-amber-200">{f}</p>
                        ))}
                      </div>
                    )}

                    {/* Category breakdown */}
                    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                      {scan.categories && scan.categories.map((cat) => (
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

                  </div>
                )}
              </div>
            )})}
          </div>

        </div>
        )
      })()}

    </section>
  )
}
