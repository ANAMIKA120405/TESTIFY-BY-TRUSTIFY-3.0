import { type ChangeEvent, useState } from 'react'

type VaultFile = {
  id: number
  name: string
  sizeMB: number
  uploadedAt: string
}

type PasswordEntry = {
  service: string
  username: string
  strength: number
  reused: boolean
  lastChanged: string
}

const passwords: PasswordEntry[] = [
  { service: 'AWS Console', username: 'admin@company.io', strength: 92, reused: false, lastChanged: '2026-01-15' },
  { service: 'GitHub', username: 'dev@company.io', strength: 55, reused: true, lastChanged: '2025-11-03' },
  { service: 'HubSpot', username: 'sales@company.io', strength: 30, reused: true, lastChanged: '2025-08-22' },
  { service: 'Jira', username: 'ops@company.io', strength: 78, reused: false, lastChanged: '2026-02-01' },
]

function StrengthBar({ value }: { value: number }) {
  const color = value >= 80 ? 'bg-emerald-400' : value >= 50 ? 'bg-amber-400' : 'bg-red-400'
  const label = value >= 80 ? 'Strong' : value >= 50 ? 'Moderate' : 'Weak'
  const labelColor = value >= 80 ? 'text-emerald-400' : value >= 50 ? 'text-amber-400' : 'text-red-400'
  return (
    <div className="flex items-center gap-3">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-700/60">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className={`w-16 text-right text-xs font-medium ${labelColor}`}>{label}</span>
    </div>
  )
}

export function SecurityBoxPage() {
  const [tab, setTab] = useState<'vault' | 'passwords'>('vault')
  const [files, setFiles] = useState<VaultFile[]>([])
  const [dragging, setDragging] = useState(false)

  const totalFiles = files.length
  const storageMB = parseFloat(files.reduce((acc, f) => acc + f.sizeMB, 0).toFixed(2))
  const encryptedCount = files.length

  const addFiles = (list: FileList | null) => {
    if (!list) return
    Array.from(list).forEach((file) => {
      setFiles((prev) => [
        ...prev,
        {
          id: Date.now() + Math.random(),
          name: file.name,
          sizeMB: parseFloat((file.size / (1024 * 1024)).toFixed(2)),
          uploadedAt: new Date().toISOString().slice(0, 10),
        },
      ])
    })
  }

  const handleFileInput = (e: ChangeEvent<HTMLInputElement>) => {
    addFiles(e.target.files)
    e.target.value = ''
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    addFiles(e.dataTransfer.files)
  }

  const weakPasswords = passwords.filter((p) => p.strength < 50).length
  const reusedPasswords = passwords.filter((p) => p.reused).length

  return (
    <section className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-slate-100">Security Box</h2>
        <p className="mt-1 text-slate-400">Encrypted file storage and password health monitoring</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => setTab('vault')}
          className={[
            'rounded-xl px-5 py-2.5 text-sm font-semibold transition',
            tab === 'vault'
              ? 'bg-cyan-500 text-white'
              : 'border border-slate-700/60 bg-[#0f172a] text-slate-300 hover:bg-slate-800',
          ].join(' ')}
        >
          File Vault
        </button>
        <button
          type="button"
          onClick={() => setTab('passwords')}
          className={[
            'rounded-xl px-5 py-2.5 text-sm font-semibold transition',
            tab === 'passwords'
              ? 'bg-cyan-500 text-white'
              : 'border border-slate-700/60 bg-[#0f172a] text-slate-300 hover:bg-slate-800',
          ].join(' ')}
        >
          Password Health
        </button>
      </div>

      {tab === 'vault' && (
        <>
          {/* Stat cards */}
          <div className="grid grid-cols-3 gap-4">
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <p className="text-sm text-slate-400">Total Files</p>
              <p className="mt-2 text-4xl font-bold text-slate-100">{totalFiles}</p>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <p className="text-sm text-slate-400">Storage Used</p>
              <p className="mt-2 text-4xl font-bold text-cyan-400">{storageMB} MB</p>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <p className="text-sm text-slate-400">Encrypted</p>
              <p className="mt-2 text-4xl font-bold text-emerald-400">{encryptedCount}</p>
            </div>
          </div>

          {/* Drop zone */}
          <label
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            className={[
              'flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed py-16 transition',
              dragging
                ? 'border-cyan-400 bg-cyan-500/10'
                : 'border-slate-700/60 bg-[#0f172a] hover:border-slate-600',
            ].join(' ')}
          >
            <span className="text-6xl">📁</span>
            <p className="mt-4 text-lg font-bold text-slate-100">Drop files here to encrypt and upload</p>
            <p className="mt-1 text-sm text-slate-400">or click to browse files</p>
            <span className="mt-5 rounded-xl bg-cyan-500 px-8 py-3 text-sm font-bold text-white hover:bg-cyan-400 transition">
              Select Files
            </span>
            <p className="mt-3 text-xs text-slate-500">Max file size: 100MB • Supports all file types</p>
            <input type="file" multiple className="sr-only" onChange={handleFileInput} />
          </label>

          {/* Encrypted Files list */}
          <div>
            <h3 className="mb-3 text-xl font-bold text-slate-100">Encrypted Files</h3>
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] overflow-hidden">
              {files.length === 0 ? (
                <p className="py-12 text-center text-sm text-slate-500">No files uploaded yet</p>
              ) : (
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-800/60">
                      {['File Name', 'Size', 'Uploaded', 'Action'].map((h) => (
                        <th key={h} className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-slate-500">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {files.map((f) => (
                      <tr key={f.id} className="border-b border-slate-800/40 last:border-0">
                        <td className="px-5 py-3.5 font-mono text-xs text-slate-200">{f.name}</td>
                        <td className="px-5 py-3.5 text-slate-400">{f.sizeMB} MB</td>
                        <td className="px-5 py-3.5 text-slate-400">{f.uploadedAt}</td>
                        <td className="px-5 py-3.5">
                          <button
                            type="button"
                            onClick={() => setFiles((prev) => prev.filter((x) => x.id !== f.id))}
                            className="text-xs text-red-400 underline underline-offset-2 hover:text-red-300"
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </>
      )}

      {tab === 'passwords' && (
        <>
          {/* Password stat cards */}
          <div className="grid grid-cols-3 gap-4">
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <p className="text-sm text-slate-400">Total Passwords</p>
              <p className="mt-2 text-4xl font-bold text-slate-100">{passwords.length}</p>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <p className="text-sm text-slate-400">Weak Passwords</p>
              <p className="mt-2 text-4xl font-bold text-red-400">{weakPasswords}</p>
            </div>
            <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
              <p className="text-sm text-slate-400">Reused</p>
              <p className="mt-2 text-4xl font-bold text-amber-400">{reusedPasswords}</p>
            </div>
          </div>

          {/* Password list */}
          <div>
            <h3 className="mb-3 text-xl font-bold text-slate-100">Password Health</h3>
            <div className="space-y-3">
              {passwords.map((pw) => (
                <div
                  key={pw.service}
                  className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5"
                >
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div>
                      <p className="font-semibold text-slate-100">{pw.service}</p>
                      <p className="text-xs text-slate-500">{pw.username}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {pw.reused && (
                        <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-xs text-amber-400">
                          Reused
                        </span>
                      )}
                      <span className="text-xs text-slate-500">Changed {pw.lastChanged}</span>
                    </div>
                  </div>
                  <StrengthBar value={pw.strength} />
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </section>
  )
}
