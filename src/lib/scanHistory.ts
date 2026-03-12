/* ── Scan History Store ─────────────────────────────────────────────────────
 * Persists scan results to localStorage so the History page can display them.
 * Works for both URL Scanner and Image Processor scans.
 * ─────────────────────────────────────────────────────────────────────────── */

export type CategoryResult = {
  name: string
  icon: string
  score: number
  findings: string[]
}

export type HistoryEntry = {
  id: string
  source: 'URL Scanner' | 'Image Processor'
  url: string
  score: number
  status: string
  confidence: string
  trusted: boolean
  categories: CategoryResult[]
  criticalFindings: string[]
  warningFindings: string[]
  summary: string
  timestamp: string   // ISO string
}

const STORAGE_KEY = 'testify_scan_history'
const MAX_ENTRIES = 200

function loadRaw(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    return JSON.parse(raw) as HistoryEntry[]
  } catch {
    return []
  }
}

export function getHistory(): HistoryEntry[] {
  return loadRaw()
}

export function addToHistory(entry: Omit<HistoryEntry, 'id'>): void {
  const entries = loadRaw()
  const newEntry: HistoryEntry = {
    ...entry,
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
  }
  const updated = [newEntry, ...entries].slice(0, MAX_ENTRIES)
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  } catch {
    // storage quota exceeded — drop oldest half and retry
    const trimmed = [newEntry, ...entries.slice(0, MAX_ENTRIES / 2)]
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed))
  }
}

export function clearHistory(): void {
  localStorage.removeItem(STORAGE_KEY)
}
