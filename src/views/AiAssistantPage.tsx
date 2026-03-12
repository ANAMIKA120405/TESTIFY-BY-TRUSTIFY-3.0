import { useEffect, useRef, useState } from 'react'

type Role = 'assistant' | 'user'

type Message = {
  id: number
  role: Role
  content: string
  timestamp: Date | string
}

const BACKEND_URL = '/api/ai-chat'

const SUGGESTIONS = [
  'What are the most common cybersecurity threats?',
  'How can I improve my password security?',
  'Explain what a DDoS attack is',
  'What is zero-trust security?',
  'How do I protect against phishing?',
]

const WELCOME: Message = {
  id: 0,
  role: 'assistant',
  content: `Hello! I'm your AI Security Assistant, powered by Groq's lightning-fast LLM inference.

I can help you:
• Analyze and interpret security scan results
• Interpret scan results and findings
• Provide remediation recommendations
• Answer questions about your security posture

How can I assist you today?`,
  timestamp: new Date(),
}

function formatTime(d: Date | string) {
  const dateObj = typeof d === 'string' ? new Date(d) : d
  return dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function TypingDots() {
  return (
    <span className="inline-flex items-center gap-1">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-2 w-2 rounded-full bg-cyan-400 animate-bounce"
          style={{ animationDelay: `${i * 0.15}s` }}
        />
      ))}
    </span>
  )
}

export function AiAssistantPage() {
  const [messages, setMessages] = useState<Message[]>([WELCOME])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const nextId = useRef(1)

  // Load messages safely on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem('testify_ai_chat')
      if (saved) {
        const parsed = JSON.parse(saved)
        if (Array.isArray(parsed) && parsed.length > 0) {
          setMessages(parsed)
          nextId.current = Math.max(...parsed.map((m: Message) => m.id)) + 1
        }
      }
    } catch {
      localStorage.removeItem('testify_ai_chat')
    }
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // Save messages to localStorage whenever they change
  useEffect(() => {
    localStorage.setItem('testify_ai_chat', JSON.stringify(messages))
  }, [messages])

  async function sendMessage(text: string) {
    const trimmed = text.trim()
    if (!trimmed || loading) return

    const userMsg: Message = {
      id: nextId.current++,
      role: 'user',
      content: trimmed,
      timestamp: new Date(),
    }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setError(null)
    setLoading(true)

    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }

    try {
      const payload = [...messages, userMsg]
        .filter((m) => m.id !== 0)
        .map((m) => ({ role: m.role, content: m.content }))

      const res = await fetch(BACKEND_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ messages: payload }),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.error || `HTTP ${res.status}`)
      }

      const data = await res.json()

      const botMessage: Message = {
        id: nextId.current++,
        role: 'assistant',
        content: data.content || 'I encountered an error processing that request.',
        timestamp: new Date(),
      }
      setMessages((prev) => [...prev, botMessage])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage(input)
    }
  }

  function handleInput(e: React.ChangeEvent<HTMLTextAreaElement>) {
    setInput(e.target.value)
    const el = e.target
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`
  }

  return (
    <section className="flex flex-col gap-6 h-full">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-slate-100">AI Security Assistant</h2>
        <p className="mt-1 text-slate-400">
          Powered by Groq's lightning-fast LLM inference&nbsp;•&nbsp;Llama 3.1 70B
        </p>
      </div>

      {/* Chat container */}
      <div className="flex flex-col rounded-2xl border border-slate-800/60 bg-[#0f172a] overflow-hidden flex-1 min-h-0">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 min-h-0" style={{ maxHeight: '55vh' }}>
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] rounded-xl px-4 py-3 text-sm leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-cyan-500 text-slate-900 font-medium'
                    : 'bg-slate-800/70 border border-slate-700/50 text-slate-200'
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>
                <p
                  className={`mt-1.5 text-xs ${
                    msg.role === 'user' ? 'text-cyan-900/70' : 'text-slate-500'
                  }`}
                >
                  {formatTime(msg.timestamp)}
                </p>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="rounded-xl bg-slate-800/70 border border-slate-700/50 px-4 py-3">
                <TypingDots />
              </div>
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              {error}
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Suggestions */}
        <div className="px-5 py-3 border-t border-slate-800/60">
          <p className="mb-2 text-xs text-slate-500">Try asking:</p>
          <div className="flex flex-wrap gap-2">
            {SUGGESTIONS.map((s) => (
              <button
                key={s}
                onClick={() => sendMessage(s)}
                disabled={loading}
                className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-40"
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Input */}
        <div className="px-5 pb-4 pt-3 border-t border-slate-800/60">
          <div className="flex gap-3 items-end">
            <textarea
              ref={textareaRef}
              rows={1}
              value={input}
              onChange={handleInput}
              onKeyDown={handleKeyDown}
              placeholder="Ask me anything about cybersecurity..."
              className="flex-1 resize-none rounded-xl border border-slate-700/60 bg-slate-800/60 px-4 py-3 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 leading-relaxed"
              style={{ minHeight: '48px', maxHeight: '160px' }}
            />
            <button
              onClick={() => sendMessage(input)}
              disabled={!input.trim() || loading}
              className="h-12 w-16 rounded-xl bg-cyan-500 text-sm font-semibold text-slate-900 hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex-shrink-0"
            >
              Send
            </button>
          </div>
          <p className="mt-2 text-xs text-slate-500 flex items-center gap-2">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              AI Online
            </span>
            <span>•</span>
            <span>Press Enter to send, Shift+Enter for new line</span>
          </p>
        </div>
      </div>

      {/* Feature cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[
          {
            icon: '⚡',
            iconColor: 'text-yellow-400',
            title: 'Lightning Fast',
            desc: "Powered by Groq's LPU for instant responses",
          },
          {
            icon: '🧠',
            iconColor: 'text-pink-400',
            title: 'Expert Knowledge',
            desc: 'Trained on cybersecurity best practices and threats',
          },
          {
            icon: '🔒',
            iconColor: 'text-cyan-400',
            title: 'Context Aware',
            desc: 'Understands your security context and history',
          },
        ].map((f) => (
          <div key={f.title} className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-5">
            <p className={`text-2xl ${f.iconColor} mb-2`}>{f.icon}</p>
            <p className={`font-semibold ${f.iconColor}`}>{f.title}</p>
            <p className="mt-1 text-sm text-slate-400">{f.desc}</p>
          </div>
        ))}
      </div>
    </section>
  )
}
