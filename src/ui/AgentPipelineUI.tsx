export function AgentPipelineUI() {
  const agents = [
    {
      id: 1,
      icon: '🔗',
      title: 'Extract',
      subtitle: 'Parse URL components',
      colorClass: 'border-cyan-400',
      titleColor: 'text-cyan-400',
    },
    {
      id: 2,
      icon: '🌐',
      title: 'Domain',
      subtitle: 'WHOIS & reputation',
      colorClass: 'border-blue-400',
      titleColor: 'text-blue-400',
    },
    {
      id: 3,
      icon: '📡',
      title: 'Signals',
      subtitle: '27 heuristic checks',
      colorClass: 'border-indigo-400',
      titleColor: 'text-indigo-400',
    },
    {
      id: 4,
      icon: '🎣',
      title: 'Phishing',
      subtitle: 'Pattern & brand match',
      colorClass: 'border-purple-400',
      titleColor: 'text-purple-400',
    },
    {
      id: 5,
      icon: '🧠',
      title: 'Reasoning',
      subtitle: 'AI threat analysis',
      colorClass: 'border-fuchsia-400',
      titleColor: 'text-fuchsia-400',
    },
    {
      id: 6,
      icon: '✍️',
      title: 'Narrative',
      subtitle: 'Plain language report',
      colorClass: 'border-emerald-400',
      titleColor: 'text-emerald-400',
    },
    {
      id: 7,
      icon: '🛡️',
      title: 'Action',
      subtitle: 'Risk verdict & score',
      colorClass: 'border-green-400',
      titleColor: 'text-green-400',
    },
    {
      id: 8,
      icon: '📚',
      title: 'Learning',
      subtitle: 'Feedback & pattern DB',
      colorClass: 'border-teal-400',
      titleColor: 'text-teal-400',
    },
  ]

  return (
    <div className="rounded-xl border border-slate-800/60 bg-[#0f172a] p-6 mb-8">
      <div className="text-center mb-6">
        <h3 className="text-lg font-medium text-slate-300">
          Not one AI — a team of 8 specialized agents, each building on the last.
        </h3>
      </div>
      
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
        {agents.map((agent) => (
          <div 
            key={agent.id} 
            className={`flex flex-col items-center text-center p-4 border rounded-lg bg-slate-900/50 ${agent.colorClass} border-opacity-70`}
          >
            <div className="text-3xl mb-4">{agent.icon}</div>
            <h4 className={`text-base font-bold mb-6 ${agent.titleColor}`}>{agent.title}</h4>
            <div className="mt-auto">
              <p className="text-xs text-slate-300 px-1">{agent.subtitle}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
