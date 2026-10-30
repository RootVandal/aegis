import { Link } from 'react-router-dom'

import { fetchScenarios, type ScenarioSummary } from '../../api/scenarios'
import { ErrorNotice, Panel } from '../../components/Panel'
import { useApi } from '../../lib/useApi'

const DIFFICULTY_STYLE = {
  beginner: 'border-ok/40 text-ok',
  intermediate: 'border-warn/50 text-warn',
  advanced: 'border-crit/50 text-crit',
} as const

export function ScenarioLabPage() {
  const scenarios = useApi((signal) => fetchScenarios(signal), 'scenarios')
  return (
    <div className="space-y-4 p-4 md:p-6">
      <p className="max-w-3xl text-[13px] text-ink-muted">
        Guided investigations on synthetic data. Each one gives you a briefing, the normal AEGIS tools and a set of
        questions. You are graded on whether your conclusions are right <em>and</em> backed by the right evidence, not
        on speed. Nothing here runs a real attack.
      </p>
      {scenarios.status === 'error' && <ErrorNotice error={scenarios.error} what="scenarios" />}
      <div className="grid gap-4 md:grid-cols-2">
        {scenarios.data?.map((scenario) => <ScenarioCard key={scenario.id} scenario={scenario} />)}
      </div>
    </div>
  )
}

function ScenarioCard({ scenario }: { scenario: ScenarioSummary }) {
  const latest = scenario.latest_attempt
  const state = scenario.completed
    ? { text: 'Completed', style: 'text-ok' }
    : latest?.status === 'in_progress'
      ? { text: 'In progress', style: 'text-warn' }
      : latest
        ? { text: 'Attempted, not completed', style: 'text-ink-muted' }
        : { text: 'Not started', style: 'text-ink-faint' }
  return (
    <Panel
      title={scenario.title}
      actions={
        <span className={`rounded-sm border px-1.5 py-px text-[11px] uppercase tracking-wide ${DIFFICULTY_STYLE[scenario.difficulty]}`}>
          {scenario.difficulty}
        </span>
      }
    >
      <p className="text-[13px] text-ink">{scenario.summary}</p>
      <p className="mt-2 font-mono text-[11px] text-ink-faint">
        {scenario.event_count} events · rules {scenario.relevant_rules.join(', ')}
      </p>
      <div className="mt-3 flex items-center justify-between text-[12px]">
        <span className={state.style}>
          {state.text}
          {scenario.attempt_count > 0 && ` · ${scenario.attempt_count} attempt(s)`}
        </span>
        <Link to={`/scenarios/${scenario.id}`} className="text-ok hover:underline">
          {latest?.status === 'in_progress' ? 'Continue →' : 'Open →'}
        </Link>
      </div>
    </Panel>
  )
}
