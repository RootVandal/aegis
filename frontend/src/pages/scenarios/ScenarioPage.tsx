import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { fetchEvents, type EventSummary } from '../../api/events'
import {
  fetchAttempts,
  fetchScenario,
  revealHint,
  revealSolution,
  startAttempt,
  submitAttempt,
  type Attempt,
  type ScenarioDetail,
  type Submission,
} from '../../api/scenarios'
import { SeverityBadge } from '../../components/Badges'
import { BUTTON, BUTTON_PRIMARY, ErrorNotice, INPUT, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

const MIN_RATIONALE = 40

export function ScenarioPage() {
  const { scenarioId = '' } = useParams()
  const [version, setVersion] = useState(0)
  const scenario = useApi((signal) => fetchScenario(scenarioId, signal), scenarioId, version)
  const attempts = useApi((signal) => fetchAttempts(scenarioId, signal), scenarioId, version)
  const [selected, setSelected] = useState<Attempt | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)

  const latest = attempts.data?.[0] ?? null
  const shown = selected?.scenario_id === scenarioId ? selected : latest
  const refresh = (attempt: Attempt) => {
    setSelected(attempt)
    setVersion((v) => v + 1)
  }

  const begin = async () => {
    setStarting(true)
    setError(null)
    try {
      refresh(await startAttempt(scenarioId))
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Could not start the scenario.')
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 md:p-6">
      <Link to="/scenarios" className="text-[12px] text-ink-muted hover:text-ink">
        ← Scenario Lab
      </Link>
      {scenario.status === 'error' && <ErrorNotice error={scenario.error} what="this scenario" />}
      {scenario.data && (
        <>
          <Briefing scenario={scenario.data} />
          {error && <p role="alert" className="text-[12px] text-crit">{error}</p>}
          {shown?.status === 'in_progress' ? (
            <Workspace scenario={scenario.data} attempt={shown} onChange={refresh} />
          ) : (
            <>
              {shown && <Result scenario={scenario.data} attempt={shown} />}
              <div className="flex flex-wrap items-center gap-3">
                <button type="button" className={BUTTON_PRIMARY} disabled={starting} onClick={() => void begin()}>
                  {starting ? 'Preparing data…' : shown ? 'Start a new attempt' : 'Start investigation'}
                </button>
                {!shown && (
                  <span className="text-[12px] text-ink-muted">
                    Loads {scenario.data.event_count} synthetic events (labeled “synthetic”) and runs detection on them.
                  </span>
                )}
              </div>
            </>
          )}
          {attempts.data && attempts.data.length > 1 && (
            <History attempts={attempts.data} current={shown?.id} onSelect={setSelected} />
          )}
        </>
      )}
    </div>
  )
}

function Briefing({ scenario }: { scenario: ScenarioDetail }) {
  return (
    <Panel title={`${scenario.title} · ${scenario.difficulty}`}>
      <p className="text-[13px] leading-relaxed text-ink">{scenario.context}</p>
      <h3 className="mb-1 mt-3 text-[11px] uppercase tracking-wider text-ink-faint">Objectives</h3>
      <ul className="list-disc space-y-0.5 pl-5 text-[13px] text-ink-muted">
        {scenario.objectives.map((objective) => (
          <li key={objective}>{objective}</li>
        ))}
      </ul>
      <p className="mt-3 font-mono text-[11px] text-ink-faint">
        Related rules:{' '}
        {scenario.relevant_rules.map((rule, index) => (
          <span key={rule}>
            {index > 0 && ', '}
            <Link to={`/rules/${rule}`} className="hover:text-ok">
              {rule}
            </Link>
          </span>
        ))}
      </p>
    </Panel>
  )
}

/** Draft answers survive navigation to the investigation tools and back. */
function useDraft(attemptId: number): [Submission, (update: (draft: Submission) => Submission) => void] {
  const key = `aegis.scenario-draft.${attemptId}`
  const [draft, setDraft] = useState<Submission>(() => {
    try {
      const stored = localStorage.getItem(key)
      if (stored) return JSON.parse(stored) as Submission
    } catch {
      // Storage unavailable or corrupt: start empty.
    }
    return { answers: {}, evidence_event_ids: [], rationale: '' }
  })
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(draft))
    } catch {
      // Best effort only.
    }
  }, [key, draft])
  return [draft, (update) => setDraft((current) => update(current))]
}

function Workspace({
  scenario,
  attempt,
  onChange,
}: {
  scenario: ScenarioDetail
  attempt: Attempt
  onChange: (attempt: Attempt) => void
}) {
  const [draft, update] = useDraft(attempt.id)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirmReveal, setConfirmReveal] = useState(false)
  const events = useApi(
    (signal) => fetchEvents({ scenario_id: scenario.scenario_tag, sort: 'timestamp_asc' }, signal),
    scenario.scenario_tag,
  )

  const act = async (action: () => Promise<Attempt>) => {
    setBusy(true)
    setError(null)
    try {
      onChange(await action())
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'The action failed.')
    } finally {
      setBusy(false)
    }
  }
  const toggleEvidence = (eventId: string) =>
    update((d) => ({
      ...d,
      evidence_event_ids: d.evidence_event_ids.includes(eventId)
        ? d.evidence_event_ids.filter((id) => id !== eventId)
        : [...d.evidence_event_ids, eventId],
    }))
  const unanswered = scenario.questions.filter((q) => !draft.answers[q.id]).length
  const rationaleShort = draft.rationale.trim().length < MIN_RATIONALE

  return (
    <div className="space-y-4">
      <Panel title="Investigate">
        <p className="text-[13px] text-ink-muted">
          Use the normal tools. Your answers below are saved as a draft in this browser while you explore.
        </p>
        <div className="mt-2 flex flex-wrap gap-2">
          <Link to={`/events?scenario_id=${encodeURIComponent(scenario.scenario_tag)}&sort=timestamp_asc`} className={BUTTON}>
            Open the scenario's events in Event Explorer
          </Link>
          <Link to="/investigation" className={BUTTON}>
            Investigation workspace
          </Link>
        </div>
        <h3 className="mb-1 mt-3 text-[11px] uppercase tracking-wider text-ink-faint">
          Alerts raised on this data ({scenario.alerts.length})
        </h3>
        <ul className="space-y-1 text-[12px]">
          {scenario.alerts.map((alert) => (
            <li key={alert.id} className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <Link to={`/alerts/${alert.id}`} className="text-ink hover:text-ok">
                #{alert.id} {alert.title}
              </Link>
              <span className="font-mono text-ink-faint">{alert.rule_id}</span>
            </li>
          ))}
        </ul>
      </Panel>

      <Panel title={`Hints (${attempt.hints.length} of ${attempt.hints.length + attempt.hints_remaining} shown)`}>
        {attempt.hints.length > 0 && (
          <ol className="mb-2 list-decimal space-y-1 pl-5 text-[13px] text-ink-muted">
            {attempt.hints.map((hint) => (
              <li key={hint}>{hint}</li>
            ))}
          </ol>
        )}
        <button
          type="button"
          className={BUTTON}
          disabled={busy || attempt.hints_remaining === 0}
          onClick={() => void act(() => revealHint(attempt.id))}
        >
          {attempt.hints_remaining === 0 ? 'No more hints' : 'Show a hint'}
        </button>
        <span className="ml-3 text-[12px] text-ink-faint">Hints are recorded but do not affect the grade.</span>
      </Panel>

      <Panel title={`Cite your key evidence (${draft.evidence_event_ids.length} selected)`} padded={false}>
        <p className="px-4 pt-3 text-[12px] text-ink-muted">
          Select the events your conclusions rest on. Citing events that look suspicious but have a benign explanation
          counts against you, so cite what you can justify.
        </p>
        {events.status === 'error' && <div className="p-4"><ErrorNotice error={events.error} what="the scenario's events" /></div>}
        {events.data && (
          <table className="mt-2 w-full min-w-[760px] text-left text-[12px]">
            <thead className="border-y border-line text-[11px] uppercase tracking-wider text-ink-faint">
              <tr>
                {['Cite', 'Time (UTC)', 'Event', 'Host', 'User', 'Details'].map((h) => (
                  <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {events.data.items.map((event) => (
                <tr key={event.event_id} className="align-top">
                  <td className="px-3 py-1.5 pl-4">
                    <input
                      type="checkbox"
                      aria-label={`Cite ${event.event_id}`}
                      checked={draft.evidence_event_ids.includes(event.event_id)}
                      onChange={() => toggleEvidence(event.event_id)}
                    />
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">{formatUtc(event.timestamp).replace(' UTC', '')}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">
                    <Link to={`/events/${encodeURIComponent(event.event_id)}`} className="text-ink hover:text-ok">
                      {event.event_type}
                    </Link>
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">{event.hostname ?? '—'}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">{event.username ?? '—'}</td>
                  <td className="max-w-[360px] truncate px-3 py-1.5 font-mono text-ink-muted"
                      title={event.process_command_line ?? undefined}>
                    {eventDetails(event)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Your conclusions">
        <div className="space-y-4">
          {scenario.questions.map((question) => (
            <fieldset key={question.id}>
              <legend className="mb-1 text-[13px] text-ink">{question.prompt}</legend>
              <div className="space-y-1">
                {question.options.map((option) => (
                  <label key={option.id} className="flex items-start gap-2 text-[13px] text-ink-muted">
                    <input
                      type="radio"
                      name={`q-${question.id}`}
                      className="mt-1"
                      checked={draft.answers[question.id] === option.id}
                      onChange={() => update((d) => ({ ...d, answers: { ...d.answers, [question.id]: option.id } }))}
                    />
                    {option.text}
                  </label>
                ))}
              </div>
            </fieldset>
          ))}
          <label className="block">
            <span className="mb-1 block text-[13px] text-ink">
              Your reasoning: what happened, and which evidence supports it?
            </span>
            <textarea
              className={INPUT}
              rows={5}
              maxLength={10000}
              value={draft.rationale}
              onChange={(e) => update((d) => ({ ...d, rationale: e.target.value }))}
            />
            <span className="text-[11px] text-ink-faint">
              {draft.rationale.trim().length} characters (at least {MIN_RATIONALE}). Stored with your attempt and shown
              next to the model reasoning; it is not auto-graded.
            </span>
          </label>
        </div>
      </Panel>

      {error && <p role="alert" className="text-[12px] text-crit">{error}</p>}
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          className={BUTTON_PRIMARY}
          disabled={busy}
          onClick={() => void act(() => submitAttempt(attempt.id, draft))}
        >
          Submit for assessment
        </button>
        <span className="text-[12px] text-ink-faint">
          {unanswered > 0 && `${unanswered} question(s) unanswered. `}
          {rationaleShort && 'Reasoning is shorter than required. '}
          Submitting closes this attempt and shows the explanation.
        </span>
        {confirmReveal ? (
          <span className="ml-auto flex items-center gap-2 text-[12px]">
            Show the solution without an assessment?
            <button type="button" className={BUTTON} onClick={() => void act(() => revealSolution(attempt.id))}>
              Yes, reveal
            </button>
            <button type="button" className={BUTTON} onClick={() => setConfirmReveal(false)}>
              Cancel
            </button>
          </span>
        ) : (
          <button type="button" className={`${BUTTON} ml-auto`} onClick={() => setConfirmReveal(true)}>
            Reveal solution…
          </button>
        )}
      </div>
    </div>
  )
}

function Result({ scenario, attempt }: { scenario: ScenarioDetail; attempt: Attempt }) {
  const evaluation = attempt.evaluation
  const solution = attempt.solution
  const optionText = (questionId: string, optionId: string | null) =>
    scenario.questions.find((q) => q.id === questionId)?.options.find((o) => o.id === optionId)?.text ?? '—'
  return (
    <div className="space-y-4">
      {evaluation ? (
        <Panel title={`Assessment · attempt #${attempt.id}`}>
          <p role="status" className={`text-[14px] font-medium ${evaluation.completed ? 'text-ok' : 'text-warn'}`}>
            {evaluation.completed ? 'Completed: every objective was met.' : 'Not completed yet: see the objectives below.'}
          </p>
          <ul className="mt-2 space-y-1 text-[13px]">
            {evaluation.objectives.map((objective) => (
              <li key={objective.objective}>
                <span className={objective.met ? 'text-ok' : 'text-crit'}>{objective.met ? '✓' : '✗'}</span>{' '}
                <span className="text-ink">{objective.objective}</span>{' '}
                <span className="text-ink-muted">· {objective.detail}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-ink-faint">
            Time spent {Math.round(attempt.elapsed_seconds / 60)} min and {attempt.hints.length} hint(s) used. Neither is
            part of the grade.
          </p>
        </Panel>
      ) : (
        <Panel title={`Solution revealed · attempt #${attempt.id}`}>
          <p className="text-[13px] text-ink-muted">This attempt was not submitted, so there is no assessment.</p>
        </Panel>
      )}

      {evaluation && (
        <Panel title="Questions">
          <ul className="space-y-3 text-[13px]">
            {evaluation.questions.map((q) => (
              <li key={q.id}>
                <p className="text-ink">
                  <span className={q.correct ? 'text-ok' : 'text-crit'}>{q.correct ? '✓' : '✗'}</span> {q.prompt}
                </p>
                <p className="text-ink-muted">Your answer: {optionText(q.id, q.your_answer)}</p>
                {!q.correct && <p className="text-ink-muted">Correct: {optionText(q.id, q.correct_answer)}</p>}
                <p className="mt-0.5 text-[12px] text-ink-faint">{q.explanation}</p>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {solution && (
        <div className="grid gap-4 lg:grid-cols-2 [&>*]:min-w-0">
          <Panel title="Evidence key">
            <ul className="space-y-2 text-[12px]">
              {solution.required_evidence.map((item) => {
                const cited = evaluation?.evidence.required.find((r) => r.description === item.description)?.cited
                return (
                  <li key={item.description}>
                    {evaluation && <span className={cited ? 'text-ok' : 'text-crit'}>{cited ? '✓ ' : '✗ '}</span>}
                    <span className="text-ink">{item.description}</span>
                    <EventLinks ids={item.event_ids} />
                  </li>
                )
              })}
            </ul>
            <h3 className="mb-1 mt-3 text-[11px] uppercase tracking-wider text-ink-faint">Benign lookalikes</h3>
            <ul className="space-y-2 text-[12px]">
              {solution.decoys.map((decoy) => {
                const hit = evaluation?.evidence.decoys_cited.some((d) => d.why === decoy.why)
                return (
                  <li key={decoy.why}>
                    {hit && <span className="font-medium text-warn">You cited this. </span>}
                    <span className="text-ink-muted">{decoy.why}</span>
                    <EventLinks ids={decoy.event_ids} />
                  </li>
                )
              })}
            </ul>
          </Panel>
          <Panel title="Intended reasoning">
            <ol className="list-decimal space-y-1 pl-5 text-[13px] text-ink-muted">
              {solution.reasoning.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <h3 className="mb-1 mt-3 text-[11px] uppercase tracking-wider text-ink-faint">False positives to consider</h3>
            <ul className="list-disc space-y-1 pl-5 text-[13px] text-ink-muted">
              {solution.false_positive_discussion.map((point) => (
                <li key={point}>{point}</li>
              ))}
            </ul>
            {attempt.rationale && (
              <>
                <h3 className="mb-1 mt-3 text-[11px] uppercase tracking-wider text-ink-faint">Your reasoning</h3>
                <p className="whitespace-pre-wrap break-words text-[13px] text-ink-muted">{attempt.rationale}</p>
              </>
            )}
          </Panel>
        </div>
      )}
    </div>
  )
}

function EventLinks({ ids }: { ids: string[] }) {
  return (
    <span className="ml-1 font-mono text-ink-faint">
      (
      {ids.map((id, index) => (
        <span key={id}>
          {index > 0 && ', '}
          <Link to={`/events/${encodeURIComponent(id)}`} className="hover:text-ok">
            {id}
          </Link>
        </span>
      ))}
      )
    </span>
  )
}

function History({
  attempts,
  current,
  onSelect,
}: {
  attempts: Attempt[]
  current: number | undefined
  onSelect: (attempt: Attempt) => void
}) {
  return (
    <Panel title="Attempts">
      <ul className="space-y-1 text-[12px]">
        {attempts.map((attempt) => (
          <li key={attempt.id}>
            <button
              type="button"
              onClick={() => onSelect(attempt)}
              className={`hover:text-ok ${attempt.id === current ? 'text-ink' : 'text-ink-muted'}`}
            >
              #{attempt.id} · {formatUtc(attempt.started_at)} · {attempt.status.replace('_', ' ')}
              {attempt.evaluation && (attempt.evaluation.completed ? ' · completed' : ' · not completed')}
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

/** The most informative field of an event for the evidence picker. */
function eventDetails(event: EventSummary): string {
  if (event.process_command_line) return event.process_command_line
  const parts = []
  if (event.source_ip) parts.push(`src ${event.source_ip}`)
  if (event.destination_ip) parts.push(`dst ${event.destination_ip}:${event.destination_port ?? ''}`)
  return parts.join(' · ')
}
