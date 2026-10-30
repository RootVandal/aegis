import { useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import {
  INCIDENT_STATUSES,
  VERDICTS,
  addEvidence,
  addIncidentNote,
  fetchIncident,
  fetchReport,
  fetchTimeline,
  linkAlerts,
  removeEvidence,
  saveAssessment,
  unlinkAlert,
  updateIncident,
  type IncidentDetail,
  type Verdict,
} from '../../api/incidents'
import { SeverityBadge } from '../../components/Badges'
import { BUTTON, BUTTON_PRIMARY, ErrorNotice, INPUT, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'
import { IncidentStatusBadge } from './IncidentStatusBadge'

type Run = (action: () => Promise<IncidentDetail | void>) => Promise<boolean>

export function IncidentDetailPage() {
  const { incidentId = '' } = useParams()
  const loaded = useApi((signal) => fetchIncident(incidentId, signal), incidentId)
  const [updated, setUpdated] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [version, setVersion] = useState(0) // bumps the timeline after any change
  const incident = updated && String(updated.id) === incidentId ? updated : loaded.data

  // Every mutation returns the updated incident (or we refetch it), so the
  // page always shows what the server accepted.
  const run: Run = async (action) => {
    setError(null)
    try {
      const result = await action()
      setUpdated(result ?? (await fetchIncident(incidentId)))
      setVersion((v) => v + 1)
      return true
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'The action failed.')
      return false
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 md:p-6">
      <Link to="/incidents" className="text-[12px] text-ink-muted hover:text-ink">
        ← Incidents
      </Link>
      {loaded.status === 'loading' && !incident && <p className="text-[13px] text-ink-muted">Loading incident…</p>}
      {loaded.status === 'error' && <ErrorNotice error={loaded.error} what="this incident" />}
      {incident && (
        <>
          <Header incident={incident} run={run} />
          {error && (
            <p role="alert" className="rounded-md border border-crit/40 bg-crit-dim px-4 py-2 text-[12px] text-crit">
              {error}
            </p>
          )}
          <Description incident={incident} run={run} />
          <Alerts incident={incident} run={run} />
          <Timeline incident={incident} run={run} version={version} />
          <div className="grid gap-4 lg:grid-cols-2">
            <Evidence incident={incident} run={run} />
            <Notes incident={incident} run={run} />
          </div>
          <Assessment incident={incident} run={run} />
          <div className="grid gap-4 lg:grid-cols-2">
            <History incident={incident} />
            <Report incident={incident} />
          </div>
        </>
      )}
    </div>
  )
}

function Header({ incident, run }: { incident: IncidentDetail; run: Run }) {
  const current = INCIDENT_STATUSES.indexOf(incident.status)
  const hasAssessment = Boolean(incident.verdict && incident.final_assessment && incident.resolution_summary)
  return (
    <header className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-base font-medium text-ink">
          #{incident.id} {incident.title}
        </h2>
        <SeverityBadge severity={incident.severity} />
        <IncidentStatusBadge status={incident.status} />
      </div>
      <ol className="flex flex-wrap items-center gap-1 text-[11px] uppercase tracking-wide" aria-label="Lifecycle">
        {INCIDENT_STATUSES.map((status, index) => (
          <li key={status} className="flex items-center gap-1">
            <span
              aria-current={status === incident.status ? 'step' : undefined}
              className={`rounded-sm border px-1.5 py-0.5 ${
                index === current
                  ? 'border-ok/60 text-ok'
                  : index < current
                    ? 'border-line-strong text-ink-muted'
                    : 'border-line text-ink-faint'
              }`}
            >
              {status}
            </span>
            {index < INCIDENT_STATUSES.length - 1 && <span className="text-ink-faint">→</span>}
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap items-center gap-2">
        {incident.allowed_transitions.map((status) => {
          const blocked = status === 'resolved' && !hasAssessment
          return (
            <button
              key={status}
              type="button"
              className={status === 'resolved' ? BUTTON_PRIMARY : BUTTON}
              disabled={blocked}
              title={blocked ? 'Record the final assessment first' : undefined}
              onClick={() => void run(() => updateIncident(incident.id, { status }))}
            >
              {incident.status === 'resolved' ? 'Reopen' : `Move to ${status}`}
            </button>
          )
        })}
        {incident.allowed_transitions.includes('resolved') && !hasAssessment && (
          <span className="text-[12px] text-ink-faint">Resolving requires the final assessment below.</span>
        )}
      </div>
    </header>
  )
}

function Description({ incident, run }: { incident: IncidentDetail; run: Run }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(incident.description)
  return (
    <Panel
      title="Description"
      actions={
        !editing && (
          <button type="button" className={BUTTON} onClick={() => { setText(incident.description); setEditing(true) }}>
            Edit
          </button>
        )
      }
    >
      {editing ? (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            void run(() => updateIncident(incident.id, { description: text })).then((ok) => ok && setEditing(false))
          }}
          className="space-y-2"
        >
          <textarea aria-label="Description" className={INPUT} rows={4} maxLength={5000} value={text}
                    onChange={(e) => setText(e.target.value)} />
          <div className="flex gap-2">
            <button type="submit" className={BUTTON_PRIMARY}>Save</button>
            <button type="button" className={BUTTON} onClick={() => setEditing(false)}>Cancel</button>
          </div>
        </form>
      ) : (
        <p className="whitespace-pre-wrap text-[13px] text-ink-muted">{incident.description || 'No description.'}</p>
      )}
    </Panel>
  )
}

function Alerts({ incident, run }: { incident: IncidentDetail; run: Run }) {
  const [alertId, setAlertId] = useState('')
  return (
    <Panel title={`Alerts (${incident.alerts.length})`} padded={false}>
      {incident.alerts.length > 0 && (
        <ul className="divide-y divide-line">
          {incident.alerts.map((alert) => (
            <li key={alert.id} className="flex flex-wrap items-center gap-3 px-4 py-2 text-[12px]">
              <SeverityBadge severity={alert.severity} />
              <Link to={`/alerts/${alert.id}`} className="text-ink hover:text-ok">
                #{alert.id} {alert.title}
              </Link>
              <span className="font-mono text-ink-faint">
                {alert.rule_id} · {alert.status.replace('_', ' ')}
              </span>
              <button type="button" className={`${BUTTON} ml-auto`}
                      onClick={() => void run(() => unlinkAlert(incident.id, alert.id))}>
                Unlink
              </button>
            </li>
          ))}
        </ul>
      )}
      <form
        className="flex gap-2 border-t border-line px-4 py-2"
        onSubmit={(e) => {
          e.preventDefault()
          void run(() => linkAlerts(incident.id, [Number(alertId)])).then((ok) => ok && setAlertId(''))
        }}
      >
        <input aria-label="Alert ID" className={`${INPUT} max-w-40`} inputMode="numeric" placeholder="Alert ID"
               value={alertId} onChange={(e) => setAlertId(e.target.value.replace(/\D/g, ''))} />
        <button type="submit" className={BUTTON} disabled={!alertId}>Link alert</button>
      </form>
    </Panel>
  )
}

function Timeline({ incident, run, version }: { incident: IncidentDetail; run: Run; version: number }) {
  const [correlated, setCorrelated] = useState(false)
  const timeline = useApi(
    (signal) => fetchTimeline(String(incident.id), correlated, signal),
    `${incident.id}|${correlated}`,
    version,
  )
  const [marking, setMarking] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const evidenceIds = new Set(incident.evidence.map((e) => e.event.event_id))

  return (
    <Panel
      title={`Timeline${timeline.data ? ` (${timeline.data.length} events)` : ''}`}
      padded={false}
      actions={
        <label className="flex items-center gap-1.5 text-[12px] text-ink-muted">
          <input type="checkbox" checked={correlated} onChange={(e) => setCorrelated(e.target.checked)} />
          include correlated events (±1 h)
        </label>
      }
    >
      {timeline.status === 'error' && <div className="p-4"><ErrorNotice error={timeline.error} what="the timeline" /></div>}
      {timeline.status === 'success' && timeline.data.length === 0 && (
        <p className="px-4 py-3 text-[13px] text-ink-muted">Link an alert or record evidence to build the timeline.</p>
      )}
      {timeline.status === 'success' && timeline.data.length > 0 && (
        <table className="w-full min-w-[900px] text-left text-[12px]">
          <thead className="border-b border-line text-[11px] uppercase tracking-wider text-ink-faint">
            <tr>
              {['Time (UTC)', 'Event', 'Host', 'User', 'Rules', 'Why it is on the timeline', ''].map((h) => (
                <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {timeline.data.map((entry) => {
              const id = entry.event.event_id
              return (
                <tr key={id} className="align-top">
                  <td className="whitespace-nowrap px-3 py-1.5 pl-4 font-mono">{formatUtc(entry.event.timestamp).replace(' UTC', '')}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">
                    <Link to={`/events/${encodeURIComponent(id)}`} className="text-ink hover:text-ok">{entry.event.event_type}</Link>
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">{entry.event.hostname ?? '—'}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">{entry.event.username ?? '—'}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-ink-muted">{entry.rule_ids.join(', ') || '—'}</td>
                  <td className="px-3 py-1.5">
                    <ul className="space-y-0.5">
                      {entry.sources.map((source, index) => (
                        <li key={index} className={source.kind === 'correlated' ? 'text-ink-faint' : 'text-ink-muted'}>
                          {source.description}
                        </li>
                      ))}
                    </ul>
                    {marking === id && (
                      <form
                        className="mt-1 flex gap-2"
                        onSubmit={(e: FormEvent) => {
                          e.preventDefault()
                          void run(() => addEvidence(incident.id, id, note)).then((ok) => {
                            if (ok) {
                              setMarking(null)
                              setNote('')
                            }
                          })
                        }}
                      >
                        <input aria-label="Why this event matters" className={INPUT} autoFocus maxLength={2000}
                               placeholder="Why this event matters…" value={note} onChange={(e) => setNote(e.target.value)} />
                        <button type="submit" className={BUTTON} disabled={!note.trim()}>Save</button>
                      </form>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5">
                    {evidenceIds.has(id) ? (
                      <span className="text-[11px] text-ok">evidence</span>
                    ) : (
                      <button type="button" className={BUTTON} onClick={() => { setMarking(id); setNote('') }}>
                        Mark as evidence
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </Panel>
  )
}

function Evidence({ incident, run }: { incident: IncidentDetail; run: Run }) {
  return (
    <Panel title={`Documented evidence (${incident.evidence.length})`}>
      {incident.evidence.length === 0 ? (
        <p className="text-[13px] text-ink-muted">Use “Mark as evidence” on the timeline to document why an event matters.</p>
      ) : (
        <ul className="space-y-2 text-[12px]">
          {incident.evidence.map((item) => (
            <li key={item.id} className="border-l-2 border-ok/50 pl-2">
              <div className="flex items-center gap-2">
                <Link to={`/events/${encodeURIComponent(item.event.event_id)}`} className="font-mono text-ink hover:text-ok">
                  {item.event.event_id}
                </Link>
                <span className="font-mono text-[11px] text-ink-faint">{formatUtc(item.event.timestamp)}</span>
                <button type="button" className={`${BUTTON} ml-auto`}
                        onClick={() => void run(() => removeEvidence(incident.id, item.id))}>
                  Remove
                </button>
              </div>
              <p className="whitespace-pre-wrap break-words text-ink-muted">{item.note}</p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

function Notes({ incident, run }: { incident: IncidentDetail; run: Run }) {
  const [kind, setKind] = useState<'note' | 'hypothesis'>('note')
  const [body, setBody] = useState('')
  return (
    <Panel title={`Notes and hypotheses (${incident.notes.length})`}>
      <form
        className="mb-3 space-y-2"
        onSubmit={(e) => {
          e.preventDefault()
          void run(() => addIncidentNote(incident.id, kind, body)).then((ok) => ok && setBody(''))
        }}
      >
        <div className="flex gap-2">
          <select aria-label="Note type" className={`${INPUT} max-w-44`} value={kind}
                  onChange={(e) => setKind(e.target.value as 'note' | 'hypothesis')}>
            <option value="note">Note</option>
            <option value="hypothesis">Hypothesis (unverified)</option>
          </select>
          <button type="submit" className={BUTTON} disabled={!body.trim()}>Add</button>
        </div>
        <textarea aria-label="Note text" className={INPUT} rows={2} maxLength={5000} value={body}
                  onChange={(e) => setBody(e.target.value)} />
      </form>
      <ul className="space-y-2 text-[12px]">
        {incident.notes.map((note) => (
          <li key={note.id} className={`border-l-2 pl-2 ${note.kind === 'hypothesis' ? 'border-warn/60' : 'border-line-strong'}`}>
            <div className="font-mono text-[11px] text-ink-faint">
              {note.kind === 'hypothesis' && <span className="mr-1 font-sans font-medium uppercase text-warn">Hypothesis · unverified</span>}
              {formatUtc(note.created_at)} · {note.author}
            </div>
            <p className="whitespace-pre-wrap break-words text-ink-muted">{note.body}</p>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function Assessment({ incident, run }: { incident: IncidentDetail; run: Run }) {
  const [verdict, setVerdict] = useState<Verdict | ''>(incident.verdict ?? '')
  const [assessment, setAssessment] = useState(incident.final_assessment ?? '')
  const [resolution, setResolution] = useState(incident.resolution_summary ?? '')
  const [saved, setSaved] = useState(false)
  return (
    <Panel title="Final assessment">
      <form
        className="grid gap-3 text-[12px]"
        onSubmit={(e) => {
          e.preventDefault()
          if (!verdict) return
          void run(() => saveAssessment(incident.id, { verdict, final_assessment: assessment, resolution_summary: resolution }))
            .then(setSaved)
        }}
      >
        <label className="block">
          <span className="mb-1 block text-ink-faint">Verdict</span>
          <select className={INPUT} value={verdict} onChange={(e) => setVerdict(e.target.value as Verdict)} required>
            <option value="" disabled>Choose a verdict…</option>
            {VERDICTS.map((v) => (
              <option key={v.value} value={v.value}>{v.label}</option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="mb-1 block text-ink-faint">Assessment: what happened, and which evidence supports it</span>
          <textarea className={INPUT} rows={4} required maxLength={10000} value={assessment}
                    onChange={(e) => setAssessment(e.target.value)} />
        </label>
        <label className="block">
          <span className="mb-1 block text-ink-faint">Resolution summary: what was done</span>
          <textarea className={INPUT} rows={2} required maxLength={5000} value={resolution}
                    onChange={(e) => setResolution(e.target.value)} />
        </label>
        <div className="flex items-center gap-3">
          <button type="submit" className={BUTTON_PRIMARY} disabled={!verdict || !assessment.trim() || !resolution.trim()}>
            Save assessment
          </button>
          {saved && <span role="status" className="text-ok">Assessment saved.</span>}
        </div>
      </form>
    </Panel>
  )
}

function History({ incident }: { incident: IncidentDetail }) {
  return (
    <Panel title="History">
      <ul className="space-y-1 text-[12px]">
        {[...incident.history].reverse().map((entry, index) => (
          <li key={index}>
            <span className="font-mono text-[11px] text-ink-faint">{formatUtc(entry.created_at)}</span>{' '}
            <span className="text-ink-muted">{entry.summary}</span>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function Report({ incident }: { incident: IncidentDetail }) {
  const [report, setReport] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    setError(null)
    try {
      const text = await fetchReport(incident.id)
      setReport(text)
      return text
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not generate the report.')
      return null
    }
  }
  const download = async () => {
    const text = await load()
    if (text === null) return
    const url = URL.createObjectURL(new Blob([text], { type: 'text/markdown' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `incident-${incident.id}.md`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Panel title="Incident report">
      <p className="mb-2 text-[12px] text-ink-muted">
        Markdown generated from the recorded data: alerts, timeline, evidence, notes (hypotheses labeled), assessment
        and history.
      </p>
      <div className="flex gap-2">
        <button type="button" className={BUTTON} onClick={() => void load()}>Preview</button>
        <button type="button" className={BUTTON_PRIMARY} onClick={() => void download()}>Download .md</button>
      </div>
      {error && <p role="alert" className="mt-2 text-[12px] text-crit">{error}</p>}
      {report && (
        <pre aria-label="Report preview" className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-sm bg-canvas p-3 font-mono text-[11px] text-ink-muted">
          {report}
        </pre>
      )}
    </Panel>
  )
}
