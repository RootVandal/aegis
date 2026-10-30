import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { CRITERIA, fetchAlert, fetchAlerts, fetchCorrelation, type Criterion } from '../../api/detection'
import { createIncident } from '../../api/incidents'
import { SeverityBadge } from '../../components/Badges'
import { BUTTON_PRIMARY, ErrorNotice, INPUT, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

const WINDOWS = [
  [15, '15 minutes'],
  [60, '1 hour'],
  [360, '6 hours'],
  [1440, '24 hours'],
] as const

/**
 * Investigation workspace: start from one alert and look at what else
 * happened around it. Every row says why it is shown; time alone never is.
 */
export function InvestigationPage() {
  const [params, setParams] = useSearchParams()
  const alertId = params.get('alert')
  return alertId ? <Workspace alertId={alertId} params={params} setParams={setParams} /> : <PickAlert />
}

function PickAlert() {
  const alerts = useApi((signal) => fetchAlerts({ status: 'new', sort: 'severity_desc' }, signal), 'pick')
  return (
    <div className="space-y-4 p-4 md:p-6">
      <p className="max-w-3xl text-[13px] text-ink-muted">
        Pick an alert to investigate. The workspace shows events that share a host, user, IP address or scenario with
        the alert's evidence, explains each link, and lets you open an incident from what you find.
      </p>
      {alerts.status === 'error' && <ErrorNotice error={alerts.error} what="alerts" />}
      <Panel title="New alerts, most severe first" padded={false}>
        {alerts.status === 'success' && alerts.data.items.length === 0 && (
          <p className="px-4 py-4 text-[13px] text-ink-muted">
            No new alerts. Any alert can be investigated from its detail page.
          </p>
        )}
        <ul className="divide-y divide-line">
          {alerts.data?.items.map((alert) => (
            <li key={alert.id} className="flex items-center gap-3 px-4 py-2 text-[12px]">
              <SeverityBadge severity={alert.severity} />
              <Link to={`/investigation?alert=${alert.id}`} className="text-ink hover:text-ok">
                #{alert.id} {alert.title}
              </Link>
              <span className="ml-auto font-mono text-ink-faint">{alert.rule_id}</span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  )
}

function Workspace({
  alertId,
  params,
  setParams,
}: {
  alertId: string
  params: URLSearchParams
  setParams: (next: URLSearchParams) => void
}) {
  const navigate = useNavigate()
  const windowMinutes = Number(params.get('window') ?? '60')
  const criteria = (params.getAll('criteria').length ? params.getAll('criteria') : CRITERIA) as Criterion[]
  const alert = useApi((signal) => fetchAlert(alertId, signal), alertId)
  const correlation = useApi(
    (signal) => fetchCorrelation(alertId, windowMinutes, criteria, signal),
    `${alertId}|${windowMinutes}|${criteria.join(',')}`,
  )
  const [selected, setSelected] = useState<number[]>([])
  const [error, setError] = useState<string | null>(null)

  const update = (changes: { window?: number; criteria?: Criterion[] }) => {
    const next = new URLSearchParams(params)
    if (changes.window !== undefined) next.set('window', String(changes.window))
    if (changes.criteria !== undefined) {
      next.delete('criteria')
      changes.criteria.forEach((c) => next.append('criteria', c))
    }
    setParams(next)
  }
  const toggleCriterion = (criterion: Criterion) => {
    const next = criteria.includes(criterion) ? criteria.filter((c) => c !== criterion) : [...criteria, criterion]
    if (next.length > 0) update({ criteria: next })
  }

  const openIncident = async () => {
    if (alert.status !== 'success') return
    setError(null)
    try {
      const incident = await createIncident({
        title: alert.data.title,
        description: `Opened from the investigation of alert #${alert.data.id}.`,
        alert_ids: [alert.data.id, ...selected],
      })
      navigate(`/incidents/${incident.id}`)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Could not create the incident.')
    }
  }

  return (
    <div className="space-y-4 p-4 md:p-6">
      <Link to="/investigation" className="text-[12px] text-ink-muted hover:text-ink">
        ← Pick another alert
      </Link>
      {alert.status === 'error' && <ErrorNotice error={alert.error} what="the alert" />}
      {alert.status === 'success' && (
        <Panel title="Starting point">
          <div className="flex flex-wrap items-center gap-3 text-[13px]">
            <SeverityBadge severity={alert.data.severity} />
            <Link to={`/alerts/${alert.data.id}`} className="text-ink hover:text-ok">
              Alert #{alert.data.id}: {alert.data.title}
            </Link>
            <span className="font-mono text-[12px] text-ink-faint">
              {formatUtc(alert.data.first_seen)} → {formatUtc(alert.data.last_seen)}
            </span>
          </div>
          <p className="mt-2 font-mono text-[12px] text-ink-muted">
            hosts: {alert.data.hosts.join(', ') || '—'} · users: {alert.data.users.join(', ') || '—'} · IPs:{' '}
            {alert.data.ips.join(', ') || '—'}
          </p>
          {alert.data.incident ? (
            <p className="mt-2 text-[12px]">
              Already part of{' '}
              <Link to={`/incidents/${alert.data.incident.id}`} className="text-ok hover:underline">
                incident #{alert.data.incident.id}
              </Link>
              .
            </p>
          ) : (
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button type="button" className={BUTTON_PRIMARY} onClick={() => void openIncident()}>
                Create incident{selected.length > 0 ? ` with ${selected.length} related alert(s)` : ''}
              </button>
              {error && <span role="alert" className="text-[12px] text-crit">{error}</span>}
            </div>
          )}
        </Panel>
      )}

      <Panel title="Correlation settings">
        <div className="flex flex-wrap items-end gap-6 text-[12px]">
          <label>
            <span className="mb-1 block text-ink-faint">Look before and after the alert</span>
            <select
              aria-label="Time window"
              className={INPUT}
              value={windowMinutes}
              onChange={(e) => update({ window: Number(e.target.value) })}
            >
              {WINDOWS.map(([value, text]) => (
                <option key={value} value={value}>
                  {text}
                </option>
              ))}
            </select>
          </label>
          <fieldset>
            <legend className="mb-1 text-ink-faint">Link events that share a…</legend>
            <div className="flex gap-4">
              {CRITERIA.map((criterion) => (
                <label key={criterion} className="flex items-center gap-1.5">
                  <input type="checkbox" checked={criteria.includes(criterion)} onChange={() => toggleCriterion(criterion)} />
                  {criterion === 'ip' ? 'IP address' : criterion}
                </label>
              ))}
            </div>
          </fieldset>
        </div>
        <p className="mt-2 text-[11px] text-ink-faint">
          Events are never linked only because they happened at a similar time. Very common values (a domain
          controller, a shared NAT address) can create weak links: switch a criterion off to narrow the result.
        </p>
      </Panel>

      {correlation.status === 'error' && <ErrorNotice error={correlation.error} what="correlated activity" />}
      {correlation.status === 'success' && (
        <>
          <Panel title={`Related alerts (${correlation.data.related_alerts.length})`} padded={false}>
            {correlation.data.related_alerts.length === 0 ? (
              <p className="px-4 py-3 text-[13px] text-ink-muted">No other alert cites the correlated events.</p>
            ) : (
              <ul className="divide-y divide-line">
                {correlation.data.related_alerts.map(({ alert: related, shared_event_ids }) => (
                  <li key={related.id} className="flex flex-wrap items-center gap-3 px-4 py-2 text-[12px]">
                    {!related.incident_id && alert.data && !alert.data.incident && (
                      <input
                        type="checkbox"
                        aria-label={`Include alert ${related.id}`}
                        checked={selected.includes(related.id)}
                        onChange={(e) =>
                          setSelected(e.target.checked ? [...selected, related.id] : selected.filter((id) => id !== related.id))
                        }
                      />
                    )}
                    <SeverityBadge severity={related.severity} />
                    <Link to={`/alerts/${related.id}`} className="text-ink hover:text-ok">
                      #{related.id} {related.title}
                    </Link>
                    <span className="font-mono text-ink-faint">
                      {related.rule_id} · shares {shared_event_ids.length} event(s)
                      {related.incident_id ? ` · in incident #${related.incident_id}` : ''}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel
            title={`Correlated events (${correlation.data.total}${correlation.data.truncated ? `, first ${correlation.data.events.length} shown` : ''})`}
            padded={false}
          >
            {correlation.data.events.length === 0 ? (
              <p className="px-4 py-3 text-[13px] text-ink-muted">
                No events in this window share a selected entity with the alert.
              </p>
            ) : (
              <table className="w-full min-w-[900px] text-left text-[12px]">
                <thead className="border-b border-line text-[11px] uppercase tracking-wider text-ink-faint">
                  <tr>
                    {['Time (UTC)', 'When', 'Event', 'Host', 'User', 'Why it is linked', 'Alerted by'].map((h) => (
                      <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {correlation.data.events.map((item) => (
                    <tr key={item.event.event_id} className="align-top">
                      <td className="whitespace-nowrap px-3 py-1.5 pl-4 font-mono">
                        {formatUtc(item.event.timestamp).replace(' UTC', '')}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 text-ink-muted">
                        {offsetLabel(item.relation, item.offset_seconds)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono">
                        <Link to={`/events/${encodeURIComponent(item.event.event_id)}`} className="text-ink hover:text-ok">
                          {item.event.event_type}
                        </Link>
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono">{item.event.hostname ?? '—'}</td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono">{item.event.username ?? '—'}</td>
                      <td className="px-3 py-1.5">
                        <ul className="flex flex-wrap gap-1">
                          {item.reasons.map((reason) => (
                            <li
                              key={`${reason.criterion}-${reason.value}`}
                              className="whitespace-nowrap rounded-sm border border-line-strong px-1.5 py-px font-mono text-[11px] text-ink-muted"
                            >
                              {reason.criterion}: {reason.value}
                            </li>
                          ))}
                        </ul>
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-ink-muted">
                        {item.rule_ids.join(', ') || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </>
      )}
    </div>
  )
}

/** Same wording rule as the backend: seconds below two minutes, then minutes. */
function offsetLabel(relation: 'before' | 'during' | 'after', seconds: number): string {
  if (relation === 'during') return 'during'
  const amount = seconds < 120 ? `${Math.round(seconds)} s` : `${Math.round(seconds / 60)} min`
  return `${amount} ${relation}`
}
