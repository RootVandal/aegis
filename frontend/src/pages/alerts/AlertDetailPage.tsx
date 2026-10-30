import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'

import { fetchAlert, type AlertDetail } from '../../api/detection'
import { OriginBadge, SeverityBadge } from '../../components/Badges'
import { ErrorNotice, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'
import { AlertTriage } from './AlertTriage'

export function AlertDetailPage() {
  const { alertId = '' } = useParams()
  const alert = useApi((signal) => fetchAlert(alertId, signal), alertId)
  // Triage actions return the updated alert; show it without re-fetching.
  const [updated, setUpdated] = useState<AlertDetail | null>(null)
  const current = updated && String(updated.id) === alertId ? updated : alert.data

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 md:p-6">
      <Link to="/alerts" className="text-[12px] text-ink-muted hover:text-ink">
        ← Alerts
      </Link>
      {alert.status === 'loading' && !current && <p className="text-[13px] text-ink-muted">Loading alert…</p>}
      {alert.status === 'error' && <ErrorNotice error={alert.error} what="this alert" />}
      {current && <AlertView alert={current} onChange={setUpdated} />}
    </div>
  )
}

/**
 * The explanation is the snapshot stored when the alert was created: it is
 * derived from the matched events and the rule, never generated afterwards.
 */
function AlertView({ alert, onChange }: { alert: AlertDetail; onChange: (alert: AlertDetail) => void }) {
  const x = alert.explanation
  return (
    <>
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-base font-medium text-ink">{alert.title}</h2>
          <SeverityBadge severity={alert.severity} />
          <span className="rounded-sm border border-line-strong px-1.5 py-px text-[11px] uppercase tracking-wide text-ink-muted">
            {alert.status.replace('_', ' ')}
          </span>
        </div>
        <p className="font-mono text-[12px] text-ink-muted">
          Alert #{alert.id} ·{' '}
          <Link to={`/rules/${alert.rule_id}`} className="text-ink hover:text-ok">
            {alert.rule_id} {alert.rule_name}
          </Link>{' '}
          v{alert.rule_version} · created {formatUtc(alert.created_at)}
        </p>
      </header>

      <p className="rounded-md border border-line bg-surface px-4 py-2 text-[12px] text-ink-muted">{x.disclaimer}</p>

      <AlertTriage alert={alert} onChange={onChange} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Section n={1} title="What the rule detected">
          <p className="text-[13px] text-ink">{x.what}</p>
        </Section>

        <Section n={3} title="Conditions satisfied">
          <ul className="space-y-2 text-[12px]">
            {x.conditions.map((c) => (
              <li key={c.description}>
                <span className="text-ok">✓</span> <span className="text-ink">{c.description}</span>
                <div className="ml-4 font-mono text-ink-muted break-all">{c.observed}</div>
              </li>
            ))}
          </ul>
        </Section>
      </div>

      <Section n={2} title={`Events that triggered it (${alert.events.length})`} padded={false}>
        <table className="w-full min-w-[760px] text-left text-[12px]">
          <thead className="border-b border-line text-[11px] uppercase tracking-wider text-ink-faint">
            <tr>
              {['Time (UTC)', 'Event', 'Summary', 'Origin'].map((h) => (
                <th key={h} className="px-3 py-2 font-medium first:pl-4">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {alert.events.map((event) => {
              const summary = x.triggering_events.find((t) => t.event_id === event.event_id)?.description
              return (
                <tr key={event.event_id} className="align-top">
                  <td className="whitespace-nowrap px-3 py-1.5 pl-4 font-mono">
                    {formatUtc(event.timestamp).replace(' UTC', '')}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono">
                    <Link to={`/events/${encodeURIComponent(event.event_id)}`} className="text-ink hover:text-ok">
                      {event.event_id}
                    </Link>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-ink-muted break-words">{summary ?? event.event_type}</td>
                  <td className="px-3 py-1.5">
                    <OriginBadge origin={event.data_origin} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </Section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section n={4} title="Evidence available">
          <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-[12px]">
            <dt className="text-ink-faint">Events</dt>
            <dd className="font-mono">{x.evidence.event_count}</dd>
            <dt className="text-ink-faint">Time span</dt>
            <dd className="font-mono">
              {formatUtc(x.evidence.first_seen)} → {formatUtc(x.evidence.last_seen)}
            </dd>
            <dt className="text-ink-faint">Hosts</dt>
            <dd className="font-mono">{x.evidence.hosts.join(', ') || '—'}</dd>
            <dt className="text-ink-faint">Users</dt>
            <dd className="font-mono">{x.evidence.users.join(', ') || '—'}</dd>
            <dt className="text-ink-faint">IP addresses</dt>
            <dd className="font-mono">{x.evidence.ips.join(', ') || '—'}</dd>
          </dl>
        </Section>

        <Section n={5} title="What remains unknown">
          <Bullets items={x.unknowns} />
        </Section>

        <Section n={6} title="What to investigate next">
          <Bullets items={x.next_steps} ordered />
        </Section>

        <Section n={7} title="What could make this a false positive">
          <Bullets items={x.false_positives} />
        </Section>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="MITRE ATT&CK">
          {x.mitre.length === 0 ? (
            <p className="text-[12px] text-ink-muted">
              This finding is not mapped: the matched conditions do not justify a specific technique.
            </p>
          ) : (
            <ul className="space-y-2 text-[12px]">
              {x.mitre.map((m) => (
                <li key={m.id}>
                  <a href={m.url} target="_blank" rel="noopener noreferrer" className="font-mono text-ink hover:text-ok">
                    {m.id} {m.name} ↗
                  </a>
                  <span className="ml-2 text-ink-faint">{m.tactics.join(', ')}</span>
                  <p className="text-ink-muted">{m.relationship}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Rule parameters when this alert was created">
          <pre className="whitespace-pre-wrap break-all font-mono text-[12px] text-ink-muted">
            {JSON.stringify(alert.rule_params, null, 2)}
          </pre>
        </Panel>
      </div>
    </>
  )
}

function Section({ n, title, children, padded = true }: { n: number; title: string; children: ReactNode; padded?: boolean }) {
  return (
    <Panel title={`${n}. ${title}`} padded={padded}>
      {children}
    </Panel>
  )
}

function Bullets({ items, ordered = false }: { items: string[]; ordered?: boolean }) {
  const Tag = ordered ? 'ol' : 'ul'
  return (
    <Tag className={`space-y-1 pl-5 text-[13px] text-ink-muted ${ordered ? 'list-decimal' : 'list-disc'}`}>
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </Tag>
  )
}
