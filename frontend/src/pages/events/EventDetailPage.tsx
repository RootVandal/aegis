import { Link, useParams } from 'react-router-dom'

import { fetchEvent, type EventDetail } from '../../api/events'
import { OriginBadge, SeverityBadge } from '../../components/Badges'
import { ErrorNotice, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

const FIELDS: { key: keyof EventDetail; label: string }[] = [
  { key: 'event_id', label: 'Event ID' },
  { key: 'timestamp', label: 'Timestamp' },
  { key: 'event_source', label: 'Source' },
  { key: 'event_type', label: 'Type' },
  { key: 'hostname', label: 'Host' },
  { key: 'username', label: 'User' },
  { key: 'source_ip', label: 'Source IP' },
  { key: 'destination_ip', label: 'Destination IP' },
  { key: 'destination_port', label: 'Destination port' },
  { key: 'process_name', label: 'Process' },
  { key: 'parent_process_name', label: 'Parent process' },
  { key: 'process_command_line', label: 'Command line' },
  { key: 'windows_event_id', label: 'Windows event ID' },
  { key: 'scenario_id', label: 'Scenario' },
  { key: 'ingested_at', label: 'Ingested at' },
  { key: 'batch_id', label: 'Ingestion batch' },
]

export function EventDetailPage() {
  const { eventId = '' } = useParams()
  const event = useApi((signal) => fetchEvent(eventId, signal), eventId)

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 md:p-6">
      <Link to="/events" className="text-[12px] text-ink-muted hover:text-ink">
        ← Event Explorer
      </Link>

      {event.status === 'loading' && <p className="text-[13px] text-ink-muted">Loading event…</p>}
      {event.status === 'error' && <ErrorNotice error={event.error} what="this event" />}
      {event.status === 'success' && <EventView event={event.data} />}
    </div>
  )
}

function EventView({ event }: { event: EventDetail }) {
  const notes = Array.isArray(event.normalized_fields.notes) ? (event.normalized_fields.notes as string[]) : []

  return (
    <>
      <header className="flex flex-wrap items-center gap-3">
        <h2 className="font-mono text-base text-ink">{event.event_type}</h2>
        <SeverityBadge severity={event.severity} />
        <OriginBadge origin={event.data_origin} />
        <span className="font-mono text-[12px] text-ink-muted">{formatUtc(event.timestamp)}</span>
      </header>

      <Panel title={`Cited by alerts (${event.alerts.length})`}>
        {event.alerts.length === 0 ? (
          <p className="text-[12px] text-ink-muted">No alert uses this event as evidence.</p>
        ) : (
          <ul className="space-y-1 text-[12px]">
            {event.alerts.map((alert) => (
              <li key={alert.id} className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={alert.severity} />
                <Link to={`/alerts/${alert.id}`} className="text-ink hover:text-ok">
                  #{alert.id} {alert.title}
                </Link>
                <span className="font-mono text-ink-faint">
                  {alert.rule_id} · {alert.status.replace('_', ' ')}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {notes.length > 0 && (
        <div className="rounded-md border border-warn/40 bg-warn-dim px-4 py-2 text-[12px] text-warn">
          <span className="font-medium">Normalization notes:</span> {notes.join('; ')}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Normalized fields">
          <dl className="divide-y divide-line text-[12px]">
            {FIELDS.map(({ key, label }) => (
              <div key={key} className="grid grid-cols-[150px_1fr] gap-3 py-1.5">
                <dt className="text-ink-muted">{label}</dt>
                <dd className="break-all font-mono text-ink">{display(event, key)}</dd>
              </div>
            ))}
          </dl>
          {Object.keys(event.normalized_fields).length > 0 && (
            <>
              <h3 className="mt-4 mb-1 text-[11px] uppercase tracking-wider text-ink-faint">
                Additional normalized fields
              </h3>
              <JsonBlock value={event.normalized_fields} />
            </>
          )}
        </Panel>

        <Panel title="Original record (as ingested)">
          <JsonBlock value={event.raw_event} />
        </Panel>
      </div>
    </>
  )
}

function display(event: EventDetail, key: keyof EventDetail): string {
  const value = event[key]
  if (value === null || value === undefined || value === '') return '—'
  if (key === 'timestamp' || key === 'ingested_at') return formatUtc(String(value))
  return String(value)
}

/**
 * Event content is attacker-controlled. It is rendered as plain text inside
 * <pre>, which React escapes, so markup in a field can never execute.
 */
function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="max-h-[480px] overflow-auto whitespace-pre-wrap break-all rounded-sm bg-canvas p-3 font-mono text-[12px] leading-relaxed text-ink">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}
