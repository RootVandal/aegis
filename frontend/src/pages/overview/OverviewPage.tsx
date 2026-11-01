import { useId, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { RANGES, fetchDashboard, type Dashboard, type DashboardRange } from '../../api/dashboard'
import { SEVERITIES, loadDataset } from '../../api/events'
import { IngestionStatusBadge, SeverityBadge } from '../../components/Badges'
import { BUTTON, BUTTON_PRIMARY, ErrorNotice, Panel } from '../../components/Panel'
import { useHealth } from '../../health/HealthContext'
import { formatCount, formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'
import { IncidentStatusBadge } from '../incidents/IncidentStatusBadge'
import { EventsChart } from './EventsChart'

// Single-hue magnitude bars (data-viz slot 1). Identity is carried by the
// label beside each bar (severity badge / rule name), never by bar color.
const BAR_COLOR = '#3987e5'

function isRange(value: string | null): value is DashboardRange {
  return RANGES.some((r) => r.value === value)
}

function ageInDays(iso: string, now: string): number {
  return Math.floor((new Date(now).getTime() - new Date(iso).getTime()) / 86_400_000)
}

export function OverviewPage() {
  const [params, setParams] = useSearchParams()
  const raw = params.get('range')
  const range: DashboardRange = isRange(raw) ? raw : 'all'
  const [reloadToken, setReloadToken] = useState(0)
  const dashboard = useApi((signal) => fetchDashboard(range, signal), range, reloadToken)

  // Refetch keeps the frame: show the previous result, dimmed, until the new one arrives.
  const [last, setLast] = useState<Dashboard | null>(null)
  if (dashboard.status === 'success' && dashboard.data !== last) setLast(dashboard.data)
  const shown = dashboard.data ?? last
  const refreshing = dashboard.status === 'loading' && last !== null

  return (
    <div className="space-y-5 p-4 md:px-8 md:py-7">
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Time range">
        {RANGES.map((option) => (
          <button
            key={option.value}
            type="button"
            aria-pressed={range === option.value}
            onClick={() => setParams(option.value === 'all' ? {} : { range: option.value })}
            className={`${BUTTON} ${range === option.value ? 'border-accent/50 bg-accent-dim text-ink' : ''}`}
          >
            {option.label}
          </button>
        ))}
        <button type="button" className={`${BUTTON} ml-auto`} onClick={() => setReloadToken((t) => t + 1)}>
          Refresh
        </button>
      </div>

      {dashboard.status === 'error' && <ErrorNotice error={dashboard.error} what="the dashboard" />}
      {!shown && dashboard.status === 'loading' && <p className="text-[13px] text-ink-muted">Loading dashboard…</p>}

      {shown && shown.data.events_total === 0 && <EmptyState onLoaded={() => setReloadToken((t) => t + 1)} />}

      {shown && shown.data.events_total > 0 && (
        <div className={`space-y-4 transition-opacity ${refreshing ? 'opacity-60' : ''}`} aria-busy={refreshing}>
          <Freshness dashboard={shown} />
          <Kpis dashboard={shown} />
          <Panel title={`Events over time · ${RANGES.find((r) => r.value === range)?.label}`}>
            {shown.in_range.events_over_time.points.length === 0 ? (
              <p className="py-6 text-center text-[13px] text-ink-muted">No events in this range.</p>
            ) : (
              <EventsChart
                points={shown.in_range.events_over_time.points}
                bucket={shown.in_range.events_over_time.bucket}
              />
            )}
          </Panel>
          <div className="grid gap-4 lg:grid-cols-2 [&>*]:min-w-0">
            <SeverityPanel dashboard={shown} />
            <TopRulesPanel dashboard={shown} />
          </div>
          <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
            <RecentAlerts dashboard={shown} />
            <RecentIncidents dashboard={shown} />
            <RecentIngestion dashboard={shown} />
          </div>
        </div>
      )}
    </div>
  )
}

function Freshness({ dashboard }: { dashboard: Dashboard }) {
  const { data, start, generated_at: now } = dashboard
  const latest = data.latest_event_at
  const stale = latest !== null && start !== null && latest < start
  return (
    <div className="space-y-2 text-[12px] text-ink-muted">
      <p>
        Stored: <span className="font-mono text-ink">{formatCount(data.synthetic_events)}</span> synthetic ·{' '}
        <span className="font-mono text-ink">{formatCount(data.imported_events)}</span> imported events. Newest event{' '}
        <span className="font-mono text-ink">{formatUtc(latest)}</span>
        {latest && ` (${ageInDays(latest, now)} days ago)`}. Figures computed at{' '}
        <span className="font-mono">{formatUtc(now)}</span>; nothing updates in the background.
      </p>
      {stale && (
        <p role="status" className="rounded-sm border border-warn/40 bg-warn-dim px-3 py-1.5 text-warn">
          The newest stored event is older than the selected range, so range-based figures are empty. Choose “All
          time” to see the stored data.
        </p>
      )}
    </div>
  )
}

function Kpis({ dashboard }: { dashboard: Dashboard }) {
  const { current, in_range: range } = dashboard
  return (
    <div className="grid gap-4 md:grid-cols-[3fr_2fr]">
      <KpiGroup title="Now (ignores the range)">
        <Tile label="New alerts" value={current.alerts_new} to="/alerts?status=new" />
        <Tile label="Open alerts" value={current.alerts_open} to="/alerts" hint="new, acknowledged or investigating" />
        <Tile label="Open incidents" value={current.incidents_open} to="/incidents" />
      </KpiGroup>
      <KpiGroup title="In the selected range">
        <Tile label="Events" value={range.events} to="/events" />
        <Tile label="Alerts raised" value={range.alerts} to="/alerts" hint="by time of their evidence" />
      </KpiGroup>
    </div>
  )
}

function KpiGroup({ title, children }: { title: string; children: ReactNode }) {
  const id = useId()
  return (
    <section aria-labelledby={id} className="rounded-xl border border-line bg-surface">
      <h2 id={id} className="border-b border-line/70 px-5 py-3 text-[13px] font-semibold text-ink">
        {title}
      </h2>
      <div className="grid grid-cols-2 divide-line sm:flex sm:divide-x">{children}</div>
    </section>
  )
}

function Tile({ label, value, to, hint }: { label: string; value: number; to: string; hint?: string }) {
  return (
    <Link to={to} className="block flex-1 px-5 py-4 transition-colors hover:bg-surface-raised" title={hint}>
      <div className="text-[12px] text-ink-muted">{label}</div>
      <div className="mt-1.5 text-[28px] font-semibold leading-none tracking-tight text-ink tabular-nums">{formatCount(value)}</div>
    </Link>
  )
}

function BarRow({ label, value, max, to }: { label: ReactNode; value: number; max: number; to?: string }) {
  const width = max > 0 ? Math.max((value / max) * 100, value > 0 ? 2 : 0) : 0
  const content = (
    <div className="grid grid-cols-[minmax(0,15rem)_1fr_3rem] items-center gap-3 px-1 py-1.5 text-[12px]">
      <div className="truncate">{label}</div>
      <div className="h-2 rounded-full bg-line/60">
        <div className="h-2 rounded-full" style={{ width: `${width}%`, background: BAR_COLOR }} />
      </div>
      <div className="text-right font-mono tabular-nums text-ink">{formatCount(value)}</div>
    </div>
  )
  return to ? (
    <Link to={to} className="block rounded-md transition-colors hover:bg-surface-raised">
      {content}
    </Link>
  ) : (
    content
  )
}

function SeverityPanel({ dashboard }: { dashboard: Dashboard }) {
  const counts = dashboard.in_range.alert_severity
  const max = Math.max(0, ...Object.values(counts))
  return (
    <Panel title="Alerts by severity (in range)">
      {dashboard.in_range.alerts === 0 ? (
        <p className="py-4 text-[13px] text-ink-muted">No alerts in this range.</p>
      ) : (
        SEVERITIES.map((severity) => (
          <BarRow
            key={severity}
            label={<SeverityBadge severity={severity} />}
            value={counts[severity] ?? 0}
            max={max}
            to={`/alerts?severity=${severity}`}
          />
        ))
      )}
    </Panel>
  )
}

function TopRulesPanel({ dashboard }: { dashboard: Dashboard }) {
  const rules = dashboard.in_range.top_rules
  const max = Math.max(0, ...rules.map((r) => r.count))
  return (
    <Panel title="Most frequently triggered rules (in range)">
      {rules.length === 0 ? (
        <p className="py-4 text-[13px] text-ink-muted">No rule has triggered in this range.</p>
      ) : (
        rules.map((rule) => (
          <BarRow
            key={rule.rule_id}
            label={<span className="text-ink-muted" title={rule.rule_id}>{rule.name}</span>}
            value={rule.count}
            max={max}
            to={`/alerts?rule_id=${rule.rule_id}`}
          />
        ))
      )}
    </Panel>
  )
}

function RecentAlerts({ dashboard }: { dashboard: Dashboard }) {
  return (
    <Panel title="Recent alerts" padded={false}>
      {dashboard.recent_alerts.length === 0 && <p className="px-4 py-3 text-[13px] text-ink-muted">No alerts yet.</p>}
      <ul className="divide-y divide-line">
        {dashboard.recent_alerts.map((alert) => (
          <li key={alert.id} className="px-4 py-2 text-[12px]">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <Link to={`/alerts/${alert.id}`} className="min-w-0 truncate text-ink hover:text-accent" title={alert.title}>
                {alert.title}
              </Link>
            </div>
            <div className="mt-0.5 font-mono text-[11px] text-ink-faint">
              #{alert.id} · {alert.rule_id} · {alert.status.replace('_', ' ')}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function RecentIncidents({ dashboard }: { dashboard: Dashboard }) {
  return (
    <Panel title="Recent incidents" padded={false}>
      {dashboard.recent_incidents.length === 0 && (
        <p className="px-4 py-3 text-[13px] text-ink-muted">No incidents yet.</p>
      )}
      <ul className="divide-y divide-line">
        {dashboard.recent_incidents.map((incident) => (
          <li key={incident.id} className="px-4 py-2 text-[12px]">
            <div className="flex items-center gap-2">
              <IncidentStatusBadge status={incident.status} />
              <Link to={`/incidents/${incident.id}`} className="min-w-0 truncate text-ink hover:text-accent" title={incident.title}>
                {incident.title}
              </Link>
            </div>
            <div className="mt-0.5 font-mono text-[11px] text-ink-faint">
              #{incident.id} · {incident.alert_count} alert(s) · updated {formatUtc(incident.updated_at)}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function RecentIngestion({ dashboard }: { dashboard: Dashboard }) {
  const run = dashboard.last_detection_run
  return (
    <Panel title="Recent ingestion" padded={false}>
      <ul className="divide-y divide-line">
        {dashboard.recent_batches.map((batch) => (
          <li key={batch.id} className="flex items-center gap-2 px-4 py-2 text-[12px]">
            <IngestionStatusBadge status={batch.status} />
            <span className="min-w-0 truncate font-mono text-ink" title={batch.source_name}>{batch.source_name}</span>
            <span className="ml-auto whitespace-nowrap font-mono text-[11px] text-ink-faint">
              +{formatCount(batch.accepted_count)} / {formatCount(batch.received_count)}
            </span>
          </li>
        ))}
      </ul>
      <p className="border-t border-line px-4 py-2 text-[11px] text-ink-faint">
        {run
          ? `Last detection run #${run.id} (${run.trigger}) at ${formatUtc(run.completed_at)}: ${run.alerts_created} new alert(s).`
          : 'Detection has not run yet.'}{' '}
        <Link to="/events/import" className="text-accent hover:underline">
          Import events →
        </Link>
      </p>
    </Panel>
  )
}

function EmptyState({ onLoaded }: { onLoaded: () => void }) {
  const { refresh } = useHealth()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const load = async (id: string) => {
    setBusy(true)
    setError(null)
    try {
      await loadDataset(id)
      refresh()
      onLoaded()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Loading failed.')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Panel title="No data yet">
      <p className="max-w-3xl text-[13px] text-ink-muted">
        AEGIS has no stored events, so there is nothing to summarize. Load a bundled <strong className="text-ink">synthetic</strong>{' '}
        dataset to explore the platform, or import your own JSONL / JSON file. Synthetic data stays labeled as such
        everywhere.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" className={BUTTON_PRIMARY} disabled={busy} onClick={() => void load('baseline')}>
          Load baseline office activity
        </button>
        <button type="button" className={BUTTON} disabled={busy} onClick={() => void load('detection-lab')}>
          Load detection lab (creates alerts)
        </button>
        <Link to="/events/import" className={BUTTON}>
          Import a file
        </Link>
      </div>
      {error && <p role="alert" className="mt-2 text-[12px] text-crit">{error}</p>}
    </Panel>
  )
}
