import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { ALERT_STATUSES, fetchAlerts, fetchRules, type AlertFilters } from '../../api/detection'
import { SEVERITIES } from '../../api/events'
import { SeverityBadge } from '../../components/Badges'
import { BUTTON, ErrorNotice, INPUT, Panel } from '../../components/Panel'
import { formatCount, formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

const KEYS = ['status', 'severity', 'rule_id', 'page'] as const satisfies readonly (keyof AlertFilters)[]
const PAGE_SIZE = 50

export function AlertsPage() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const filters: AlertFilters = {}
  for (const key of KEYS) {
    const value = params.get(key)
    if (value) filters[key] = value
  }
  const alerts = useApi((signal) => fetchAlerts(filters, signal), params.toString())
  const rules = useApi((signal) => fetchRules(signal), 'rules')

  const set = (key: keyof AlertFilters, value: string | undefined) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    if (key !== 'page') next.delete('page')
    setParams(next)
  }
  const page = Number(filters.page ?? '1')

  return (
    <div className="space-y-4 p-4 md:p-6">
      <p className="text-[13px] text-ink-muted">
        Alerts are created by the detection rules from stored events. Status changes, notes and incidents arrive in
        milestone 4; for now every alert is shown with its current status.
      </p>

      <Panel title="Filters">
        <div className="grid grid-cols-1 gap-3 text-[12px] sm:grid-cols-3">
          <Select label="Status" value={filters.status} onChange={(v) => set('status', v)}
                  options={ALERT_STATUSES.map((s) => [s, s.replace('_', ' ')])} />
          <Select label="Severity" value={filters.severity} onChange={(v) => set('severity', v)}
                  options={SEVERITIES.map((s) => [s, s])} />
          <Select label="Rule" value={filters.rule_id} onChange={(v) => set('rule_id', v)}
                  options={(rules.data ?? []).map((r) => [r.id, `${r.id} — ${r.name}`])} />
        </div>
      </Panel>

      {alerts.status === 'error' && <ErrorNotice error={alerts.error} what="alerts" />}
      {alerts.status !== 'error' && (
        <Panel title="Alerts" padded={false}>
          {alerts.status === 'loading' && <p className="px-4 py-4 text-[13px] text-ink-muted">Loading alerts…</p>}
          {alerts.status === 'success' && alerts.data.total === 0 && (
            <p className="px-4 py-4 text-[13px] text-ink-muted">
              {Object.keys(filters).length > 0 ? (
                'No alerts match these filters.'
              ) : (
                <>
                  No alerts yet. Alerts appear when imported events match a rule; the{' '}
                  <Link to="/events/import" className="text-ok hover:underline">
                    detection lab dataset
                  </Link>{' '}
                  produces one for every rule.
                </>
              )}
            </p>
          )}
          {alerts.status === 'success' && alerts.data.total > 0 && (
            <>
              <table className="w-full min-w-[920px] text-left text-[12px]">
                <thead className="border-b border-line text-[11px] uppercase tracking-wider text-ink-faint">
                  <tr>
                    {['#', 'Severity', 'Alert', 'Rule', 'Hosts', 'Users', 'Events', 'Last seen (UTC)', 'Status'].map(
                      (h) => (
                        <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">
                          {h}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {alerts.data.items.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => navigate(`/alerts/${alert.id}`)}
                      className="cursor-pointer align-top hover:bg-surface-raised"
                    >
                      <td className="px-3 py-1.5 pl-4 font-mono text-ink-faint">
                        <Link to={`/alerts/${alert.id}`} onClick={(e) => e.stopPropagation()} className="hover:text-ok">
                          {alert.id}
                        </Link>
                      </td>
                      <td className="px-3 py-1.5">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-3 py-1.5 text-ink">{alert.title}</td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-ink-muted">{alert.rule_id}</td>
                      <td className="px-3 py-1.5 font-mono">{alert.hosts.join(', ') || '—'}</td>
                      <td className="px-3 py-1.5 font-mono">{alert.users.join(', ') || '—'}</td>
                      <td className="px-3 py-1.5 font-mono">{alert.event_count}</td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-ink-muted">
                        {formatUtc(alert.last_seen).replace(' UTC', '')}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 text-ink-muted">{alert.status.replace('_', ' ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="flex items-center justify-between border-t border-line px-4 py-2 text-[12px] text-ink-muted">
                <span className="font-mono">
                  {formatCount((page - 1) * PAGE_SIZE + 1)}–{formatCount(Math.min(page * PAGE_SIZE, alerts.data.total))} of{' '}
                  {formatCount(alerts.data.total)}
                </span>
                <div className="flex gap-2">
                  <button type="button" className={BUTTON} disabled={page <= 1} onClick={() => set('page', String(page - 1))}>
                    Previous
                  </button>
                  <button
                    type="button"
                    className={BUTTON}
                    disabled={page * PAGE_SIZE >= alerts.data.total}
                    onClick={() => set('page', String(page + 1))}
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </Panel>
      )}
    </div>
  )
}

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: string | undefined
  options: [string, string][]
  onChange: (value: string | undefined) => void
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-ink-faint">{label}</span>
      <select className={INPUT} value={value ?? ''} onChange={(e) => onChange(e.target.value || undefined)}>
        <option value="">Any</option>
        {options.map(([optionValue, text]) => (
          <option key={optionValue} value={optionValue}>
            {text}
          </option>
        ))}
      </select>
    </label>
  )
}
