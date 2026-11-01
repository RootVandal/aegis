import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { SEVERITIES, type Severity } from '../../api/events'
import { INCIDENT_STATUSES, createIncident, fetchIncidents } from '../../api/incidents'
import { SeverityBadge } from '../../components/Badges'
import { BUTTON, BUTTON_PRIMARY, ErrorNotice, INPUT, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'
import { IncidentStatusBadge } from './IncidentStatusBadge'

export function IncidentsPage() {
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? undefined
  const incidents = useApi((signal) => fetchIncidents(status, signal), status ?? 'all')
  const [creating, setCreating] = useState(false)

  return (
    <div className="space-y-5 p-4 md:px-8 md:py-7">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-[13px] text-ink-muted">
          Incidents group related alerts and evidence into one investigation with a documented outcome. Lifecycle:
          new → investigating → contained → resolved. Resolving requires a final assessment.
        </p>
        <button type="button" className={BUTTON_PRIMARY} onClick={() => setCreating((v) => !v)}>
          {creating ? 'Cancel' : 'New incident'}
        </button>
      </div>

      {creating && <NewIncidentForm />}

      <div className="flex flex-wrap gap-2 text-[12px]" role="group" aria-label="Status filter">
        {[undefined, ...INCIDENT_STATUSES].map((value) => (
          <button
            key={value ?? 'all'}
            type="button"
            aria-pressed={status === value}
            onClick={() => setParams(value ? { status: value } : {})}
            className={`${BUTTON} ${status === value ? 'border-accent/50 bg-accent-dim text-ink' : ''}`}
          >
            {value ?? 'all'}
          </button>
        ))}
      </div>

      {incidents.status === 'error' && <ErrorNotice error={incidents.error} what="incidents" />}
      <Panel title="Incidents" padded={false}>
        {incidents.status === 'success' && incidents.data.items.length === 0 && (
          <p className="px-4 py-4 text-[13px] text-ink-muted">
            No incidents{status ? ` with status ${status}` : ''}. Create one here, or from an alert.
          </p>
        )}
        {incidents.status === 'success' && incidents.data.items.length > 0 && (
          <table className="w-full min-w-[760px] text-left text-[12px]">
            <thead className="border-b border-line text-[12px] font-medium text-ink-faint">
              <tr>
                {['#', 'Severity', 'Title', 'Status', 'Alerts', 'Verdict', 'Updated (UTC)'].map((h) => (
                  <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {incidents.data.items.map((incident) => (
                <tr key={incident.id} className="hover:bg-surface-raised">
                  <td className="px-3 py-1.5 pl-4 font-mono text-ink-faint">{incident.id}</td>
                  <td className="px-3 py-1.5">
                    <SeverityBadge severity={incident.severity} />
                  </td>
                  <td className="px-3 py-1.5">
                    <Link to={`/incidents/${incident.id}`} className="text-ink hover:text-accent">
                      {incident.title}
                    </Link>
                  </td>
                  <td className="px-3 py-1.5">
                    <IncidentStatusBadge status={incident.status} />
                  </td>
                  <td className="px-3 py-1.5 font-mono">{incident.alert_count}</td>
                  <td className="px-3 py-1.5 text-ink-muted">{incident.verdict?.replace('_', ' ') ?? '—'}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-ink-muted">
                    {formatUtc(incident.updated_at).replace(' UTC', '')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}

function NewIncidentForm() {
  const navigate = useNavigate()
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<Severity>('medium')
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setError(null)
    try {
      const incident = await createIncident({ title, description, severity })
      navigate(`/incidents/${incident.id}`)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Could not create the incident.')
    }
  }

  return (
    <Panel title="New incident">
      <form onSubmit={(e) => void submit(e)} className="grid gap-3 text-[12px] md:grid-cols-[2fr_1fr]">
        <label className="block">
          <span className="mb-1 block text-ink-faint">Title</span>
          <input className={INPUT} required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
        </label>
        <label className="block">
          <span className="mb-1 block text-ink-faint">Severity</span>
          <select className={INPUT} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="block md:col-span-2">
          <span className="mb-1 block text-ink-faint">Description</span>
          <textarea className={INPUT} rows={3} maxLength={5000} value={description}
                    onChange={(e) => setDescription(e.target.value)} />
        </label>
        <div className="flex items-center gap-3 md:col-span-2">
          <button type="submit" className={BUTTON_PRIMARY} disabled={!title.trim()}>
            Create
          </button>
          {error && <span role="alert" className="text-crit">{error}</span>}
        </div>
      </form>
    </Panel>
  )
}
