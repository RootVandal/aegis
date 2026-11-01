import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { addAlertNote, fetchAlert, updateAlertStatus, type AlertDetail, type AlertStatus } from '../../api/detection'
import { createIncident, fetchIncidents, linkAlerts } from '../../api/incidents'
import { BUTTON, BUTTON_PRIMARY, INPUT, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

const CLOSED: readonly AlertStatus[] = ['resolved', 'false_positive']
const label = (status: string) => status.replace('_', ' ')

/**
 * Triage controls for one alert. Every action calls the API and replaces
 * the displayed alert with the server's answer, so the page never shows a
 * state the backend did not accept.
 */
export function AlertTriage({ alert, onChange }: { alert: AlertDetail; onChange: (alert: AlertDetail) => void }) {
  const navigate = useNavigate()
  const [reason, setReason] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const openIncidents = useApi(
    (signal) => fetchIncidents(undefined, signal).then((page) => page.items.filter((i) => i.status !== 'resolved')),
    `open-incidents-${alert.incident?.id ?? 'none'}`,
  )
  const [targetIncident, setTargetIncident] = useState('')

  const act = async (action: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    try {
      await action()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'The action failed.')
    } finally {
      setBusy(false)
    }
  }
  const reload = async () => onChange(await fetchAlert(String(alert.id)))

  const changeStatus = (status: AlertStatus) =>
    act(async () => {
      onChange(await updateAlertStatus(alert.id, status, reason))
      setReason('')
    })

  const submitNote = (event: FormEvent) => {
    event.preventDefault()
    if (!note.trim()) return
    void act(async () => {
      await addAlertNote(alert.id, note)
      setNote('')
      await reload()
    })
  }

  const needsReason = (status: AlertStatus) => CLOSED.includes(status) || CLOSED.includes(alert.status)

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Triage">
        <div className="space-y-3 text-[12px]">
          <p className="text-ink-muted">
            Current status: <span className="font-medium capitalize text-ink">{label(alert.status)}</span>
          </p>
          <label className="block">
            <span className="mb-1 block text-ink-faint">Reason (required to close or reopen)</span>
            <textarea className={INPUT} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
          </label>
          <div className="flex flex-wrap gap-2">
            {alert.allowed_transitions.map((status) => (
              <button
                key={status}
                type="button"
                className={BUTTON}
                disabled={busy || (needsReason(status) && !reason.trim())}
                title={needsReason(status) && !reason.trim() ? 'Enter a reason first' : undefined}
                onClick={() => void changeStatus(status)}
              >
                Mark {label(status)}
              </button>
            ))}
          </div>

          <div className="border-t border-line pt-3">
            {alert.incident ? (
              <p>
                Part of{' '}
                <Link to={`/incidents/${alert.incident.id}`} className="text-accent hover:underline">
                  incident #{alert.incident.id}: {alert.incident.title}
                </Link>{' '}
                <span className="text-ink-faint">({alert.incident.status})</span>
              </p>
            ) : (
              <div className="space-y-2">
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className={BUTTON_PRIMARY}
                    disabled={busy}
                    onClick={() =>
                      void act(async () => {
                        const incident = await createIncident({ title: alert.title, alert_ids: [alert.id] })
                        navigate(`/incidents/${incident.id}`)
                      })
                    }
                  >
                    Create incident from this alert
                  </button>
                  <Link to={`/investigation?alert=${alert.id}`} className={BUTTON}>
                    Investigate related activity →
                  </Link>
                </div>
                {openIncidents.status === 'success' && openIncidents.data.length > 0 && (
                  <div className="flex gap-2">
                    <select
                      aria-label="Existing incident"
                      className={INPUT}
                      value={targetIncident}
                      onChange={(e) => setTargetIncident(e.target.value)}
                    >
                      <option value="">Add to an existing incident…</option>
                      {openIncidents.data.map((i) => (
                        <option key={i.id} value={i.id}>
                          #{i.id} {i.title}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      className={BUTTON}
                      disabled={busy || !targetIncident}
                      onClick={() =>
                        void act(async () => {
                          await linkAlerts(Number(targetIncident), [alert.id])
                          await reload()
                        })
                      }
                    >
                      Add
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
          {error && (
            <p role="alert" className="text-crit">
              {error}
            </p>
          )}
        </div>
      </Panel>

      <Panel title={`Notes and history (${alert.notes.length + alert.status_changes.length})`}>
        <form onSubmit={submitNote} className="mb-3 flex gap-2" aria-label="Add note">
          <input
            className={INPUT}
            placeholder="Add an investigation note…"
            value={note}
            maxLength={5000}
            onChange={(e) => setNote(e.target.value)}
          />
          <button type="submit" className={BUTTON} disabled={busy || !note.trim()}>
            Add
          </button>
        </form>
        <ul className="space-y-2 text-[12px]">
          {[
            ...alert.notes.map((n) => ({ at: n.created_at, key: `n${n.id}`, text: n.body, meta: `note · ${n.author}` })),
            ...alert.status_changes.map((c, i) => ({
              at: c.changed_at,
              key: `s${i}`,
              text: `${label(c.from_status)} → ${label(c.to_status)}${c.reason ? `: ${c.reason}` : ''}`,
              meta: `status · ${c.author}`,
            })),
          ]
            .sort((a, b) => b.at.localeCompare(a.at))
            .map((item) => (
              <li key={item.key} className="border-l-2 border-line-strong pl-2">
                <div className="font-mono text-[11px] text-ink-faint">
                  {formatUtc(item.at)} · {item.meta}
                </div>
                <div className="whitespace-pre-wrap break-words text-ink-muted">{item.text}</div>
              </li>
            ))}
          {alert.notes.length + alert.status_changes.length === 0 && (
            <li className="text-ink-faint">No notes or status changes yet.</li>
          )}
        </ul>
      </Panel>
    </div>
  )
}
