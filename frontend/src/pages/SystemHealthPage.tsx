import type { ReactNode } from 'react'

import { isBackendUnreachable } from '../api/client'
import type { HealthResponse } from '../api/health'
import { StatusBadge } from '../components/StatusBadge'
import { useHealth } from '../health/HealthContext'
import { formatCount, formatUtc } from '../lib/format'

export function SystemHealthPage() {
  const { health, error, systemState } = useHealth()
  const unreachable = error !== null && isBackendUnreachable(error)

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 md:p-6">
      <p className="text-[13px] text-ink-muted">
        Live status of the AEGIS backend and its database, read from{' '}
        <code className="font-mono text-ink">GET /api/v1/health</code>.
      </p>

      {error && (
        <div role="alert" className="rounded-md border border-crit/40 bg-crit-dim px-4 py-3 text-[13px]">
          <p className="font-medium text-crit">
            {unreachable ? 'Cannot reach the AEGIS backend.' : 'The health check failed.'}
          </p>
          <p className="mt-1 text-ink-muted">{error.message}</p>
          {unreachable && (
            <p className="mt-2 text-ink-muted">
              Start the API with{' '}
              <code className="font-mono text-ink">uvicorn app.main:create_app --factory --reload</code>{' '}
              from the <code className="font-mono text-ink">backend</code> directory (see README).
            </p>
          )}
        </div>
      )}

      <Section title="Components">
        <table className="w-full text-left text-[13px]">
          <thead className="border-b border-line text-[11px] uppercase tracking-wider text-ink-faint">
            <tr>
              <th className="py-2 pr-4 font-medium">Component</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            <tr>
              <td className="py-2.5 pr-4 align-top text-ink">API server</td>
              <td className="py-2.5 pr-4 align-top">
                <StatusBadge
                  state={error ? systemState : health ? 'ok' : 'checking'}
                  label={error ? undefined : health ? 'Reachable' : undefined}
                />
              </td>
              <td className="py-2.5 align-top text-ink-muted">
                {health ? <ApiDetail health={health} /> : error ? 'No response.' : 'Waiting for response…'}
              </td>
            </tr>
            <tr>
              <td className="py-2.5 pr-4 align-top text-ink">Database</td>
              <td className="py-2.5 pr-4 align-top">
                {health ? (
                  <StatusBadge state={health.database.status} />
                ) : (
                  <StatusBadge state="checking" label={error ? 'Unknown' : undefined} />
                )}
              </td>
              <td className="py-2.5 align-top text-ink-muted">
                {health ? (
                  <>
                    {health.database.message}
                    <div className="mt-1 font-mono text-[12px] text-ink-faint">
                      schema {health.database.schema_revision ?? 'none'} · expected{' '}
                      {health.database.expected_revision ?? 'none'}
                    </div>
                  </>
                ) : (
                  'Unknown while the API is unavailable.'
                )}
              </td>
            </tr>
          </tbody>
        </table>
      </Section>

      <Section title="Stored data">
        <StoredData health={health} />
      </Section>
    </div>
  )
}

function ApiDetail({ health }: { health: HealthResponse }) {
  return (
    <span className="font-mono text-[12px]">
      v{health.version} · {health.environment} · server time {formatUtc(health.server_time)}
    </span>
  )
}

function StoredData({ health }: { health: HealthResponse | null }) {
  if (!health) {
    return <p className="text-[13px] text-ink-muted">Unavailable until the API responds.</p>
  }
  if (!health.data) {
    return (
      <p className="text-[13px] text-ink-muted">
        Unavailable: the database schema is not current, so counts cannot be read reliably.
      </p>
    )
  }

  const { data } = health
  return (
    <>
      <dl className="grid grid-cols-1 gap-x-8 gap-y-3 text-[13px] sm:grid-cols-2">
        <Field label="Events stored" value={formatCount(data.event_count)} />
        <Field label="Ingestion batches" value={formatCount(data.ingestion_batch_count)} />
        <Field label="Newest event timestamp" value={formatUtc(data.latest_event_at)} />
        <Field label="Last ingestion finished" value={formatUtc(data.last_ingestion_at)} />
      </dl>
      {data.event_count === 0 && (
        <p className="mt-4 border-t border-line pt-3 text-[13px] text-ink-muted">
          No events have been ingested yet. Event ingestion and the sample dataset are delivered in
          milestone 2.
        </p>
      )}
    </>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line/60 pb-2">
      <dt className="text-ink-muted">{label}</dt>
      <dd className="font-mono text-ink">{value}</dd>
    </div>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-md border border-line bg-surface">
      <h2 className="border-b border-line px-4 py-2 text-[11px] font-medium uppercase tracking-wider text-ink-muted">
        {title}
      </h2>
      <div className="overflow-x-auto px-4 py-3">{children}</div>
    </section>
  )
}
