import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { ApiError } from '../../api/client'
import {
  MAX_UPLOAD_BYTES,
  fetchBatches,
  fetchDatasets,
  loadDataset,
  uploadEventsFile,
  type IngestionResult,
} from '../../api/events'
import { IngestionStatusBadge, OriginBadge } from '../../components/Badges'
import { BUTTON, BUTTON_PRIMARY, ErrorNotice, Panel } from '../../components/Panel'
import { useHealth } from '../../health/HealthContext'
import { formatCount, formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

const EXAMPLE = `{"event_id":"lab-0001","timestamp":"2026-10-05T08:15:00Z","event_source":"windows-security","event_type":"authentication_failure","hostname":"dc-01","username":"a.kowalski","source_ip":"10.10.1.11","windows_event_id":4625}`

export function ImportPage() {
  const { refresh } = useHealth()
  const [reloadToken, setReloadToken] = useState(0)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<IngestionResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [file, setFile] = useState<File | null>(null)

  const datasets = useApi((signal) => fetchDatasets(signal), 'datasets')
  const batches = useApi((signal) => fetchBatches(signal), 'batches', reloadToken)

  const run = async (action: () => Promise<IngestionResult>) => {
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      setResult(await action())
      setReloadToken((token) => token + 1)
      refresh()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Import failed.')
    } finally {
      setBusy(false)
    }
  }

  const upload = (event: FormEvent) => {
    event.preventDefault()
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      setResult(null)
      setError(`${file.name} is ${formatCount(file.size)} bytes; the limit is ${formatCount(MAX_UPLOAD_BYTES)} bytes.`)
      return
    }
    void run(() => uploadEventsFile(file))
  }

  return (
    <div className="mx-auto max-w-5xl space-y-5 p-4 md:px-8 md:py-7">
      <Link to="/events" className="text-[12px] text-ink-muted hover:text-ink">
        ← Event Explorer
      </Link>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Upload a file">
          <form onSubmit={upload} className="space-y-3 text-[13px]">
            <p className="text-ink-muted">
              <span className="font-mono text-ink">.jsonl</span> / <span className="font-mono text-ink">.ndjson</span>{' '}
              (one JSON object per line) or <span className="font-mono text-ink">.json</span> (an object or an array of
              objects). Up to {formatCount(MAX_UPLOAD_BYTES / 1024 / 1024)} MB. Uploaded events are labelled{' '}
              <OriginBadge origin="imported" />.
            </p>
            <input
              type="file"
              accept=".jsonl,.ndjson,.json"
              aria-label="Event file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="block w-full text-[12px] text-ink-muted file:mr-3 file:rounded-sm file:border file:border-line-strong file:bg-surface-raised file:px-2 file:py-1 file:text-ink"
            />
            <button type="submit" className={BUTTON_PRIMARY} disabled={!file || busy}>
              {busy ? 'Importing…' : 'Import'}
            </button>
          </form>
          <details className="mt-3 text-[12px] text-ink-muted">
            <summary className="cursor-pointer">Minimal JSONL line</summary>
            <pre className="mt-2 whitespace-pre-wrap break-all rounded-sm bg-canvas p-2 font-mono text-ink">{EXAMPLE}</pre>
            <p className="mt-1">
              Required: <span className="font-mono">timestamp</span>, <span className="font-mono">event_source</span>,{' '}
              <span className="font-mono">event_type</span>. The full field reference is in{' '}
              <span className="font-mono">docs/EVENT_FORMAT.md</span>.
            </p>
          </details>
        </Panel>

        <Panel title="Sample datasets">
          {datasets.status === 'error' && <ErrorNotice error={datasets.error} what="datasets" />}
          {datasets.status === 'loading' && <p className="text-[13px] text-ink-muted">Loading…</p>}
          {datasets.status === 'success' && (
            <ul className="space-y-3">
              {datasets.data.map((dataset) => (
                <li key={dataset.id} className="text-[13px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-medium text-ink">{dataset.name}</span>
                    <button
                      type="button"
                      className={BUTTON}
                      disabled={busy}
                      onClick={() => void run(() => loadDataset(dataset.id))}
                    >
                      Load {formatCount(dataset.event_count)} events
                    </button>
                  </div>
                  <p className="mt-1 text-[12px] text-ink-muted">
                    <OriginBadge origin={dataset.data_origin} /> {dataset.description}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      {error && (
        <div role="alert" className="rounded-md border border-crit/40 bg-crit-dim px-4 py-3 text-[13px] text-crit">
          {error}
        </div>
      )}
      {result && <ResultPanel result={result} />}

      <Panel title="Recent ingestion batches" padded={false}>
        {batches.status === 'error' && (
          <div className="p-4">
            <ErrorNotice error={batches.error} what="ingestion history" />
          </div>
        )}
        {batches.status === 'success' && batches.data.length === 0 && (
          <p className="px-4 py-4 text-[13px] text-ink-muted">Nothing has been ingested yet.</p>
        )}
        {batches.status === 'success' && batches.data.length > 0 && (
          <table className="w-full min-w-[720px] text-left text-[12px]">
            <thead className="border-b border-line text-[12px] font-medium text-ink-faint">
              <tr>
                {['#', 'Source', 'Origin', 'Status', 'Received', 'Accepted', 'Duplicate', 'Rejected', 'Finished (UTC)'].map(
                  (h) => (
                    <th key={h} className="px-3 py-2 font-medium first:pl-4">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-line font-mono">
              {batches.data.map((b) => (
                <tr key={b.id}>
                  <td className="px-3 py-1.5 pl-4 text-ink-faint">{b.id}</td>
                  <td className="px-3 py-1.5 text-ink">{b.source_name}</td>
                  <td className="px-3 py-1.5">
                    <OriginBadge origin={b.data_origin} />
                  </td>
                  <td className="px-3 py-1.5">
                    <IngestionStatusBadge status={b.status} />
                  </td>
                  <td className="px-3 py-1.5">{formatCount(b.received_count)}</td>
                  <td className="px-3 py-1.5">{formatCount(b.accepted_count)}</td>
                  <td className="px-3 py-1.5">{formatCount(b.duplicate_count)}</td>
                  <td className="px-3 py-1.5">{formatCount(b.rejected_count)}</td>
                  <td className="px-3 py-1.5 text-ink-muted">{formatUtc(b.completed_at).replace(' UTC', '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}

function ResultPanel({ result }: { result: IngestionResult }) {
  const { batch, rejections } = result
  return (
    <Panel title={`Import result — ${batch.source_name}`} actions={<IngestionStatusBadge status={batch.status} />}>
      <p className="font-mono text-[13px] text-ink">
        {formatCount(batch.received_count)} received · {formatCount(batch.accepted_count)} stored ·{' '}
        {formatCount(batch.duplicate_count)} duplicate · {formatCount(batch.rejected_count)} rejected
      </p>
      {batch.accepted_count > 0 && (
        <Link to="/events" className="mt-2 inline-block text-[12px] text-accent hover:underline">
          View events →
        </Link>
      )}
      {result.detection && (
        <p className="mt-2 font-mono text-[12px] text-ink-muted">
          Detection ran over {formatCount(result.detection.events_evaluated)} events:{' '}
          <span className={result.detection.alerts_created > 0 ? 'text-warn' : 'text-ink'}>
            {formatCount(result.detection.alerts_created)} new alert(s)
          </span>
          {result.detection.alerts_existing > 0 && `, ${formatCount(result.detection.alerts_existing)} already known`}
          {result.detection.alerts_created > 0 && (
            <Link to="/alerts" className="ml-2 font-sans text-accent hover:underline">
              View alerts →
            </Link>
          )}
        </p>
      )}
      {rejections.length > 0 && (
        <div className="mt-3">
          <h3 className="mb-1 text-[12px] font-medium text-ink-faint">
            Rejected records{batch.rejected_count > rejections.length ? ` (first ${rejections.length})` : ''}
          </h3>
          <ul className="max-h-60 space-y-1 overflow-auto font-mono text-[12px]">
            {rejections.map((r) => (
              <li key={r.position}>
                <span className="text-ink-faint">#{r.position}</span> <span className="text-warn">{r.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  )
}
