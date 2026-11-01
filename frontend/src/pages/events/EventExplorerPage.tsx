import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import {
  PAGE_SIZE,
  fetchEvents,
  fetchFacets,
  loadDataset,
  type EventFilters,
  type EventSummary,
} from '../../api/events'
import { OriginBadge, SeverityBadge } from '../../components/Badges'
import { BUTTON, BUTTON_PRIMARY, ErrorNotice, Panel } from '../../components/Panel'
import { useHealth } from '../../health/HealthContext'
import { formatCount, formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'
import { FilterBar } from './FilterBar'

const FILTER_KEYS = [
  'q',
  'start',
  'end',
  'event_type',
  'severity',
  'hostname',
  'username',
  'source_ip',
  'data_origin',
  'scenario_id',
  'sort',
  'page',
] as const satisfies readonly (keyof EventFilters)[]

const FILTER_LABELS: Partial<Record<keyof EventFilters, string>> = {
  q: 'search',
  start: 'from',
  end: 'to',
  event_type: 'type',
  source_ip: 'source IP',
  data_origin: 'origin',
  scenario_id: 'scenario',
}

function readFilters(params: URLSearchParams): EventFilters {
  const filters: EventFilters = {}
  for (const key of FILTER_KEYS) {
    const value = params.get(key)
    if (value) filters[key] = value
  }
  return filters
}

export function EventExplorerPage() {
  const [params, setParams] = useSearchParams()
  const filters = readFilters(params)
  const queryKey = params.toString()
  const [reloadToken, setReloadToken] = useState(0)
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null)

  const events = useApi(
    (signal) =>
      fetchEvents(filters, signal).then((page) => {
        setFetchedAt(new Date())
        return page
      }),
    queryKey,
    reloadToken,
  )
  const facets = useApi((signal) => fetchFacets(signal), 'facets', reloadToken)

  const apply = (next: EventFilters) => {
    const search = new URLSearchParams()
    for (const key of FILTER_KEYS) {
      const value = next[key]
      if (value) search.set(key, value)
    }
    setParams(search)
  }
  const reload = () => setReloadToken((token) => token + 1)

  const activeFilters = FILTER_KEYS.filter((key) => key !== 'page' && key !== 'sort' && filters[key])
  const page = Number(filters.page ?? '1')
  const origins = facets.data?.data_origins ?? []
  // No events at all (not just "no matches"): offer to load data instead of an empty table.
  const databaseIsEmpty = events.status === 'success' && events.data.total === 0 && activeFilters.length === 0

  return (
    <div className="space-y-5 p-4 md:px-8 md:py-7">
      <div className="flex flex-wrap items-center justify-between gap-3 text-[12px] text-ink-muted">
        <p>
          Stored events:{' '}
          {origins.length === 0
            ? 'none'
            : origins.map((o) => `${formatCount(o.count)} ${o.value}`).join(' · ')}
          {fetchedAt && <span className="ml-3 font-mono text-ink-faint">fetched {fetchedAt.toLocaleTimeString()}</span>}
        </p>
        <div className="flex gap-2">
          <button type="button" className={BUTTON} onClick={reload}>
            Refresh
          </button>
          <Link to="/events/import" className={BUTTON_PRIMARY}>
            Import events
          </Link>
        </div>
      </div>

      <Panel title="Filters">
        {/* key: reset the editable draft whenever the URL filters change. */}
        <FilterBar key={queryKey} filters={filters} facets={facets.data} onApply={apply} />
        {activeFilters.length > 0 && (
          <ul className="mt-3 flex flex-wrap gap-1.5" aria-label="Active filters">
            {activeFilters.map((key) => (
              <li key={key}>
                <button
                  type="button"
                  onClick={() => apply({ ...filters, [key]: undefined, page: undefined })}
                  className="rounded-sm border border-line-strong bg-surface-raised px-1.5 py-0.5 font-mono text-[11px] text-ink hover:border-ink-faint"
                  title="Remove filter"
                >
                  {FILTER_LABELS[key] ?? key}={key === 'start' || key === 'end' ? formatUtc(filters[key]) : filters[key]} ×
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {events.status === 'error' && <ErrorNotice error={events.error} what="events" />}

      {databaseIsEmpty ? (
        <EmptyDatabase onLoaded={reload} />
      ) : (
        events.status !== 'error' && (
        <Panel
          title="Events"
          padded={false}
          actions={
            <SortToggle
              sort={filters.sort ?? 'timestamp_desc'}
              onChange={(sort) => apply({ ...filters, sort, page: undefined })}
            />
          }
        >
          {events.status === 'loading' ? (
            <p className="px-4 py-6 text-[13px] text-ink-muted">Loading events…</p>
          ) : events.data.items.length === 0 ? (
            <p className="px-4 py-6 text-[13px] text-ink-muted">No events match these filters.</p>
          ) : (
            <EventTable items={events.data.items} />
          )}
          {events.status === 'success' && events.data.total > 0 && (
            <Pagination
              page={page}
              total={events.data.total}
              onPage={(next) => apply({ ...filters, page: next > 1 ? String(next) : undefined })}
            />
          )}
        </Panel>
        )
      )}
    </div>
  )
}

function EventTable({ items }: { items: EventSummary[] }) {
  const navigate = useNavigate()
  return (
    <table className="w-full min-w-[900px] text-left text-[12px]">
      <thead className="border-b border-line text-[12px] font-medium text-ink-faint">
        <tr>
          {['Time (UTC)', 'Severity', 'Type', 'Host', 'User', 'Source IP', 'Details', 'Origin'].map((h) => (
            <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {items.map((item) => {
          const href = `/events/${encodeURIComponent(item.event_id)}`
          return (
            <tr
              key={item.event_id}
              onClick={() => navigate(href)}
              className="cursor-pointer align-top hover:bg-surface-raised"
            >
              <td className="whitespace-nowrap px-3 py-1.5 pl-4 font-mono text-ink">
                <Link to={href} onClick={(e) => e.stopPropagation()} className="hover:text-accent">
                  {formatUtc(item.timestamp).replace(' UTC', '')}
                </Link>
              </td>
              <td className="px-3 py-1.5">
                <SeverityBadge severity={item.severity} />
              </td>
              <td className="whitespace-nowrap px-3 py-1.5 font-mono text-ink">{item.event_type}</td>
              <td className="whitespace-nowrap px-3 py-1.5 font-mono">{item.hostname ?? '—'}</td>
              <td className="whitespace-nowrap px-3 py-1.5 font-mono">{item.username ?? '—'}</td>
              <td className="whitespace-nowrap px-3 py-1.5 font-mono">{item.source_ip ?? '—'}</td>
              <td className="max-w-[420px] truncate px-3 py-1.5 font-mono text-ink-muted" title={describe(item)}>
                {describe(item)}
              </td>
              <td className="px-3 py-1.5">
                <OriginBadge origin={item.data_origin} />
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/** A one-line summary of whatever telemetry the event actually has. */
export function describe(item: EventSummary): string {
  if (item.process_command_line) return item.process_command_line
  const parts: string[] = []
  if (item.process_name) parts.push(item.process_name)
  if (item.destination_ip) {
    parts.push(`→ ${item.destination_ip}${item.destination_port !== null ? `:${item.destination_port}` : ''}`)
  }
  if (item.windows_event_id !== null) parts.push(`EventID ${item.windows_event_id}`)
  return parts.join(' ') || item.event_source
}

function SortToggle({ sort, onChange }: { sort: string; onChange: (sort: string) => void }) {
  const ascending = sort === 'timestamp_asc'
  return (
    <button type="button" className={BUTTON} onClick={() => onChange(ascending ? 'timestamp_desc' : 'timestamp_asc')}>
      {ascending ? 'Oldest first' : 'Newest first'}
    </button>
  )
}

function Pagination({ page, total, onPage }: { page: number; total: number; onPage: (page: number) => void }) {
  const first = (page - 1) * PAGE_SIZE + 1
  const last = Math.min(page * PAGE_SIZE, total)
  const pages = Math.ceil(total / PAGE_SIZE)
  return (
    <div className="flex items-center justify-between border-t border-line px-4 py-2 text-[12px] text-ink-muted">
      <span className="font-mono">
        {first > total ? `Page ${page} is past the end` : `${formatCount(first)}–${formatCount(last)} of ${formatCount(total)}`}
      </span>
      <div className="flex gap-2">
        <button type="button" className={BUTTON} disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Previous
        </button>
        <button type="button" className={BUTTON} disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Next
        </button>
      </div>
    </div>
  )
}

function EmptyDatabase({ onLoaded }: { onLoaded: () => void }) {
  const { refresh } = useHealth()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  const loadSample = async () => {
    setLoading(true)
    setError(null)
    try {
      await loadDataset('baseline')
      refresh()
      onLoaded()
    } catch (cause) {
      setError(cause instanceof ApiError ? cause : new ApiError(0, 'unknown_error', 'Loading failed.'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <Panel title="No events yet">
      <p className="text-[13px] text-ink-muted">
        The database is empty. Load the bundled <strong className="text-ink">synthetic</strong> baseline dataset (three
        ordinary office days, no attack activity) or import your own JSONL / JSON file.
      </p>
      <div className="mt-3 flex gap-2">
        <button type="button" className={BUTTON_PRIMARY} onClick={loadSample} disabled={loading}>
          {loading ? 'Loading…' : 'Load sample dataset'}
        </button>
        <Link to="/events/import" className={BUTTON}>
          Import a file
        </Link>
      </div>
      {error && <p className="mt-2 text-[12px] text-crit">{error.message}</p>}
    </Panel>
  )
}
