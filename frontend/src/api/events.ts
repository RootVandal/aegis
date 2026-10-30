import { apiGet, apiPost, toQueryString } from './client'
import type { DetectionRun } from './detection'

// Mirrors backend/app/schemas/events.py. Keep the two in sync.

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type DataOrigin = 'synthetic' | 'imported'
export type IngestionStatus = 'completed' | 'partial' | 'failed'

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'informational']

export interface EventSummary {
  event_id: string
  timestamp: string
  event_source: string
  event_type: string
  severity: Severity
  hostname: string | null
  username: string | null
  source_ip: string | null
  destination_ip: string | null
  destination_port: number | null
  process_name: string | null
  parent_process_name: string | null
  process_command_line: string | null
  windows_event_id: number | null
  data_origin: DataOrigin
  scenario_id: string | null
}

export interface EventDetail extends EventSummary {
  ingested_at: string
  batch_id: number | null
  raw_event: Record<string, unknown>
  normalized_fields: Record<string, unknown>
  /** Alerts that cite this event as evidence. */
  alerts: { id: number; rule_id: string; title: string; severity: Severity; status: string }[]
}

export interface EventPage {
  items: EventSummary[]
  total: number
  page: number
  page_size: number
}

export interface FacetValue {
  value: string
  count: number
}

export interface EventFacets {
  event_types: FacetValue[]
  event_sources: FacetValue[]
  severities: FacetValue[]
  data_origins: FacetValue[]
}

/** Filter values exactly as they appear in the page URL and the API query. */
export interface EventFilters {
  q?: string
  start?: string
  end?: string
  event_type?: string
  severity?: string
  hostname?: string
  username?: string
  source_ip?: string
  data_origin?: string
  sort?: string
  page?: string
}

export const PAGE_SIZE = 50

export function fetchEvents(filters: EventFilters, signal?: AbortSignal): Promise<EventPage> {
  return apiGet<EventPage>(`/api/v1/events${toQueryString({ ...filters, page_size: PAGE_SIZE })}`, {
    signal,
  })
}

export function fetchEvent(eventId: string, signal?: AbortSignal): Promise<EventDetail> {
  return apiGet<EventDetail>(`/api/v1/events/${encodeURIComponent(eventId)}`, { signal })
}

export function fetchFacets(signal?: AbortSignal): Promise<EventFacets> {
  return apiGet<EventFacets>('/api/v1/events/facets', { signal })
}

// --- Ingestion ---------------------------------------------------------------

export interface IngestionBatch {
  id: number
  source_name: string
  input_format: string
  data_origin: DataOrigin
  status: IngestionStatus
  started_at: string
  completed_at: string | null
  received_count: number
  accepted_count: number
  duplicate_count: number
  rejected_count: number
}

export interface IngestionResult {
  batch: IngestionBatch
  rejections: { position: number; message: string }[]
  /** Detection run started automatically after new events were stored. */
  detection?: DetectionRun | null
}

export interface Dataset {
  id: string
  name: string
  description: string
  data_origin: DataOrigin
  event_count: number
}

/** Matches the backend default (AEGIS_MAX_INGEST_BYTES). Checked client-side for a fast error. */
export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024

export function uploadEventsFile(file: File): Promise<IngestionResult> {
  const isJsonl = /\.(jsonl|ndjson)$/i.test(file.name)
  return apiPost<IngestionResult>(
    `/api/v1/ingestion/batches${toQueryString({ source_name: file.name })}`,
    file,
    isJsonl ? 'application/x-ndjson' : 'application/json',
  )
}

export function fetchBatches(signal?: AbortSignal): Promise<IngestionBatch[]> {
  return apiGet<IngestionBatch[]>('/api/v1/ingestion/batches', { signal })
}

export function fetchDatasets(signal?: AbortSignal): Promise<Dataset[]> {
  return apiGet<Dataset[]>('/api/v1/datasets', { signal })
}

export function loadDataset(id: string): Promise<IngestionResult> {
  return apiPost<IngestionResult>(`/api/v1/datasets/${encodeURIComponent(id)}/load`)
}
