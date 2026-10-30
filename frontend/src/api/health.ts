import { apiGet } from './client'

// Mirrors backend/app/schemas/health.py. Keep the two in sync.

export type ComponentStatus = 'ok' | 'degraded' | 'error'

export interface DatabaseComponent {
  status: ComponentStatus
  message: string
  schema_revision: string | null
  expected_revision: string | null
}

export interface DataSummary {
  event_count: number
  ingestion_batch_count: number
  latest_event_at: string | null
  last_ingestion_at: string | null
}

export interface HealthResponse {
  status: ComponentStatus
  version: string
  environment: string
  server_time: string
  database: DatabaseComponent
  data: DataSummary | null
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return apiGet<HealthResponse>('/api/v1/health', { signal })
}
