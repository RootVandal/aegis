import { apiGet } from './client'
import type { AlertSummary, DetectionRun } from './detection'
import type { IngestionBatch } from './events'
import type { IncidentSummary } from './incidents'

// Mirrors backend/app/api/routes/dashboard.py. Keep the two in sync.

export type DashboardRange = 'all' | '30d' | '7d' | '24h'
export const RANGES: readonly { value: DashboardRange; label: string }[] = [
  { value: 'all', label: 'All time' },
  { value: '30d', label: 'Last 30 days' },
  { value: '7d', label: 'Last 7 days' },
  { value: '24h', label: 'Last 24 hours' },
]

export interface TimePoint {
  start: string
  synthetic: number
  imported: number
}

export interface Dashboard {
  range: DashboardRange
  start: string | null
  end: string
  generated_at: string
  data: {
    events_total: number
    synthetic_events: number
    imported_events: number
    earliest_event_at: string | null
    latest_event_at: string | null
  }
  current: { alerts_new: number; alerts_open: number; incidents_open: number }
  in_range: {
    events: number
    alerts: number
    alert_severity: Record<string, number>
    top_rules: { rule_id: string; name: string; count: number }[]
    events_over_time: { bucket: 'hour' | 'day' | 'month'; points: TimePoint[] }
  }
  recent_alerts: AlertSummary[]
  recent_incidents: IncidentSummary[]
  recent_batches: IngestionBatch[]
  last_detection_run: DetectionRun | null
}

export function fetchDashboard(range: DashboardRange, signal?: AbortSignal): Promise<Dashboard> {
  return apiGet<Dashboard>(`/api/v1/dashboard?range=${range}`, { signal })
}
