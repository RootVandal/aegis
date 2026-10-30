import { apiGet, apiRequestJson, toQueryString } from './client'
import type { AlertSummary } from './detection'
import type { EventSummary, Severity } from './events'

// Mirrors backend/app/schemas/investigation.py. Keep the two in sync.

export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'resolved'
export const INCIDENT_STATUSES: readonly IncidentStatus[] = ['new', 'investigating', 'contained', 'resolved']

export type Verdict = 'true_positive' | 'benign_activity' | 'false_positive' | 'inconclusive'
export const VERDICTS: readonly { value: Verdict; label: string }[] = [
  { value: 'true_positive', label: 'True positive: malicious or unauthorized activity confirmed' },
  { value: 'benign_activity', label: 'Benign activity: happened, but authorized or expected' },
  { value: 'false_positive', label: 'False positive: the detection misidentified the activity' },
  { value: 'inconclusive', label: 'Inconclusive: evidence does not support a conclusion' },
]

export interface IncidentSummary {
  id: number
  title: string
  severity: Severity
  status: IncidentStatus
  verdict: Verdict | null
  created_at: string
  updated_at: string
  alert_count: number
}

export interface IncidentDetail extends IncidentSummary {
  description: string
  resolved_at: string | null
  final_assessment: string | null
  resolution_summary: string | null
  allowed_transitions: IncidentStatus[]
  alerts: AlertSummary[]
  evidence: { id: number; note: string; author: string; added_at: string; event: EventSummary }[]
  notes: { id: number; kind: 'note' | 'hypothesis'; author: string; body: string; created_at: string }[]
  history: { action: string; summary: string; author: string; created_at: string }[]
}

export interface TimelineEntry {
  event: EventSummary
  sources: { kind: 'alert' | 'evidence' | 'correlated'; description: string; alert_id: number | null; rule_id: string | null }[]
  rule_ids: string[]
}

const base = (id: number | string) => `/api/v1/incidents/${encodeURIComponent(String(id))}`

export function fetchIncidents(
  status: string | undefined,
  signal?: AbortSignal,
): Promise<{ items: IncidentSummary[]; total: number }> {
  return apiGet(`/api/v1/incidents${toQueryString({ status })}`, { signal })
}

export function fetchIncident(id: string, signal?: AbortSignal): Promise<IncidentDetail> {
  return apiGet<IncidentDetail>(base(id), { signal })
}

export function createIncident(body: {
  title: string
  description?: string
  severity?: Severity
  alert_ids?: number[]
}): Promise<IncidentDetail> {
  return apiRequestJson<IncidentDetail>('POST', '/api/v1/incidents', body)
}

export function updateIncident(
  id: number,
  changes: { title?: string; description?: string; severity?: Severity; status?: IncidentStatus },
): Promise<IncidentDetail> {
  return apiRequestJson<IncidentDetail>('PATCH', base(id), changes)
}

export function linkAlerts(id: number, alertIds: number[]): Promise<IncidentDetail> {
  return apiRequestJson<IncidentDetail>('POST', `${base(id)}/alerts`, { alert_ids: alertIds })
}

export function unlinkAlert(id: number, alertId: number): Promise<IncidentDetail> {
  return apiRequestJson<IncidentDetail>('DELETE', `${base(id)}/alerts/${alertId}`)
}

export function addEvidence(id: number, eventId: string, note: string): Promise<IncidentDetail> {
  return apiRequestJson<IncidentDetail>('POST', `${base(id)}/evidence`, { event_id: eventId, note })
}

export function removeEvidence(id: number, evidenceId: number): Promise<IncidentDetail> {
  return apiRequestJson<IncidentDetail>('DELETE', `${base(id)}/evidence/${evidenceId}`)
}

export async function addIncidentNote(id: number, kind: 'note' | 'hypothesis', body: string): Promise<void> {
  await apiRequestJson('POST', `${base(id)}/notes`, { kind, body })
}

export function saveAssessment(
  id: number,
  body: { verdict: Verdict; final_assessment: string; resolution_summary: string },
): Promise<IncidentDetail> {
  return apiRequestJson<IncidentDetail>('PUT', `${base(id)}/assessment`, body)
}

export function fetchTimeline(id: string, includeCorrelated: boolean, signal?: AbortSignal): Promise<TimelineEntry[]> {
  return apiGet<TimelineEntry[]>(`${base(id)}/timeline${toQueryString({ include_correlated: includeCorrelated ? 'true' : undefined })}`, {
    signal,
  })
}

/** The report is Markdown text, not JSON. */
export async function fetchReport(id: number): Promise<string> {
  const response = await fetch(`${base(id)}/report`, { headers: { Accept: 'text/markdown' } })
  if (!response.ok) throw new Error(`Report request failed with HTTP ${response.status}.`)
  return response.text()
}
