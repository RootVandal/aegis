import { apiGet, apiRequestJson, toQueryString } from './client'
import type { EventSummary, Severity } from './events'

// Mirrors backend/app/schemas/detection.py. Keep the two in sync.

export type AlertStatus = 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive'
export const ALERT_STATUSES: readonly AlertStatus[] = ['new', 'acknowledged', 'investigating', 'resolved', 'false_positive']

export interface MitreSummary {
  id: string
  name: string
  tactics: string[]
  url: string
}

export interface MitreDetail extends MitreSummary {
  relationship: string
  telemetry: string
  limitations: string
}

export interface RuleSummary {
  id: string
  name: string
  version: number
  description: string
  severity: Severity
  enabled: boolean
  customized: boolean
  event_types: string[]
  mitre: MitreSummary[]
  alert_count: number
}

export type ParamValue = number | boolean | string | string[] | number[] | Record<string, string>

export interface RuleDetail extends RuleSummary {
  logic: string[]
  required_fields: string[]
  mitre_details: MitreDetail[]
  investigation_steps: string[]
  false_positives: string[]
  limitations: string[]
  unknowns: string[]
  changelog: { version: number; date: string; description: string }[]
  params: Record<string, ParamValue>
  default_params: Record<string, ParamValue>
  overrides: Record<string, ParamValue>
  params_schema: { properties?: Record<string, ParamSchema> }
  attack_version: string
}

export interface ParamSchema {
  type?: string
  description?: string
  enum?: string[]
  minimum?: number
  maximum?: number
  items?: { type?: string }
}

export interface DetectionRun {
  id: number
  trigger: 'manual' | 'ingestion'
  started_at: string
  completed_at: string | null
  events_evaluated: number
  findings_count: number
  alerts_created: number
  alerts_existing: number
  rules: { rule_id: string; version: number; params: Record<string, unknown>; findings: number }[]
}

export interface AlertSummary {
  id: number
  rule_id: string
  rule_name: string
  rule_version: number
  title: string
  severity: Severity
  status: AlertStatus
  created_at: string
  first_seen: string
  last_seen: string
  event_count: number
  hosts: string[]
  users: string[]
  ips: string[]
  incident_id: number | null
}

export interface Explanation {
  what: string
  triggering_events: { event_id: string; timestamp: string; description: string }[]
  conditions: { description: string; observed: string }[]
  evidence: {
    event_count: number
    first_seen: string
    last_seen: string
    hosts: string[]
    users: string[]
    ips: string[]
  }
  unknowns: string[]
  next_steps: string[]
  false_positives: string[]
  mitre: (MitreSummary & { relationship: string; attack_version: string })[]
  rule: { id: string; name: string; version: number; params: Record<string, unknown> }
  disclaimer: string
}

export interface AlertDetail extends AlertSummary {
  explanation: Explanation
  rule_params: Record<string, unknown>
  detection_run_id: number | null
  events: EventSummary[]
  notes: { id: number; author: string; body: string; created_at: string }[]
  status_changes: {
    from_status: AlertStatus
    to_status: AlertStatus
    reason: string | null
    author: string
    changed_at: string
  }[]
  incident: { id: number; title: string; status: string } | null
  allowed_transitions: AlertStatus[]
}

export interface AlertPage {
  items: AlertSummary[]
  total: number
  page: number
  page_size: number
}

export interface AlertFilters {
  status?: string
  severity?: string
  rule_id?: string
  q?: string
  sort?: string
  page?: string
}

export function fetchRules(signal?: AbortSignal): Promise<RuleSummary[]> {
  return apiGet<RuleSummary[]>('/api/v1/rules', { signal })
}

export function fetchRule(id: string, signal?: AbortSignal): Promise<RuleDetail> {
  return apiGet<RuleDetail>(`/api/v1/rules/${encodeURIComponent(id)}`, { signal })
}

export function updateRule(
  id: string,
  update: { enabled?: boolean; params?: Record<string, ParamValue> },
): Promise<RuleDetail> {
  return apiRequestJson<RuleDetail>('PATCH', `/api/v1/rules/${encodeURIComponent(id)}`, update)
}

export function runDetection(): Promise<DetectionRun> {
  return apiRequestJson<DetectionRun>('POST', '/api/v1/detections/runs')
}

export function fetchRuns(signal?: AbortSignal): Promise<DetectionRun[]> {
  return apiGet<DetectionRun[]>('/api/v1/detections/runs?limit=5', { signal })
}

export function fetchAlerts(filters: AlertFilters, signal?: AbortSignal): Promise<AlertPage> {
  return apiGet<AlertPage>(`/api/v1/alerts${toQueryString({ ...filters, page_size: 50 })}`, { signal })
}

export function fetchAlert(id: string, signal?: AbortSignal): Promise<AlertDetail> {
  return apiGet<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(id)}`, { signal })
}

export function updateAlertStatus(id: number, status: AlertStatus, reason?: string): Promise<AlertDetail> {
  return apiRequestJson<AlertDetail>('PATCH', `/api/v1/alerts/${id}`, { status, reason: reason || undefined })
}

export function addAlertNote(id: number, body: string): Promise<unknown> {
  return apiRequestJson('POST', `/api/v1/alerts/${id}/notes`, { body })
}

export type Criterion = 'host' | 'user' | 'ip' | 'scenario'
export const CRITERIA: readonly Criterion[] = ['host', 'user', 'ip', 'scenario']

export interface CorrelatedEvent {
  event: EventSummary
  reasons: { criterion: string; value: string; description: string }[]
  relation: 'before' | 'during' | 'after'
  offset_seconds: number
  explanation: string
  alert_ids: number[]
  rule_ids: string[]
}

export interface Correlation {
  window_minutes: number
  criteria: string[]
  seed_event_ids: string[]
  total: number
  truncated: boolean
  events: CorrelatedEvent[]
  related_alerts: { alert: AlertSummary; shared_event_ids: string[] }[]
}

export function fetchCorrelation(
  alertId: string,
  windowMinutes: number,
  criteria: readonly Criterion[],
  signal?: AbortSignal,
): Promise<Correlation> {
  const query = toQueryString({ window_minutes: windowMinutes, criteria })
  return apiGet<Correlation>(`/api/v1/alerts/${encodeURIComponent(alertId)}/correlation${query}`, { signal })
}
