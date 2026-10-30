import { apiGet, apiRequestJson } from './client'

// Mirrors backend/app/api/routes/evaluation.py. Keep the two in sync.

export type Metric = number | null

export interface RuleMetrics {
  tp: number
  fp: number
  fn: number
  tn: number
  precision: Metric
  recall: Metric
  f1: Metric
  fp_cases: string[]
  fn_cases: string[]
}

export interface CaseResult {
  case_id: string
  category: string
  expected: string[]
  fired: string[]
  outcomes: Record<string, 'tp' | 'fp' | 'fn' | 'tn'>
  records: number
  rejected: number
  input_handled_as_expected: boolean
}

export interface RunSummary {
  id: number
  created_at: string
  dataset_id: string
  dataset_version: string
  settings_source: 'current' | 'defaults'
  micro: { tp: number; fp: number; fn: number; tn: number; precision: Metric; recall: Metric; f1: Metric }
  input_handling_ok: boolean
}

export interface RunDetail extends RunSummary {
  rules: Record<string, { version: number; params: Record<string, unknown>; enabled: boolean }>
  results: {
    per_rule: Record<string, RuleMetrics>
    totals: {
      micro: RunSummary['micro']
      macro: Record<'precision' | 'recall' | 'f1', { value: Metric; rules: number }>
    }
    cases: CaseResult[]
    input_handling_ok: boolean
  }
  comparison: {
    previous_run_id: number
    dataset_changed: boolean
    rules: Record<string, { delta: Record<'tp' | 'fp' | 'fn' | 'tn', number>; version: [number, number]; params_changed: boolean }>
  } | null
}

export interface EvaluationDataset {
  id: string
  name: string
  version: string
  case_count: number
  categories: Record<string, number>
  metric_definitions: Record<string, string>
}

export interface EvaluationCase {
  id: string
  title: string
  category: string
  description: string
  expected: string[]
  records: Record<string, unknown>[]
  expected_rejected: number
}

export const fetchEvaluationDatasets = (signal?: AbortSignal) =>
  apiGet<EvaluationDataset[]>('/api/v1/evaluation/datasets', { signal })

export const fetchEvaluationCases = (datasetId: string, signal?: AbortSignal) =>
  apiGet<EvaluationCase[]>(`/api/v1/evaluation/datasets/${encodeURIComponent(datasetId)}/cases`, { signal })

export const fetchEvaluationRuns = (signal?: AbortSignal) =>
  apiGet<RunSummary[]>('/api/v1/evaluation/runs', { signal })

export const fetchEvaluationRun = (id: number, signal?: AbortSignal) =>
  apiGet<RunDetail>(`/api/v1/evaluation/runs/${id}`, { signal })

export const startEvaluationRun = (settings: 'current' | 'defaults') =>
  apiRequestJson<RunDetail>('POST', '/api/v1/evaluation/runs', { settings })
