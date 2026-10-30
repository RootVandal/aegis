import { apiGet, apiRequestJson } from './client'
import type { AlertSummary } from './detection'

// Mirrors backend/app/schemas/scenarios.py. Keep the two in sync.

export type Difficulty = 'beginner' | 'intermediate' | 'advanced'
export type AttemptStatus = 'in_progress' | 'submitted' | 'revealed'

export interface ScenarioSummary {
  id: string
  title: string
  difficulty: Difficulty
  summary: string
  relevant_rules: string[]
  event_count: number
  loaded_events: number
  attempt_count: number
  completed: boolean
  latest_attempt: { id: number; status: AttemptStatus; completed: boolean | null } | null
}

export interface ScenarioDetail extends ScenarioSummary {
  scenario_tag: string
  context: string
  objectives: string[]
  hint_count: number
  questions: { id: string; prompt: string; options: { id: string; text: string }[] }[]
  alerts: AlertSummary[]
}

export interface Evaluation {
  completed: boolean
  objectives: { objective: string; met: boolean; detail: string }[]
  questions: {
    id: string
    prompt: string
    your_answer: string | null
    correct_answer: string
    correct: boolean
    explanation: string
  }[]
  evidence: {
    required: { description: string; event_ids: string[]; cited: boolean }[]
    decoys_cited: { event_ids: string[]; why: string }[]
    supporting_cited: string[]
    unrelated_cited: string[]
  }
}

export interface Solution {
  reasoning: string[]
  false_positive_discussion: string[]
  required_evidence: { description: string; event_ids: string[] }[]
  supporting_evidence: string[]
  decoys: { event_ids: string[]; why: string }[]
  answers: Record<string, { correct: string; explanation: string }>
}

export interface Attempt {
  id: number
  scenario_id: string
  status: AttemptStatus
  started_at: string
  finished_at: string | null
  elapsed_seconds: number
  hints: string[]
  hints_remaining: number
  answers: Record<string, string>
  evidence_event_ids: string[]
  rationale: string
  evaluation: Evaluation | null
  solution: Solution | null
}

export interface Submission {
  answers: Record<string, string>
  evidence_event_ids: string[]
  rationale: string
}

export const fetchScenarios = (signal?: AbortSignal) => apiGet<ScenarioSummary[]>('/api/v1/scenarios', { signal })

export const fetchScenario = (id: string, signal?: AbortSignal) =>
  apiGet<ScenarioDetail>(`/api/v1/scenarios/${encodeURIComponent(id)}`, { signal })

export const fetchAttempts = (id: string, signal?: AbortSignal) =>
  apiGet<Attempt[]>(`/api/v1/scenarios/${encodeURIComponent(id)}/attempts`, { signal })

export const startAttempt = (id: string) =>
  apiRequestJson<Attempt>('POST', `/api/v1/scenarios/${encodeURIComponent(id)}/attempts`)

export const revealHint = (attemptId: number) =>
  apiRequestJson<Attempt>('POST', `/api/v1/scenario-attempts/${attemptId}/hints`)

export const submitAttempt = (attemptId: number, submission: Submission) =>
  apiRequestJson<Attempt>('POST', `/api/v1/scenario-attempts/${attemptId}/submit`, submission)

export const revealSolution = (attemptId: number) =>
  apiRequestJson<Attempt>('POST', `/api/v1/scenario-attempts/${attemptId}/reveal`)
