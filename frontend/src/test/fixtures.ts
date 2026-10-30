import type { HealthResponse } from '../api/health'

export function healthResponse(overrides: Partial<HealthResponse> = {}): HealthResponse {
  return {
    status: 'ok',
    version: '0.1.0',
    environment: 'test',
    server_time: '2026-10-30T12:00:00Z',
    database: {
      status: 'ok',
      message: 'Connected; schema is up to date.',
      schema_revision: '0001',
      expected_revision: '0001',
    },
    data: {
      event_count: 0,
      ingestion_batch_count: 0,
      latest_event_at: null,
      last_ingestion_at: null,
    },
    ...overrides,
  }
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}
