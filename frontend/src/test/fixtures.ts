import type { EventPage, EventSummary } from '../api/events'
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

export function eventSummary(overrides: Partial<EventSummary> = {}): EventSummary {
  return {
    event_id: 'evt-1',
    timestamp: '2026-10-05T08:15:00Z',
    event_source: 'windows-security',
    event_type: 'authentication_failure',
    severity: 'medium',
    hostname: 'dc-01',
    username: 'a.kowalski',
    source_ip: '10.10.1.11',
    destination_ip: null,
    destination_port: null,
    process_name: null,
    parent_process_name: null,
    process_command_line: null,
    windows_event_id: 4625,
    data_origin: 'synthetic',
    scenario_id: null,
    ...overrides,
  }
}

export function eventPage(items: EventSummary[], total = items.length, page = 1): EventPage {
  return { items, total, page, page_size: 50 }
}

const EMPTY_FACETS = { event_types: [], event_sources: [], severities: [], data_origins: [] }

type Handler = (url: URL, init?: RequestInit) => Response | Promise<Response>

/**
 * A fetch mock that answers by path, so one test can serve several endpoints.
 * Health, facets and an empty event list have defaults; anything else unmatched fails loudly.
 */
export function routeFetch(handlers: Record<string, Handler>) {
  const defaults: Record<string, Handler> = {
    'GET /api/v1/health': () => jsonResponse(healthResponse()),
    'GET /api/v1/events/facets': () => jsonResponse(EMPTY_FACETS),
    'GET /api/v1/events': () => jsonResponse(eventPage([])),
    'GET /api/v1/incidents': () => jsonResponse({ items: [], total: 0, page: 1, page_size: 50 }),
  }
  const routes = { ...defaults, ...handlers }
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'http://localhost')
    const key = `${init?.method ?? 'GET'} ${url.pathname}`
    const handler = routes[key]
    if (!handler) throw new Error(`Unexpected request in test: ${key}`)
    return handler(url, init)
  }
}
