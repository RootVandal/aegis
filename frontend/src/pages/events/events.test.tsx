import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import { App } from '../../App'
import { HealthProvider } from '../../health/HealthContext'
import { eventPage, eventSummary, jsonResponse, routeFetch } from '../../test/fixtures'
import { localInputToUtc, utcToLocalInput } from './FilterBar'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <HealthProvider pollIntervalMs={0}>
        <App />
      </HealthProvider>
    </MemoryRouter>,
  )
}

/** URLs of every GET /api/v1/events request made so far. */
function eventRequests(): URL[] {
  return fetchMock.mock.calls
    .map(([input]) => new URL(String(input), 'http://localhost'))
    .filter((url) => url.pathname === '/api/v1/events')
}

describe('Event Explorer', () => {
  it('lists events from the API with their origin', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/events': () =>
          jsonResponse(eventPage([eventSummary(), eventSummary({ event_id: 'evt-2', data_origin: 'imported' })])),
      }),
    )
    renderAt('/events')

    const table = await screen.findByRole('table')
    expect(within(table).getAllByText('authentication_failure')).toHaveLength(2)
    expect(within(table).getByText('synthetic')).toBeInTheDocument()
    expect(within(table).getByText('imported')).toBeInTheDocument()
    expect(screen.getByText('1–2 of 2')).toBeInTheDocument()
  })

  it('sends applied filters to the API and shows them as removable chips', async () => {
    fetchMock.mockImplementation(
      routeFetch({ 'GET /api/v1/events': () => jsonResponse(eventPage([eventSummary()])) }),
    )
    renderAt('/events')
    await screen.findByRole('table')

    await userEvent.type(screen.getByRole('textbox', { name: 'Search' }), 'powershell')
    await userEvent.type(screen.getByPlaceholderText('ws-fin-01'), 'ws-it-01')
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))

    await waitFor(() => {
      const last = eventRequests().at(-1)!
      expect(last.searchParams.get('q')).toBe('powershell')
      expect(last.searchParams.get('hostname')).toBe('ws-it-01')
    })
    const chips = screen.getByRole('list', { name: 'Active filters' })
    await userEvent.click(within(chips).getByRole('button', { name: /hostname=ws-it-01/ }))

    await waitFor(() => {
      const last = eventRequests().at(-1)!
      expect(last.searchParams.get('hostname')).toBeNull()
      expect(last.searchParams.get('q')).toBe('powershell')
    })
  })

  it('offers the sample dataset when the database is empty, and loads it', async () => {
    let loaded = false
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/events': () => jsonResponse(loaded ? eventPage([eventSummary()]) : eventPage([])),
        'POST /api/v1/datasets/baseline/load': () => {
          loaded = true
          return jsonResponse({ batch: {}, rejections: [] }, 201)
        },
      }),
    )
    renderAt('/events')

    await userEvent.click(await screen.findByRole('button', { name: 'Load sample dataset' }))

    expect(await screen.findByRole('table')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load sample dataset' })).not.toBeInTheDocument()
  })

  it('distinguishes "no matches" from "no data"', async () => {
    fetchMock.mockImplementation(routeFetch({}))
    renderAt('/events?q=nothing-matches')

    expect(await screen.findByText('No events match these filters.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load sample dataset' })).not.toBeInTheDocument()
  })

  it('pages through results', async () => {
    fetchMock.mockImplementation(
      routeFetch({ 'GET /api/v1/events': () => jsonResponse(eventPage([eventSummary()], 120)) }),
    )
    renderAt('/events')
    expect(await screen.findByText('1–50 of 120')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()

    await userEvent.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => expect(eventRequests().at(-1)!.searchParams.get('page')).toBe('2'))
  })

  it('reports an API error instead of an empty table', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/events': () =>
          jsonResponse({ error: { code: 'validation_error', message: 'Request validation failed.' } }, 422),
      }),
    )
    renderAt('/events')

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load events.')
  })
})

describe('Event detail', () => {
  const detail = {
    ...eventSummary({
      event_type: 'process_creation',
      process_name: 'powershell.exe',
      process_command_line: '<script>alert("x")</script>',
    }),
    ingested_at: '2026-10-30T10:00:00Z',
    batch_id: 7,
    raw_event: { Image: 'C:\\Windows\\powershell.exe', CommandLine: '<script>alert("x")</script>' },
    normalized_fields: { notes: ['timestamp had no timezone; assumed UTC'], user_domain: 'CORP' },
    alerts: [{ id: 6, rule_id: 'AEGIS-EXEC-001', title: 'Suspicious PowerShell', severity: 'high' as const, status: 'new' }],
  }

  it('shows normalized fields, the original record and normalization notes', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/events/evt-1': () => jsonResponse(detail) }))
    renderAt('/events/evt-1')

    expect(await screen.findByText('Original record (as ingested)')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '#6 Suspicious PowerShell' })).toHaveAttribute('href', '/alerts/6')
    expect(screen.getByText('Normalization notes:').parentElement).toHaveTextContent(
      'timestamp had no timezone; assumed UTC',
    )
    expect(screen.getByText(/"Image": "C:\\\\Windows\\\\powershell.exe"/)).toBeInTheDocument()
  })

  it('renders hostile field content as inert text', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/events/evt-1': () => jsonResponse(detail) }))
    const { container } = renderAt('/events/evt-1')

    expect(await screen.findAllByText(/<script>alert\("x"\)<\/script>/)).not.toHaveLength(0)
    expect(container.querySelector('script')).toBeNull()
  })

  it('encodes event IDs in the request path', async () => {
    fetchMock.mockImplementation(
      routeFetch({ 'GET /api/v1/events/sha256%3Aabc': () => jsonResponse({ ...detail, event_id: 'sha256:abc' }) }),
    )
    renderAt('/events/sha256%3Aabc')

    expect(await screen.findByText('sha256:abc')).toBeInTheDocument()
  })

  it('shows the API error for an unknown event', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/events/missing': () =>
          jsonResponse({ error: { code: 'event_not_found', message: "No event with ID 'missing'." } }, 404),
      }),
    )
    renderAt('/events/missing')

    expect(await screen.findByRole('alert')).toHaveTextContent("No event with ID 'missing'.")
  })
})

describe('Import page', () => {
  const importRoutes = {
    'GET /api/v1/datasets': () => jsonResponse([]),
    'GET /api/v1/ingestion/batches': () => jsonResponse([]),
  }

  it('uploads a JSONL file and reports accepted and rejected records', async () => {
    let request: { url: URL; init?: RequestInit } | null = null
    fetchMock.mockImplementation(
      routeFetch({
        ...importRoutes,
        'POST /api/v1/ingestion/batches': (url, init) => {
          request = { url, init }
          return jsonResponse(
            {
              batch: {
                id: 1,
                source_name: 'lab.jsonl',
                input_format: 'jsonl',
                data_origin: 'imported',
                status: 'partial',
                started_at: '2026-10-30T10:00:00Z',
                completed_at: '2026-10-30T10:00:01Z',
                received_count: 3,
                accepted_count: 2,
                duplicate_count: 0,
                rejected_count: 1,
              },
              rejections: [{ position: 3, message: 'source_ip: is not a valid IPv4 or IPv6 address' }],
            },
            201,
          )
        },
      }),
    )
    renderAt('/events/import')

    const file = new File(['{"a":1}\n'], 'lab.jsonl', { type: '' })
    await userEvent.upload(await screen.findByLabelText('Event file'), file)
    await userEvent.click(screen.getByRole('button', { name: 'Import' }))

    expect(await screen.findByText(/3 received · 2 stored · 0 duplicate · 1 rejected/)).toBeInTheDocument()
    expect(screen.getByText('source_ip: is not a valid IPv4 or IPv6 address')).toBeInTheDocument()
    expect(request!.url.searchParams.get('source_name')).toBe('lab.jsonl')
    expect((request!.init?.headers as Record<string, string>)['Content-Type']).toBe('application/x-ndjson')
  })

  it('rejects an oversized file before uploading it', async () => {
    fetchMock.mockImplementation(routeFetch(importRoutes))
    renderAt('/events/import')

    const big = new File(['x'], 'huge.json')
    Object.defineProperty(big, 'size', { value: 6 * 1024 * 1024 })
    await userEvent.upload(await screen.findByLabelText('Event file'), big)
    await userEvent.click(screen.getByRole('button', { name: 'Import' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('the limit is')
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })
})

describe('datetime-local helpers', () => {
  it('treat the input as UTC in both directions', () => {
    expect(localInputToUtc('2026-10-05T08:30')).toBe('2026-10-05T08:30:00Z')
    expect(localInputToUtc('')).toBeUndefined()
    expect(utcToLocalInput('2026-10-05T08:30:00Z')).toBe('2026-10-05T08:30')
  })
})
