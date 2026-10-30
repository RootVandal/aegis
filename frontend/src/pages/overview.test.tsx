import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import type { Dashboard } from '../api/dashboard'
import { App } from '../App'
import { HealthProvider } from '../health/HealthContext'
import { jsonResponse, routeFetch } from '../test/fixtures'

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

function dashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  return {
    range: 'all',
    start: null,
    end: '2026-10-31T10:00:00Z',
    generated_at: '2026-10-31T10:00:00Z',
    data: {
      events_total: 260,
      synthetic_events: 254,
      imported_events: 6,
      earliest_event_at: '2026-10-05T01:00:00Z',
      latest_event_at: '2026-10-08T11:04:00Z',
    },
    current: { alerts_new: 17, alerts_open: 19, incidents_open: 1 },
    in_range: {
      events: 260,
      alerts: 19,
      alert_severity: { high: 12, medium: 7 },
      top_rules: [{ rule_id: 'AEGIS-PERS-001', name: 'Persistence Mechanism Changes', count: 4 }],
      events_over_time: {
        bucket: 'day',
        points: [
          { start: '2026-10-05T00:00:00Z', synthetic: 70, imported: 0 },
          { start: '2026-10-06T00:00:00Z', synthetic: 66, imported: 6 },
        ],
      },
    },
    recent_alerts: [],
    recent_incidents: [],
    recent_batches: [
      {
        id: 1, source_name: 'sample:baseline', input_format: 'json', data_origin: 'synthetic', status: 'completed',
        started_at: '', completed_at: '', received_count: 203, accepted_count: 203, duplicate_count: 0, rejected_count: 0,
      },
    ],  // prettier-ignore
    last_detection_run: null,
    ...overrides,
  }
}

function dashboardRequests(): URL[] {
  return fetchMock.mock.calls
    .map(([input]) => new URL(String(input), 'http://x'))
    .filter((url) => url.pathname === '/api/v1/dashboard')
}

describe('Overview', () => {
  it('shows real figures with links to the underlying lists', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/dashboard': () => jsonResponse(dashboard()) }))
    renderAt('/overview')

    const now = await screen.findByRole('region', { name: 'Now (ignores the range)' })
    expect(within(now).getByRole('link', { name: /New alerts\s*17/ })).toHaveAttribute('href', '/alerts?status=new')
    expect(within(now).getByRole('link', { name: /Open incidents\s*1/ })).toHaveAttribute('href', '/incidents')
    expect(screen.getByText(/days ago/)).toHaveTextContent('2026-10-08 11:04:00 UTC (22 days ago)')
    expect(screen.getByRole('link', { name: /Persistence Mechanism Changes\s*4/ })).toHaveAttribute(
      'href',
      '/alerts?rule_id=AEGIS-PERS-001',
    )
  })

  it('offers the chart data as a table', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/dashboard': () => jsonResponse(dashboard()) }))
    renderAt('/overview')

    await userEvent.click(await screen.findByRole('button', { name: 'Show as table' }))

    const rows = screen.getAllByRole('row').map((row) => row.textContent)
    expect(rows).toContain('10-06666')
  })

  it('changes the range through the URL and keeps the previous frame while loading', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/dashboard': () => jsonResponse(dashboard()) }))
    renderAt('/overview')
    await screen.findByRole('region', { name: 'Now (ignores the range)' })

    await userEvent.click(screen.getByRole('button', { name: 'Last 7 days' }))

    await waitFor(() => expect(dashboardRequests().at(-1)!.searchParams.get('range')).toBe('7d'))
    expect(screen.getByRole('button', { name: 'Last 7 days' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('explains an empty range instead of hiding it', async () => {
    const empty = dashboard({
      range: '7d',
      start: '2026-10-24T10:00:00Z',
      in_range: { events: 0, alerts: 0, alert_severity: {}, top_rules: [], events_over_time: { bucket: 'day', points: [] } },
    })
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/dashboard': () => jsonResponse(empty) }))
    renderAt('/overview?range=7d')

    expect(await screen.findByRole('status')).toHaveTextContent('older than the selected range')
    expect(screen.getByText('No events in this range.')).toBeInTheDocument()
    expect(screen.getByText('No alerts in this range.')).toBeInTheDocument()
  })

  it('offers sample data when nothing is stored, and reloads after loading it', async () => {
    let loaded = false
    const empty = dashboard({
      data: { events_total: 0, synthetic_events: 0, imported_events: 0, earliest_event_at: null, latest_event_at: null },
    })
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/dashboard': () => jsonResponse(loaded ? dashboard() : empty),
        'POST /api/v1/datasets/baseline/load': () => {
          loaded = true
          return jsonResponse({ batch: {}, rejections: [] }, 201)
        },
      }),
    )
    renderAt('/overview')

    await userEvent.click(await screen.findByRole('button', { name: 'Load baseline office activity' }))

    expect(await screen.findByRole('region', { name: 'Now (ignores the range)' })).toBeInTheDocument()
  })
})
