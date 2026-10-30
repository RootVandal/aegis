import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import type { AlertDetail, Correlation } from '../api/detection'
import type { IncidentDetail } from '../api/incidents'
import { App } from '../App'
import { HealthProvider } from '../health/HealthContext'
import { eventSummary, jsonResponse, routeFetch } from '../test/fixtures'

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

function bodyOf(method: string, path: string): unknown {
  const call = fetchMock.mock.calls.find(
    ([input, init]) => (init?.method ?? 'GET') === method && new URL(String(input), 'http://x').pathname === path,
  )
  return call ? JSON.parse(String(call[1]?.body)) : undefined
}

const alert: AlertDetail = {
  id: 1,
  rule_id: 'AEGIS-AUTH-001',
  rule_name: 'Multiple Failed Logins',
  rule_version: 1,
  title: '7 failed logins for user j.martin followed by a success',
  severity: 'high',
  status: 'new',
  created_at: '2026-10-30T10:00:00Z',
  first_seen: '2026-10-08T09:00:00Z',
  last_seen: '2026-10-08T09:02:30Z',
  event_count: 8,
  hosts: ['dc-01'],
  users: ['j.martin'],
  ips: ['10.10.1.99'],
  incident_id: null,
  rule_params: {},
  detection_run_id: 1,
  events: [eventSummary({ event_id: 'syn-lab-001' })],
  explanation: {
    what: 'Repeated failed authentication attempts.',
    triggering_events: [],
    conditions: [],
    evidence: { event_count: 8, first_seen: '', last_seen: '', hosts: [], users: [], ips: [] },
    unknowns: [],
    next_steps: [],
    false_positives: [],
    mitre: [],
    rule: { id: 'AEGIS-AUTH-001', name: 'Multiple Failed Logins', version: 1, params: {} },
    disclaimer: 'Not proof of compromise.',
  },
  notes: [],
  status_changes: [],
  incident: null,
  allowed_transitions: ['acknowledged', 'investigating', 'resolved', 'false_positive'],
}

function incident(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    id: 5,
    title: 'Brute force against j.martin',
    severity: 'high',
    status: 'investigating',
    verdict: null,
    created_at: '2026-10-30T10:00:00Z',
    updated_at: '2026-10-30T10:00:00Z',
    alert_count: 1,
    description: 'Opened from alert #1.',
    resolved_at: null,
    final_assessment: null,
    resolution_summary: null,
    allowed_transitions: ['contained', 'resolved'],
    alerts: [{ ...alert, status: 'investigating', incident_id: 5 }],
    evidence: [],
    notes: [{ id: 1, kind: 'hypothesis', author: 'analyst', body: 'Password was guessed.', created_at: '2026-10-30T10:05:00Z' }],
    history: [{ action: 'created', summary: 'Incident created', author: 'analyst', created_at: '2026-10-30T10:00:00Z' }],
    ...overrides,
  }
}

const timeline = [
  {
    event: eventSummary({ event_id: 'syn-lab-008', event_type: 'authentication_success' }),
    sources: [{ kind: 'alert', description: 'Evidence for alert #1 (AEGIS-AUTH-001)', alert_id: 1, rule_id: 'AEGIS-AUTH-001' }],
    rule_ids: ['AEGIS-AUTH-001'],
  },
]

describe('Alert triage', () => {
  it('closing an alert requires a reason, which is sent to the API', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/alerts/1': () => jsonResponse(alert),
        'PATCH /api/v1/alerts/1': () => jsonResponse({ ...alert, status: 'false_positive', allowed_transitions: ['investigating'] }),
      }),
    )
    renderAt('/alerts/1')

    const close = await screen.findByRole('button', { name: 'Mark false positive' })
    expect(close).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Mark acknowledged' })).toBeEnabled()

    await userEvent.type(screen.getByLabelText(/Reason/), 'Known test account.')
    await userEvent.click(close)

    await waitFor(() =>
      expect(bodyOf('PATCH', '/api/v1/alerts/1')).toEqual({ status: 'false_positive', reason: 'Known test account.' }),
    )
    expect(await screen.findByRole('button', { name: 'Mark investigating' })).toBeInTheDocument()
  })

  it('creates an incident from the alert and opens it', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/alerts/1': () => jsonResponse(alert),
        'POST /api/v1/incidents': () => jsonResponse(incident(), 201),
        'GET /api/v1/incidents/5': () => jsonResponse(incident()),
        'GET /api/v1/incidents/5/timeline': () => jsonResponse(timeline),
      }),
    )
    renderAt('/alerts/1')

    await userEvent.click(await screen.findByRole('button', { name: 'Create incident from this alert' }))

    expect(await screen.findByRole('heading', { name: /#5 Brute force against j.martin/ })).toBeInTheDocument()
    expect(bodyOf('POST', '/api/v1/incidents')).toEqual({ title: alert.title, alert_ids: [1] })
  })
})

describe('Investigation workspace', () => {
  const correlation: Correlation = {
    window_minutes: 60,
    criteria: ['host', 'ip', 'scenario', 'user'],
    seed_event_ids: ['syn-lab-001'],
    total: 1,
    truncated: false,
    events: [
      {
        event: eventSummary({ event_id: 'syn-lab-021', username: 'j.martin', hostname: 'vpn-01' }),
        reasons: [{ criterion: 'user', value: 'j.martin', description: 'Same user j.martin' }],
        relation: 'after',
        offset_seconds: 3480,
        explanation: 'Same user j.martin. Occurred 58 min after the seed events.',
        alert_ids: [2],
        rule_ids: ['AEGIS-AUTH-002'],
      },
    ],
    related_alerts: [
      {
        alert: { ...alert, id: 2, rule_id: 'AEGIS-AUTH-002', title: '198.51.100.23 failed to log on as 6 accounts' },
        shared_event_ids: ['syn-lab-021'],
      },
    ],
  }

  it('shows why each event is linked and narrows by criteria', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/alerts/1': () => jsonResponse(alert),
        'GET /api/v1/alerts/1/correlation': () => jsonResponse(correlation),
      }),
    )
    renderAt('/investigation?alert=1')

    expect(await screen.findByText('user: j.martin')).toBeInTheDocument()
    expect(screen.getByText('58 min after')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('checkbox', { name: 'host' }))

    await waitFor(() => {
      const last = fetchMock.mock.calls
        .map(([input]) => new URL(String(input), 'http://x'))
        .filter((url) => url.pathname.endsWith('/correlation'))
        .at(-1)!
      expect(last.searchParams.getAll('criteria')).toEqual(['user', 'ip', 'scenario'])
    })
  })

  it('opens an incident with the selected related alerts', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/alerts/1': () => jsonResponse(alert),
        'GET /api/v1/alerts/1/correlation': () => jsonResponse(correlation),
        'POST /api/v1/incidents': () => jsonResponse(incident(), 201),
        'GET /api/v1/incidents/5': () => jsonResponse(incident()),
        'GET /api/v1/incidents/5/timeline': () => jsonResponse(timeline),
      }),
    )
    renderAt('/investigation?alert=1')

    await userEvent.click(await screen.findByRole('checkbox', { name: 'Include alert 2' }))
    await userEvent.click(screen.getByRole('button', { name: 'Create incident with 1 related alert(s)' }))

    await screen.findByRole('heading', { name: /#5/ })
    expect(bodyOf('POST', '/api/v1/incidents')).toMatchObject({ alert_ids: [1, 2] })
  })
})

describe('Incident', () => {
  it('blocks resolving until an assessment exists and labels hypotheses', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/incidents/5': () => jsonResponse(incident()),
        'GET /api/v1/incidents/5/timeline': () => jsonResponse(timeline),
      }),
    )
    renderAt('/incidents/5')

    expect(await screen.findByRole('button', { name: 'Move to resolved' })).toBeDisabled()
    expect(screen.getByText('Resolving requires the final assessment below.')).toBeInTheDocument()
    expect(screen.getByText('Hypothesis · unverified')).toBeInTheDocument()
    expect(screen.getByText('investigating', { selector: '[aria-current="step"]' })).toBeInTheDocument()
  })

  it('records evidence from the timeline with a reason', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/incidents/5': () => jsonResponse(incident()),
        'GET /api/v1/incidents/5/timeline': () => jsonResponse(timeline),
        'POST /api/v1/incidents/5/evidence': () =>
          jsonResponse(
            incident({
              evidence: [{ id: 1, note: 'Success after failures.', author: 'analyst', added_at: '', event: timeline[0]!.event }],
            }),
            201,
          ),
      }),
    )
    renderAt('/incidents/5')

    await userEvent.click(await screen.findByRole('button', { name: 'Mark as evidence' }))
    await userEvent.type(screen.getByLabelText('Why this event matters'), 'Success after failures.')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Success after failures.')).toBeInTheDocument()
    expect(bodyOf('POST', '/api/v1/incidents/5/evidence')).toEqual({ event_id: 'syn-lab-008', note: 'Success after failures.' })
  })

  it('saves the final assessment, then allows resolving', async () => {
    const assessed = incident({ verdict: 'true_positive', final_assessment: 'Guessed.', resolution_summary: 'Reset.' })
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/incidents/5': () => jsonResponse(incident()),
        'GET /api/v1/incidents/5/timeline': () => jsonResponse(timeline),
        'PUT /api/v1/incidents/5/assessment': () => jsonResponse(assessed),
      }),
    )
    renderAt('/incidents/5')

    await userEvent.selectOptions(await screen.findByLabelText('Verdict'), 'true_positive')
    await userEvent.type(screen.getByLabelText(/Assessment: what happened/), 'Guessed.')
    await userEvent.type(screen.getByLabelText(/Resolution summary/), 'Reset.')
    await userEvent.click(screen.getByRole('button', { name: 'Save assessment' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Assessment saved.')
    expect(screen.getByRole('button', { name: 'Move to resolved' })).toBeEnabled()
    expect(bodyOf('PUT', '/api/v1/incidents/5/assessment')).toEqual({
      verdict: 'true_positive',
      final_assessment: 'Guessed.',
      resolution_summary: 'Reset.',
    })
  })

  it('previews the generated report', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/incidents/5': () => jsonResponse(incident()),
        'GET /api/v1/incidents/5/timeline': () => jsonResponse(timeline),
        'GET /api/v1/incidents/5/report': () => new Response('# Incident #5: Brute force\n\n## Timeline', { status: 200 }),
      }),
    )
    renderAt('/incidents/5')

    await userEvent.click(await screen.findByRole('button', { name: 'Preview' }))

    expect(await screen.findByLabelText('Report preview')).toHaveTextContent('# Incident #5: Brute force')
  })

  it('lists incidents and filters by status', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/incidents': () => jsonResponse({ items: [incident()], total: 1, page: 1, page_size: 50 }),
      }),
    )
    renderAt('/incidents')

    const row = (await screen.findByRole('link', { name: 'Brute force against j.martin' })).closest('tr')!
    expect(within(row).getByText('investigating')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'contained' }))

    await waitFor(() => {
      const last = fetchMock.mock.calls
        .map(([input]) => new URL(String(input), 'http://x'))
        .filter((url) => url.pathname === '/api/v1/incidents')
        .at(-1)!
      expect(last.searchParams.get('status')).toBe('contained')
    })
  })
})
