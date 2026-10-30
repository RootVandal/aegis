import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import type { AlertDetail, RuleDetail, RuleSummary } from '../api/detection'
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

const ruleSummary: RuleSummary = {
  id: 'AEGIS-AUTH-001',
  name: 'Multiple Failed Logins',
  version: 1,
  description: 'Repeated failed authentication attempts.',
  severity: 'medium',
  enabled: true,
  customized: false,
  event_types: ['authentication_failure'],
  mitre: [
    {
      id: 'T1110.001',
      name: 'Brute Force: Password Guessing',
      tactics: ['Credential Access'],
      url: 'https://attack.mitre.org/techniques/T1110/001/',
    },
  ],
  alert_count: 2,
}

const ruleDetail: RuleDetail = {
  ...ruleSummary,
  logic: ['Select failures.', 'Group them.'],
  required_fields: ['timestamp', 'username'],
  mitre_details: [
    { ...ruleSummary.mitre[0]!, relationship: 'Guessing.', telemetry: '4625', limitations: 'Slow guessing.' },
  ],
  investigation_steps: ['Check the source IP.'],
  false_positives: ['Forgotten password.'],
  limitations: ['Window boundaries.'],
  unknowns: ['Who typed it.'],
  changelog: [{ version: 1, date: '2026-10-30', description: 'Initial version.' }],
  params: { threshold: 5, window_seconds: 300, group_by: 'username', success_lookahead_seconds: 600 },
  default_params: { threshold: 5, window_seconds: 300, group_by: 'username', success_lookahead_seconds: 600 },
  overrides: {},
  params_schema: {
    properties: {
      threshold: { type: 'integer', minimum: 2, description: 'Failures needed in one window.' },
      window_seconds: { type: 'integer' },
      group_by: { type: 'string', enum: ['username', 'source_ip', 'username_and_source_ip'] },
      success_lookahead_seconds: { type: 'integer' },
    },
  },
  attack_version: 'v20.0',
}

describe('Detection Rules', () => {
  it('lists rules with their mapping and alert count', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/rules': () => jsonResponse([ruleSummary]),
        'GET /api/v1/detections/runs': () => jsonResponse([]),
      }),
    )
    renderAt('/rules')

    const row = (await screen.findByRole('link', { name: 'AEGIS-AUTH-001' })).closest('tr')!
    expect(within(row).getByText('T1110.001')).toBeInTheDocument()
    expect(within(row).getByRole('link', { name: '2' })).toHaveAttribute('href', '/alerts?rule_id=AEGIS-AUTH-001')
  })

  it('runs detection on demand and refreshes the run history', async () => {
    let runs: unknown[] = []
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/rules': () => jsonResponse([ruleSummary]),
        'GET /api/v1/detections/runs': () => jsonResponse(runs),
        'POST /api/v1/detections/runs': () => {
          runs = [
            {
              id: 1, trigger: 'manual', started_at: '2026-10-30T10:00:00Z', completed_at: '2026-10-30T10:00:01Z',
              events_evaluated: 264, findings_count: 19, alerts_created: 0, alerts_existing: 19, rules: [],
            },
          ]  // prettier-ignore
          return jsonResponse(runs[0], 201)
        },
      }),
    )
    renderAt('/rules')
    await screen.findByText(/Detection has not run yet/)

    await userEvent.click(screen.getByRole('button', { name: 'Run detections now' }))

    expect(await screen.findByText('264')).toBeInTheDocument()
    expect(screen.getByText('manual')).toBeInTheDocument()
  })

  it('shows documentation and ATT&CK links that open safely', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/rules/AEGIS-AUTH-001': () => jsonResponse(ruleDetail) }))
    renderAt('/rules/AEGIS-AUTH-001')

    const link = await screen.findByRole('link', { name: /T1110.001 Brute Force: Password Guessing/ })
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    expect(link).toHaveAttribute('target', '_blank')
    expect(screen.getByText('Check the source IP.')).toBeInTheDocument()
    expect(screen.getByText('Who typed it.')).toBeInTheDocument()
  })

  it('saves only changed parameters', async () => {
    let body: unknown = null
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/rules/AEGIS-AUTH-001': () => jsonResponse(ruleDetail),
        'PATCH /api/v1/rules/AEGIS-AUTH-001': (_url, init) => {
          body = JSON.parse(String(init?.body))
          return jsonResponse({ ...ruleDetail, customized: true })
        },
      }),
    )
    renderAt('/rules/AEGIS-AUTH-001')

    const threshold = await screen.findByLabelText(/threshold/)
    await userEvent.clear(threshold)
    await userEvent.type(threshold, '3')
    await userEvent.selectOptions(screen.getByLabelText(/group_by/), 'source_ip')
    await userEvent.click(screen.getByRole('button', { name: 'Save parameters' }))

    await waitFor(() => expect(body).toEqual({ params: { threshold: 3, group_by: 'source_ip' } }))
    expect(await screen.findByRole('status')).toHaveTextContent('Saved.')
  })

  it('shows validation errors next to the field', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/rules/AEGIS-AUTH-001': () => jsonResponse(ruleDetail),
        'PATCH /api/v1/rules/AEGIS-AUTH-001': () =>
          jsonResponse(
            {
              error: {
                code: 'invalid_rule_params',
                message: 'Invalid rule parameters.',
                details: [{ loc: ['body', 'params', 'threshold'], msg: 'Input should be greater than or equal to 2' }],
              },
            },
            422,
          ),
      }),
    )
    renderAt('/rules/AEGIS-AUTH-001')

    const threshold = await screen.findByLabelText(/threshold/)
    await userEvent.clear(threshold)
    // A value the browser accepts (min=2) but the (mocked) server rejects.
    await userEvent.type(threshold, '4')
    await userEvent.click(screen.getByRole('button', { name: 'Save parameters' }))

    expect(await screen.findByText('Input should be greater than or equal to 2')).toBeInTheDocument()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})

describe('Alerts', () => {
  const alert: AlertDetail = {
    id: 7,
    rule_id: 'AEGIS-NET-001',
    rule_name: 'Suspicious Outbound Connections',
    rule_version: 1,
    title: 'powershell.exe on ws-fin-02 connected to 203.0.113.50:80',
    severity: 'medium',
    status: 'new',
    created_at: '2026-10-30T10:00:00Z',
    first_seen: '2026-10-08T10:10:02Z',
    last_seen: '2026-10-08T10:10:02Z',
    event_count: 1,
    hosts: ['ws-fin-02'],
    users: [],
    ips: ['203.0.113.50'],
    rule_params: { expected_ports: [80, 443] },
    detection_run_id: 3,
    events: [eventSummary({ event_id: 'syn-lab-035', event_type: 'network_connection' })],
    explanation: {
      what: 'An outbound network connection matched one or more documented conditions.',
      triggering_events: [
        { event_id: 'syn-lab-035', timestamp: '2026-10-08T10:10:02Z', description: 'network_connection dst=203.0.113.50:80' },
      ],
      conditions: [{ description: 'Script host or LOLBin connected to an external address', observed: 'powershell.exe' }],
      evidence: {
        event_count: 1, first_seen: '2026-10-08T10:10:02Z', last_seen: '2026-10-08T10:10:02Z',
        hosts: ['ws-fin-02'], users: [], ips: ['203.0.113.50'],
      },  // prettier-ignore
      unknowns: ['What data was transferred.'],
      next_steps: ['Identify the destination.'],
      false_positives: ['Administrative scripts.'],
      mitre: [],
      rule: { id: 'AEGIS-NET-001', name: 'Suspicious Outbound Connections', version: 1, params: {} },
      disclaimer: 'This alert is an indicator produced by a deterministic rule, not proof of compromise.',
    },
  }

  it('filters alerts through the URL', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/rules': () => jsonResponse([ruleSummary]),
        'GET /api/v1/alerts': () => jsonResponse({ items: [alert], total: 1, page: 1, page_size: 50 }),
      }),
    )
    renderAt('/alerts')
    await screen.findByText(alert.title)

    await userEvent.selectOptions(screen.getByLabelText('Severity'), 'high')

    await waitFor(() => {
      const last = fetchMock.mock.calls
        .map(([input]) => new URL(String(input), 'http://localhost'))
        .filter((url) => url.pathname === '/api/v1/alerts')
        .at(-1)!
      expect(last.searchParams.get('severity')).toBe('high')
    })
  })

  it('explains an alert in the seven documented parts', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/alerts/7': () => jsonResponse(alert) }))
    renderAt('/alerts/7')

    await screen.findByText(alert.title)
    for (const heading of [
      '1. What the rule detected',
      '2. Events that triggered it (1)',
      '3. Conditions satisfied',
      '4. Evidence available',
      '5. What remains unknown',
      '6. What to investigate next',
      '7. What could make this a false positive',
    ]) {
      expect(screen.getByRole('heading', { name: heading })).toBeInTheDocument()
    }
    expect(screen.getByRole('link', { name: 'syn-lab-035' })).toHaveAttribute('href', '/events/syn-lab-035')
    expect(screen.getByText(/not proof of compromise/)).toBeInTheDocument()
    expect(screen.getByText(/This finding is not mapped/)).toBeInTheDocument()
  })
})
