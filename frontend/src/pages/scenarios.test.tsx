import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import type { Attempt, ScenarioDetail } from '../api/scenarios'
import { App } from '../App'
import { HealthProvider } from '../health/HealthContext'
import { eventPage, eventSummary, jsonResponse, routeFetch } from '../test/fixtures'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  localStorage.clear()
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

function lastBody(method: string, pathEnd: string): unknown {
  const call = fetchMock.mock.calls
    .filter(([input, init]) => (init?.method ?? 'GET') === method && String(input).endsWith(pathEnd))
    .at(-1)
  return call ? JSON.parse(String(call[1]?.body)) : undefined
}

const scenario: ScenarioDetail = {
  id: 'auth-takeover',
  title: 'Authentication attack investigation',
  difficulty: 'beginner',
  summary: 'Decide whether her account was taken over.',
  relevant_rules: ['AEGIS-AUTH-001'],
  event_count: 2,
  loaded_events: 2,
  attempt_count: 1,
  completed: false,
  latest_attempt: { id: 7, status: 'in_progress', completed: null },
  scenario_tag: 'lab-auth-takeover',
  context: 'm.okafor reports a new VPN sign-in.',
  objectives: ['Establish whether the account was used by someone else.'],
  hint_count: 2,
  questions: [
    {
      id: 'used',
      prompt: 'Was the account used by someone else?',
      options: [
        { id: 'yes', text: 'Yes' },
        { id: 'no', text: 'No' },
      ],
    },
  ],
  alerts: [],
}

function attempt(overrides: Partial<Attempt> = {}): Attempt {
  return {
    id: 7,
    scenario_id: 'auth-takeover',
    status: 'in_progress',
    started_at: '2026-10-31T10:00:00Z',
    finished_at: null,
    elapsed_seconds: 600,
    hints: [],
    hints_remaining: 2,
    answers: {},
    evidence_event_ids: [],
    rationale: '',
    evaluation: null,
    solution: null,
    ...overrides,
  }
}

const graded = attempt({
  status: 'submitted',
  finished_at: '2026-10-31T10:10:00Z',
  answers: { used: 'yes' },
  evidence_event_ids: ['scn-a-017', 'scn-a-004'],
  rationale: 'The VPN success came after nine failures while she was at her desk.',
  evaluation: {
    completed: false,
    objectives: [
      { objective: 'Reach correct conclusions', met: true, detail: '1 of 1 correct.' },
      { objective: 'Avoid misleading evidence', met: false, detail: '1 benign lookalike(s) cited as evidence.' },
    ],
    questions: [
      { id: 'used', prompt: 'Was the account used by someone else?', your_answer: 'yes', correct_answer: 'yes',
        correct: true, explanation: 'The success followed nine failures.' },
    ],
    evidence: {
      required: [{ description: 'The successful VPN logon', event_ids: ['scn-a-017'], cited: true }],
      decoys_cited: [{ event_ids: ['scn-a-004'], why: 's.nakamura mistyped her password.' }],
      supporting_cited: [],
      unrelated_cited: [],
    },
  },  // prettier-ignore
  solution: {
    reasoning: ['Start from the user, not the alert.'],
    false_positive_discussion: ['Typos are common.'],
    required_evidence: [{ description: 'The successful VPN logon', event_ids: ['scn-a-017'] }],
    supporting_evidence: [],
    decoys: [{ event_ids: ['scn-a-004'], why: 's.nakamura mistyped her password.' }],
    answers: { used: { correct: 'yes', explanation: 'The success followed nine failures.' } },
  },
})

const events = eventPage([
  eventSummary({ event_id: 'scn-a-004', username: 's.nakamura' }),
  eventSummary({ event_id: 'scn-a-017', event_type: 'authentication_success', username: 'm.okafor' }),
])

function routes(current: Attempt, extra: Parameters<typeof routeFetch>[0] = {}) {
  return routeFetch({
    'GET /api/v1/scenarios/auth-takeover': () => jsonResponse(scenario),
    'GET /api/v1/scenarios/auth-takeover/attempts': () => jsonResponse([current]),
    'GET /api/v1/events': () => jsonResponse(events),
    ...extra,
  })
}

describe('Scenario Lab', () => {
  it('lists scenarios with their state', async () => {
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/scenarios': () =>
          jsonResponse([
            { ...scenario, completed: true, latest_attempt: { id: 3, status: 'submitted', completed: true } },
            { ...scenario, id: 'multistage', title: 'Multi-stage incident', difficulty: 'advanced',
              attempt_count: 0, latest_attempt: null },
          ]),  // prettier-ignore
      }),
    )
    renderAt('/scenarios')

    expect(await screen.findByText(/Completed · 1 attempt\(s\)/)).toBeInTheDocument()
    expect(screen.getByText('Not started')).toBeInTheDocument()
  })

  it('starts an attempt from the briefing', async () => {
    let started = false
    fetchMock.mockImplementation(
      routeFetch({
        'GET /api/v1/scenarios/auth-takeover': () =>
          jsonResponse({ ...scenario, latest_attempt: null, attempt_count: 0 }),
        'GET /api/v1/scenarios/auth-takeover/attempts': () => jsonResponse(started ? [attempt()] : []),
        'POST /api/v1/scenarios/auth-takeover/attempts': () => {
          started = true
          return jsonResponse(attempt(), 201)
        },
        'GET /api/v1/events': () => jsonResponse(events),
      }),
    )
    renderAt('/scenarios/auth-takeover')

    await userEvent.click(await screen.findByRole('button', { name: 'Start investigation' }))

    expect(await screen.findByRole('button', { name: 'Submit for assessment' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Open the scenario's events/ })).toHaveAttribute(
      'href',
      '/events?scenario_id=lab-auth-takeover&sort=timestamp_asc',
    )
  })

  it('submits answers, cited evidence and reasoning, then shows the assessment', async () => {
    fetchMock.mockImplementation(
      routes(attempt(), { 'POST /api/v1/scenario-attempts/7/submit': () => jsonResponse(graded) }),
    )
    renderAt('/scenarios/auth-takeover')

    await userEvent.click(await screen.findByRole('radio', { name: 'Yes' }))
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Cite scn-a-017' }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Cite scn-a-004' }))
    await userEvent.type(screen.getByLabelText(/Your reasoning/), 'The VPN success came after nine failures.')
    await userEvent.click(screen.getByRole('button', { name: 'Submit for assessment' }))

    expect(lastBody('POST', '/scenario-attempts/7/submit')).toEqual({
      answers: { used: 'yes' },
      evidence_event_ids: ['scn-a-017', 'scn-a-004'],
      rationale: 'The VPN success came after nine failures.',
    })
    expect(await screen.findByRole('status')).toHaveTextContent('Not completed yet')
    expect(screen.getByText(/You cited this\./)).toBeInTheDocument()
    expect(screen.getByText('Start from the user, not the alert.')).toBeInTheDocument()
    expect(screen.getByText(/Neither is part of the grade/)).toBeInTheDocument()
  })

  it('keeps the draft when the analyst leaves and comes back', async () => {
    fetchMock.mockImplementation(routes(attempt()))
    const first = renderAt('/scenarios/auth-takeover')
    await userEvent.click(await screen.findByRole('radio', { name: 'Yes' }))
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Cite scn-a-017' }))
    first.unmount()

    renderAt('/scenarios/auth-takeover')

    expect(await screen.findByRole('radio', { name: 'Yes' })).toBeChecked()
    expect(await screen.findByRole('checkbox', { name: 'Cite scn-a-017' })).toBeChecked()
  })

  it('reveals hints one at a time', async () => {
    fetchMock.mockImplementation(
      routes(attempt(), {
        'POST /api/v1/scenario-attempts/7/hints': () =>
          jsonResponse(attempt({ hints: ['Filter by user m.okafor.'], hints_remaining: 1 })),
      }),
    )
    renderAt('/scenarios/auth-takeover')

    await userEvent.click(await screen.findByRole('button', { name: 'Show a hint' }))

    expect(await screen.findByText('Filter by user m.okafor.')).toBeInTheDocument()
    expect(screen.getByText('Hints (1 of 2 shown)')).toBeInTheDocument()
  })

  it('asks for confirmation before revealing the solution', async () => {
    fetchMock.mockImplementation(
      routes(attempt(), {
        'POST /api/v1/scenario-attempts/7/reveal': () =>
          jsonResponse({ ...graded, status: 'revealed', evaluation: null }),
      }),
    )
    renderAt('/scenarios/auth-takeover')

    await userEvent.click(await screen.findByRole('button', { name: 'Reveal solution…' }))
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith('/reveal'))).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Yes, reveal' }))

    expect(await screen.findByText(/This attempt was not submitted/)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Start a new attempt' })).toBeEnabled())
  })
})
