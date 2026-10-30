import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import type { RunDetail } from '../api/evaluation'
import { App } from '../App'
import { HealthProvider } from '../health/HealthContext'
import { jsonResponse, routeFetch } from '../test/fixtures'
import { formatMetric } from './testing/DetectionTestingPage'

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

const dataset = {
  id: 'aegis-detection-suite',
  name: 'AEGIS detection test suite',
  version: 'sha256:abc',
  case_count: 3,
  categories: { positive: 1, lookalike: 1, gap: 1 },
  metric_definitions: { precision: 'TP / (TP + FP). Undefined (null) when the rule never fired.' },
}

const cases = [
  { id: 'auth-burst', title: 'Burst of failures', category: 'positive', description: 'Eight failures.',
    expected: ['AEGIS-AUTH-001'], records: [{ event_type: 'authentication_failure' }], expected_rejected: 0 },
  { id: 'auth-slow', title: 'Slow guessing', category: 'gap', description: 'Below the window.',
    expected: ['AEGIS-AUTH-001'], records: [{ event_type: 'authentication_failure', note: 'slow' }], expected_rejected: 0 },
  { id: 'ps-plain', title: 'Plain PowerShell', category: 'benign', description: 'Get-Service.',
    expected: [], records: [], expected_rejected: 0 },
]  // prettier-ignore

const run: RunDetail = {
  id: 2,
  created_at: '2026-10-31T10:00:00Z',
  dataset_id: 'aegis-detection-suite',
  dataset_version: 'sha256:abc',
  settings_source: 'current',
  micro: { tp: 1, fp: 0, fn: 1, tn: 4, precision: 1, recall: 0.5, f1: 2 / 3 },
  input_handling_ok: true,
  rules: {
    'AEGIS-AUTH-001': { version: 1, params: {}, enabled: true },
    'AEGIS-EXEC-001': { version: 1, params: {}, enabled: true },
  },
  results: {
    per_rule: {
      'AEGIS-AUTH-001': { tp: 1, fp: 0, fn: 1, tn: 1, precision: 1, recall: 0.5, f1: 2 / 3,
                          fp_cases: [], fn_cases: ['auth-slow'] },
      'AEGIS-EXEC-001': { tp: 0, fp: 0, fn: 0, tn: 3, precision: null, recall: null, f1: null,
                          fp_cases: [], fn_cases: [] },
    },
    totals: {
      micro: { tp: 1, fp: 0, fn: 1, tn: 4, precision: 1, recall: 0.5, f1: 2 / 3 },
      macro: { precision: { value: 1, rules: 1 }, recall: { value: 0.5, rules: 1 }, f1: { value: 2 / 3, rules: 1 } },
    },
    cases: [
      { case_id: 'auth-burst', category: 'positive', expected: ['AEGIS-AUTH-001'], fired: ['AEGIS-AUTH-001'],
        outcomes: { 'AEGIS-AUTH-001': 'tp', 'AEGIS-EXEC-001': 'tn' }, records: 1, rejected: 0, input_handled_as_expected: true },
      { case_id: 'auth-slow', category: 'gap', expected: ['AEGIS-AUTH-001'], fired: [],
        outcomes: { 'AEGIS-AUTH-001': 'fn', 'AEGIS-EXEC-001': 'tn' }, records: 1, rejected: 0, input_handled_as_expected: true },
      { case_id: 'ps-plain', category: 'benign', expected: [], fired: [],
        outcomes: { 'AEGIS-AUTH-001': 'tn', 'AEGIS-EXEC-001': 'tn' }, records: 0, rejected: 0, input_handled_as_expected: true },
    ],
    input_handling_ok: true,
  },  // prettier-ignore
  comparison: {
    previous_run_id: 1,
    dataset_changed: false,
    rules: { 'AEGIS-AUTH-001': { delta: { tp: -1, fp: 0, fn: 1, tn: 0 }, version: [1, 1], params_changed: true } },
  },
}

function routes(runs: unknown[], extra: Parameters<typeof routeFetch>[0] = {}) {
  return routeFetch({
    'GET /api/v1/evaluation/datasets': () => jsonResponse([dataset]),
    'GET /api/v1/evaluation/datasets/aegis-detection-suite/cases': () => jsonResponse(cases),
    'GET /api/v1/evaluation/runs': () => jsonResponse(runs),
    'GET /api/v1/evaluation/runs/2': () => jsonResponse(run),
    ...extra,
  })
}

describe('Detection Testing', () => {
  it('formats undefined metrics as n/a, never as a number', () => {
    expect(formatMetric(null)).toBe('n/a')
    expect(formatMetric(0)).toBe('0.0%')
    expect(formatMetric(0.75)).toBe('75.0%')
  })

  it('runs an evaluation with the chosen parameters and shows the results', async () => {
    let runs: unknown[] = []
    fetchMock.mockImplementation(
      routes([], {
        'GET /api/v1/evaluation/runs': () => jsonResponse(runs),
        'POST /api/v1/evaluation/runs': (_url, init) => {
          runs = [run]
          expect(JSON.parse(String(init?.body))).toEqual({ settings: 'defaults' })
          return jsonResponse(run, 201)
        },
      }),
    )
    renderAt('/detection-testing')

    expect(await screen.findByText('No evaluation has been run yet.')).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByLabelText('Rule parameters'), 'defaults')
    await userEvent.click(screen.getByRole('button', { name: 'Run evaluation' }))

    const row = (await screen.findByRole('link', { name: 'AEGIS-EXEC-001' })).closest('tr')!
    const undefinedCells = within(row).getAllByText('n/a')
    expect(undefinedCells).toHaveLength(3)
    expect(undefinedCells[0]).toHaveAttribute('title', 'Undefined: the rule never fired on this suite.')
  })

  it('explains what changed since the previous run', async () => {
    fetchMock.mockImplementation(routes([run]))
    renderAt('/detection-testing')

    expect(await screen.findByText(/Compared with run #1/)).toBeInTheDocument()
    expect(screen.getByText(/AEGIS-AUTH-001: TP -1, FN \+1 · parameters changed/)).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent('do not show how the rules perform on real telemetry')
  })

  it('lists misclassified cases first and shows their records on demand', async () => {
    fetchMock.mockImplementation(routes([run]))
    renderAt('/detection-testing')

    const slow = await screen.findByRole('button', { name: /auth-slow/ })
    expect(screen.queryByRole('button', { name: /auth-burst/ })).not.toBeInTheDocument()
    expect(slow).toHaveTextContent('FN AEGIS-AUTH-001')

    await userEvent.click(slow)
    expect(await screen.findByText(/"note": "slow"/)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Show all cases' }))
    await waitFor(() => expect(screen.getByRole('button', { name: /auth-burst/ })).toBeInTheDocument())
  })
})
