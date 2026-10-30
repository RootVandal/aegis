import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import { App } from '../App'
import { ErrorBoundary } from '../components/ErrorBoundary'
import { HealthProvider } from '../health/HealthContext'
import { jsonResponse, routeFetch } from '../test/fixtures'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  localStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const settings = {
  version: '1.0.0', environment: 'development', database: 'sqlite (aegis.db)',
  cors_origins: ['http://localhost:5173'], auto_detect: true, log_level: 'INFO',
  max_ingest_bytes: 5242880, max_ingest_records: 10000, max_record_bytes: 65536,
  max_request_body_bytes: 1048576, attack_version: 'v20.0', rule_count: 8,
  authentication: 'none: run on localhost only (see SECURITY.md)',
}  // prettier-ignore

describe('Settings', () => {
  it('shows the effective configuration read-only', async () => {
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/settings': () => jsonResponse(settings) }))
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <HealthProvider pollIntervalMs={0}>
          <App />
        </HealthProvider>
      </MemoryRouter>,
    )

    expect(await screen.findByText('sqlite (aegis.db)')).toBeInTheDocument()
    expect(screen.getByText('8 (ATT&CK v20.0)')).toBeInTheDocument()
    expect(screen.getByText(/none: run on localhost only/)).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  })

  it('clears scenario drafts stored in this browser and nothing else', async () => {
    localStorage.setItem('aegis.scenario-draft.3', '{}')
    localStorage.setItem('aegis.scenario-draft.4', '{}')
    localStorage.setItem('unrelated', 'keep')
    fetchMock.mockImplementation(routeFetch({ 'GET /api/v1/settings': () => jsonResponse(settings) }))
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <HealthProvider pollIntervalMs={0}>
          <App />
        </HealthProvider>
      </MemoryRouter>,
    )

    expect(await screen.findByText('2 saved draft(s)')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Clear scenario drafts' }))

    expect(screen.getByText('0 saved draft(s)')).toBeInTheDocument()
    expect(localStorage.getItem('unrelated')).toBe('keep')
  })
})

describe('ErrorBoundary', () => {
  it('contains a crashing page and shows a message instead of a blank screen', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    function Broken(): never {
      throw new Error('boom')
    }

    render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>,
    )

    expect(screen.getByRole('alert')).toHaveTextContent('This page failed to render.')
    expect(screen.queryByText('boom')).not.toBeInTheDocument()
  })
})
