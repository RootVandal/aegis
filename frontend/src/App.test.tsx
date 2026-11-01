import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import { App } from './App'
import { HealthProvider } from './health/HealthContext'
import { healthResponse, jsonResponse, routeFetch } from './test/fixtures'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderApp(path = '/health') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <HealthProvider pollIntervalMs={0}>
        <App />
      </HealthProvider>
    </MemoryRouter>,
  )
}

describe('navigation', () => {
  it('redirects the root path to the Overview', async () => {
    fetchMock.mockImplementation(routeFetch({}))
    renderApp('/')

    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument()
  })

  it('links every primary page in the navigation', async () => {
    fetchMock.mockResolvedValue(jsonResponse(healthResponse()))
    renderApp()
    const nav = screen.getByRole('navigation', { name: 'Primary' })

    const links = within(nav).getAllByRole('link').map((link) => link.getAttribute('href'))
    expect(links).toEqual([
      '/overview', '/alerts', '/incidents', '/investigation', '/events', '/rules',
      '/scenarios', '/detection-testing', '/health', '/settings',
    ])  // prettier-ignore
    expect(nav.querySelector('[aria-disabled]')).toBeNull()
    await within(screen.getByRole('banner')).findByText('Operational')
  })
})

describe('System Health page', () => {
  it('shows backend data from the health endpoint', async () => {
    fetchMock.mockResolvedValue(jsonResponse(healthResponse()))
    renderApp()

    expect(await within(screen.getByRole('banner')).findByText('Operational')).toBeInTheDocument()
    expect(await screen.findByText('Connected; schema is up to date.')).toBeInTheDocument()
    expect(screen.getByText(/v0\.1\.0 · test · server time 2026-10-30 12:00:00 UTC/)).toBeInTheDocument()
    expect(screen.getByText(/No events have been ingested yet/)).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/health', expect.anything())
  })

  it('shows real counts instead of the empty state when events exist', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        healthResponse({
          data: {
            event_count: 1250,
            ingestion_batch_count: 3,
            latest_event_at: '2026-10-29T08:15:00Z',
            last_ingestion_at: '2026-10-30T09:00:00Z',
          },
        }),
      ),
    )
    renderApp()

    expect(await screen.findByText('1,250')).toBeInTheDocument()
    expect(screen.getByText('2026-10-29 08:15:00 UTC')).toBeInTheDocument()
    expect(screen.queryByText(/No events have been ingested yet/)).not.toBeInTheDocument()
  })

  it('explains an unreachable backend without showing stale data', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    renderApp()

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Cannot reach the AEGIS backend.')
    expect(screen.getAllByText('Unreachable').length).toBeGreaterThan(0)
    expect(screen.getByText('Unavailable until the API responds.')).toBeInTheDocument()
  })

  it('treats a proxy 502 as an unreachable backend', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 502 }))
    renderApp()

    expect(await screen.findByRole('alert')).toHaveTextContent('Cannot reach the AEGIS backend.')
  })

  it('flags a database that has not been migrated', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        healthResponse({
          status: 'degraded',
          database: {
            status: 'degraded',
            message: 'Connected, but migrations are not applied. Run `alembic upgrade head`.',
            schema_revision: null,
            expected_revision: '0001',
          },
          data: null,
        }),
      ),
    )
    renderApp()

    expect((await screen.findAllByText('Degraded')).length).toBe(2) // top bar + database row
    expect(screen.getByText(/migrations are not applied/)).toBeInTheDocument()
    expect(screen.getByText(/database schema is not current/)).toBeInTheDocument()
  })

  it('re-checks health when Refresh is clicked', async () => {
    fetchMock
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(jsonResponse(healthResponse()))
    renderApp()
    await screen.findByRole('alert')

    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))

    expect(await within(screen.getByRole('banner')).findByText('Operational')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
