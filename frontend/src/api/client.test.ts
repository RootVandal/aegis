import { jsonResponse } from '../test/fixtures'
import { ApiError, apiGet, isBackendUnreachable } from './client'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

async function expectApiError(promise: Promise<unknown>): Promise<ApiError> {
  const error = await promise.catch((cause: unknown) => cause)
  expect(error).toBeInstanceOf(ApiError)
  return error as ApiError
}

describe('apiGet', () => {
  it('returns the parsed body on success', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ status: 'ok' }))

    await expect(apiGet('/api/v1/health/live')).resolves.toEqual({ status: 'ok' })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/health/live', expect.anything())
  })

  it('surfaces the backend error envelope', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ error: { code: 'not_found', message: 'Not Found' } }, 404))

    const error = await expectApiError(apiGet('/api/v1/missing'))

    expect(error.status).toBe(404)
    expect(error.code).toBe('not_found')
    expect(error.message).toBe('Not Found')
  })

  it('reports an unreachable backend as status 0', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))

    const error = await expectApiError(apiGet('/api/v1/health'))

    expect(error.status).toBe(0)
    expect(error.code).toBe('network_error')
  })

  it('handles a non-JSON error response', async () => {
    fetchMock.mockResolvedValue(new Response('<html>Server Error</html>', { status: 500 }))

    const error = await expectApiError(apiGet('/api/v1/health'))

    expect(error.status).toBe(500)
    expect(error.code).toBe('http_error')
    expect(isBackendUnreachable(error)).toBe(false)
  })

  // Regression: with the backend stopped, the Vite proxy answers 502 instead of
  // failing the request, and the UI reported a generic error instead of
  // "backend unreachable".
  it.each([502, 503, 504])('treats a bare gateway %i as an unreachable backend', async (status) => {
    fetchMock.mockResolvedValue(new Response('', { status }))

    const error = await expectApiError(apiGet('/api/v1/health'))

    expect(error.code).toBe('backend_unavailable')
    expect(isBackendUnreachable(error)).toBe(true)
  })

  it('trusts the backend envelope even on a 503', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ error: { code: 'service_unavailable', message: 'Maintenance' } }, 503),
    )

    const error = await expectApiError(apiGet('/api/v1/health'))

    expect(error.code).toBe('service_unavailable')
    expect(isBackendUnreachable(error)).toBe(false)
  })

  it('rejects a successful response with an unparseable body', async () => {
    fetchMock.mockResolvedValue(new Response('not json', { status: 200 }))

    const error = await expectApiError(apiGet('/api/v1/health'))

    expect(error.code).toBe('invalid_response')
  })
})
