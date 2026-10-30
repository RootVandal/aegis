/**
 * Minimal typed HTTP client for the AEGIS API.
 *
 * Every failure becomes an ApiError with a stable `code`, mirroring the
 * backend's `{"error": {"code", "message"}}` envelope. Network failures use
 * status 0 so the UI can distinguish "backend unreachable" from "backend
 * answered with an error".
 */

// Empty by default: in development Vite proxies /api to the backend.
const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? ''

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** Field-level problems from the backend (validation errors), if any. */
  readonly details: { loc: (string | number)[]; msg: string }[]

  constructor(status: number, code: string, message: string, details: ApiError['details'] = []) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

/** True when the request never got an answer from the AEGIS API itself. */
export function isBackendUnreachable(error: ApiError): boolean {
  return error.code === 'network_error' || error.code === 'backend_unavailable'
}

const GATEWAY_STATUSES = new Set([502, 503, 504])

interface ErrorEnvelope {
  error: { code: string; message: string; details?: unknown }
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false
  const error = (value as { error: unknown }).error
  return (
    typeof error === 'object' &&
    error !== null &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { message?: unknown }).message === 'string'
  )
}

export type QueryValue = string | number | undefined | null | readonly string[]

/** Builds "?a=1&b=x&b=y", skipping empty values. Arrays repeat the key. */
export function toQueryString(params: Record<string, QueryValue>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    if (Array.isArray(value)) value.forEach((item) => search.append(key, item))
    else search.append(key, String(value))
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'
  body?: BodyInit
  contentType?: string
  signal?: AbortSignal
}

export function apiGet<T>(path: string, init?: { signal?: AbortSignal }): Promise<T> {
  return apiRequest<T>(path, { signal: init?.signal })
}

export function apiPost<T>(path: string, body?: BodyInit, contentType?: string): Promise<T> {
  return apiRequest<T>(path, { method: 'POST', body, contentType })
}

/** POST/PATCH/PUT/DELETE with a JSON body (or no body). */
export function apiRequestJson<T>(
  method: 'POST' | 'PATCH' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<T> {
  return apiRequest<T>(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    contentType: body === undefined ? undefined : 'application/json',
  })
}

async function apiRequest<T>(path: string, options: RequestOptions): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (options.contentType) headers['Content-Type'] = options.contentType

  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: options.method ?? 'GET',
      headers,
      body: options.body,
      signal: options.signal,
    })
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'network_error', 'The AEGIS backend could not be reached.')
  }

  let body: unknown = null
  try {
    body = await response.json()
  } catch {
    // Non-JSON body (for example a proxy error page). Handled below.
  }

  if (!response.ok) {
    if (isErrorEnvelope(body)) {
      const details = Array.isArray(body.error.details) ? (body.error.details as ApiError['details']) : []
      throw new ApiError(response.status, body.error.code, body.error.message, details)
    }
    if (GATEWAY_STATUSES.has(response.status)) {
      // A proxy in front of the API (the Vite dev server, nginx, ...) answered
      // because it could not reach the backend: the API itself never replied.
      throw new ApiError(
        response.status,
        'backend_unavailable',
        `The AEGIS backend could not be reached (gateway returned HTTP ${response.status}).`,
      )
    }
    throw new ApiError(response.status, 'http_error', `Request failed with HTTP ${response.status}.`)
  }
  if (body === null) {
    throw new ApiError(response.status, 'invalid_response', 'The backend returned an invalid response.')
  }
  return body as T
}
