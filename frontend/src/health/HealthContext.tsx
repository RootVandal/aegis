import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'

import { ApiError, isBackendUnreachable } from '../api/client'
import { fetchHealth, type HealthResponse } from '../api/health'

/**
 * Shares one health check between the top bar and the System Health page.
 *
 * The status is re-checked on a fixed interval and on demand. It never
 * invents a state: until the first response arrives it reports "checking",
 * and a failed request is shown as a failure, not as stale "ok" data.
 */

export type SystemState = 'checking' | 'ok' | 'degraded' | 'error' | 'unreachable'

interface HealthState {
  health: HealthResponse | null
  error: ApiError | null
  checking: boolean
  lastCheckedAt: Date | null
}

interface HealthContextValue extends HealthState {
  systemState: SystemState
  refresh: () => void
}

const HealthContext = createContext<HealthContextValue | null>(null)

const DEFAULT_POLL_MS = 30_000

export function HealthProvider({
  children,
  pollIntervalMs = DEFAULT_POLL_MS,
}: {
  children: ReactNode
  /** 0 disables polling (used by tests). */
  pollIntervalMs?: number
}) {
  const [state, setState] = useState<HealthState>({
    health: null,
    error: null,
    checking: true,
    lastCheckedAt: null,
  })
  const inFlight = useRef<AbortController | null>(null)

  const runCheck = useCallback(async () => {
    inFlight.current?.abort()
    const controller = new AbortController()
    inFlight.current = controller

    try {
      const health = await fetchHealth(controller.signal)
      setState({ health, error: null, checking: false, lastCheckedAt: new Date() })
    } catch (cause) {
      if (controller.signal.aborted) return
      const error =
        cause instanceof ApiError ? cause : new ApiError(0, 'unknown_error', 'Health check failed.')
      // Drop the previous response: showing old "ok" data next to a failure would mislead.
      setState({ health: null, error, checking: false, lastCheckedAt: new Date() })
    }
  }, [])

  const refresh = useCallback(() => {
    setState((previous) => ({ ...previous, checking: true }))
    void runCheck()
  }, [runCheck])

  useEffect(() => {
    // A setTimeout chain rather than setInterval: the next check is scheduled
    // only after the previous one finished, so a slow backend never receives
    // overlapping health requests.
    let cancelled = false
    let timer: number | undefined
    const tick = async () => {
      await runCheck()
      if (!cancelled && pollIntervalMs > 0) timer = window.setTimeout(tick, pollIntervalMs)
    }
    timer = window.setTimeout(tick, 0)
    return () => {
      cancelled = true
      window.clearTimeout(timer)
      inFlight.current?.abort()
    }
  }, [runCheck, pollIntervalMs])

  const value: HealthContextValue = { ...state, systemState: deriveSystemState(state), refresh }
  return <HealthContext.Provider value={value}>{children}</HealthContext.Provider>
}

function deriveSystemState({ health, error }: HealthState): SystemState {
  if (error) return isBackendUnreachable(error) ? 'unreachable' : 'error'
  if (health) return health.status
  return 'checking'
}

export function useHealth(): HealthContextValue {
  const value = useContext(HealthContext)
  if (!value) throw new Error('useHealth must be used inside <HealthProvider>.')
  return value
}
