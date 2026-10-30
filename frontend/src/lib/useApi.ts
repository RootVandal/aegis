import { useEffect, useState } from 'react'

import { ApiError } from '../api/client'

export type ApiState<T> =
  | { status: 'loading'; data: null; error: null }
  | { status: 'success'; data: T; error: null }
  | { status: 'error'; data: null; error: ApiError }

/**
 * Runs `load` whenever `key` changes and tracks loading / data / error.
 *
 * The previous request is aborted when the key changes, so a slow response
 * for old filters can never overwrite the results of newer ones.
 * Bump `reloadToken` to re-run the same request.
 */
export function useApi<T>(
  load: (signal: AbortSignal) => Promise<T>,
  key: string,
  reloadToken = 0,
): ApiState<T> {
  const [state, setState] = useState<{ key: string; value: ApiState<T> }>({
    key: '',
    value: { status: 'loading', data: null, error: null },
  })
  const requestKey = `${key}#${reloadToken}`

  useEffect(() => {
    const controller = new AbortController()
    load(controller.signal).then(
      (data) => setState({ key: requestKey, value: { status: 'success', data, error: null } }),
      (cause: unknown) => {
        if (controller.signal.aborted) return
        const error =
          cause instanceof ApiError ? cause : new ApiError(0, 'unknown_error', 'Request failed.')
        setState({ key: requestKey, value: { status: 'error', data: null, error } })
      },
    )
    return () => controller.abort()
    // `load` is intentionally not a dependency: callers pass inline closures,
    // and `key` already captures everything the request depends on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestKey])

  // A result for an older key is stale: report "loading" until the new one arrives.
  return state.key === requestKey ? state.value : { status: 'loading', data: null, error: null }
}
