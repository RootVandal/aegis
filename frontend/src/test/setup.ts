import '@testing-library/jest-dom/vitest'
import { configure } from '@testing-library/react'

// Pages are lazy-loaded chunks; the first import of a heavy one (Recharts) can
// exceed the default 1 s findBy* timeout when the whole suite runs in parallel.
configure({ asyncUtilTimeout: 5000 })

// jsdom has no ResizeObserver; Recharts' ResponsiveContainer needs one to mount.
// Charts render at zero size in tests, so assertions use the table view instead.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver
