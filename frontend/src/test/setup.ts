import '@testing-library/jest-dom/vitest'
import { configure } from '@testing-library/react'

// Pages are lazy-loaded chunks. Transforming them (Recharts especially) is
// slow on a busy machine, and without this the first test in each file paid
// that cost inside its findBy* wait. Loading every page module up front moves
// it into a hook with its own generous budget; React.lazy then resolves from
// the module cache.
const pageModules = import.meta.glob('../pages/**/*Page.tsx')
beforeAll(async () => {
  await Promise.all(Object.values(pageModules).map((load) => load()))
}, 60_000)

configure({ asyncUtilTimeout: 5000 })

// jsdom has no ResizeObserver; Recharts' ResponsiveContainer needs one to mount.
// Charts render at zero size in tests, so assertions use the table view instead.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver
