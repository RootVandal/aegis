import { Menu, RefreshCw } from 'lucide-react'

import { useHealth } from '../../health/HealthContext'
import { StatusBadge } from '../StatusBadge'

export function TopBar({ title, onOpenMenu }: { title: string; onOpenMenu: () => void }) {
  const { systemState, lastCheckedAt, checking, refresh, health } = useHealth()

  return (
    <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-3 border-b border-line bg-canvas/75 px-4 backdrop-blur md:px-8">
      <button
        type="button"
        onClick={onOpenMenu}
        className="-ml-1 rounded-lg p-1.5 text-ink-muted hover:bg-surface-raised hover:text-ink md:hidden"
        aria-label="Open navigation"
      >
        <Menu className="h-5 w-5" strokeWidth={1.75} aria-hidden="true" />
      </button>

      <h1 className="truncate text-[17px] font-semibold tracking-tight text-ink">{title}</h1>

      <div className="ml-auto flex items-center gap-2.5 text-[12px] text-ink-muted">
        {health && (
          <span className="hidden rounded-full border border-line px-2.5 py-0.5 sm:inline">
            {health.environment} · v{health.version}
          </span>
        )}
        <span
          className="inline-flex items-center gap-2"
          title={lastCheckedAt ? `API checked ${lastCheckedAt.toLocaleTimeString()}` : 'API not checked yet'}
        >
          <span className="hidden sm:inline">API</span>
          <StatusBadge state={systemState} />
        </span>
        <span className="hidden lg:inline">
          {lastCheckedAt ? `checked ${lastCheckedAt.toLocaleTimeString()}` : 'not checked yet'}
        </span>
        <button
          type="button"
          onClick={refresh}
          disabled={checking}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-raised px-2.5 py-1 text-[12px] font-medium text-ink transition-colors hover:bg-line disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${checking ? 'animate-spin' : ''}`} strokeWidth={2} aria-hidden="true" />
          {checking ? 'Checking…' : 'Refresh'}
        </button>
      </div>
    </header>
  )
}
