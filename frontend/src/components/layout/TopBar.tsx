import { useHealth } from '../../health/HealthContext'
import { StatusBadge } from '../StatusBadge'

export function TopBar({ title, onOpenMenu }: { title: string; onOpenMenu: () => void }) {
  const { systemState, lastCheckedAt, checking, refresh, health } = useHealth()

  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-line bg-surface px-4">
      <button
        type="button"
        onClick={onOpenMenu}
        className="-ml-1 rounded-sm p-1 text-ink-muted hover:text-ink md:hidden"
        aria-label="Open navigation"
      >
        <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.5}>
          <path d="M3 5h14M3 10h14M3 15h14" />
        </svg>
      </button>

      <h1 className="truncate text-sm font-medium text-ink">{title}</h1>

      <div className="ml-auto flex items-center gap-3 text-[12px] text-ink-muted">
        {health && (
          <span className="hidden font-mono text-ink-faint sm:inline">
            {health.environment} · v{health.version}
          </span>
        )}
        <span className="hidden sm:inline">API</span>
        <StatusBadge state={systemState} />
        <span className="hidden font-mono lg:inline" title="Time of the last health check (your local clock)">
          {lastCheckedAt ? `checked ${lastCheckedAt.toLocaleTimeString()}` : 'not checked yet'}
        </span>
        <button
          type="button"
          onClick={refresh}
          disabled={checking}
          className="rounded-sm border border-line-strong px-2 py-0.5 text-ink-muted hover:border-ink-faint hover:text-ink disabled:opacity-50"
        >
          {checking ? 'Checking…' : 'Refresh'}
        </button>
      </div>
    </header>
  )
}
