import type { SystemState } from '../health/HealthContext'

const STYLES: Record<SystemState, { label: string; className: string }> = {
  checking: { label: 'Checking', className: 'border-line-strong text-ink-muted' },
  ok: { label: 'Operational', className: 'border-ok/25 bg-ok-dim text-ok' },
  degraded: { label: 'Degraded', className: 'border-warn/25 bg-warn-dim text-warn' },
  error: { label: 'Error', className: 'border-crit/25 bg-crit-dim text-crit' },
  unreachable: { label: 'Unreachable', className: 'border-crit/25 bg-crit-dim text-crit' },
}

export function StatusBadge({ state, label }: { state: SystemState; label?: string }) {
  const style = STYLES[state]
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[12px] font-medium ${style.className}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
      {label ?? style.label}
    </span>
  )
}
