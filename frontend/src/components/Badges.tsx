import type { DataOrigin, IngestionStatus, Severity } from '../api/events'

const BASE = 'inline-flex items-center rounded-sm border px-1.5 py-px text-[11px] font-medium uppercase tracking-wide'

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'border-crit bg-crit text-canvas',
  high: 'border-crit/50 bg-crit-dim text-crit',
  medium: 'border-warn/50 bg-warn-dim text-warn',
  low: 'border-info/40 bg-info-dim text-info',
  informational: 'border-line-strong text-ink-muted',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`${BASE} ${SEVERITY_STYLES[severity]}`}>{severity === 'informational' ? 'info' : severity}</span>
}

/** Every displayed event says whether it is synthetic training data or imported data. */
export function OriginBadge({ origin }: { origin: DataOrigin }) {
  return (
    <span
      className={`${BASE} ${origin === 'synthetic' ? 'border-info/40 text-info' : 'border-line-strong text-ink'}`}
      title={origin === 'synthetic' ? 'Generated training data' : 'Imported by a user'}
    >
      {origin}
    </span>
  )
}

const STATUS_STYLES: Record<IngestionStatus, string> = {
  completed: 'border-ok/40 bg-ok-dim text-ok',
  partial: 'border-warn/50 bg-warn-dim text-warn',
  failed: 'border-crit/50 bg-crit-dim text-crit',
}

export function IngestionStatusBadge({ status }: { status: IngestionStatus }) {
  return <span className={`${BASE} ${STATUS_STYLES[status]}`}>{status}</span>
}
