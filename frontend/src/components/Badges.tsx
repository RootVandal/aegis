import type { DataOrigin, IngestionStatus, Severity } from '../api/events'

const BASE = 'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize leading-4'

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'border-crit/60 bg-crit text-white',
  high: 'border-crit/25 bg-crit-dim text-crit',
  medium: 'border-warn/25 bg-warn-dim text-warn',
  low: 'border-info/25 bg-info-dim text-info',
  informational: 'border-line-strong bg-surface-raised text-ink-muted',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`${BASE} ${SEVERITY_STYLES[severity]}`}>{severity === 'informational' ? 'info' : severity}</span>
}

/** Every displayed event says whether it is synthetic training data or imported data. */
export function OriginBadge({ origin }: { origin: DataOrigin }) {
  return (
    <span
      className={`${BASE} ${origin === 'synthetic' ? 'border-info/25 bg-info-dim text-info' : 'border-line-strong bg-surface-raised text-ink'}`}
      title={origin === 'synthetic' ? 'Generated training data' : 'Imported by a user'}
    >
      {origin}
    </span>
  )
}

const STATUS_STYLES: Record<IngestionStatus, string> = {
  completed: 'border-ok/25 bg-ok-dim text-ok',
  partial: 'border-warn/25 bg-warn-dim text-warn',
  failed: 'border-crit/25 bg-crit-dim text-crit',
}

export function IngestionStatusBadge({ status }: { status: IngestionStatus }) {
  return <span className={`${BASE} ${STATUS_STYLES[status]}`}>{status}</span>
}
