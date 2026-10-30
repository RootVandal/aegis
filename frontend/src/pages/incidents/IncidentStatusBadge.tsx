import type { IncidentStatus } from '../../api/incidents'

const STYLES: Record<IncidentStatus, string> = {
  new: 'border-info/40 text-info',
  investigating: 'border-warn/50 bg-warn-dim text-warn',
  contained: 'border-line-strong bg-surface-raised text-ink',
  resolved: 'border-ok/40 bg-ok-dim text-ok',
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-sm border px-1.5 py-px text-[11px] font-medium uppercase tracking-wide ${STYLES[status]}`}
    >
      {status}
    </span>
  )
}
