import type { IncidentStatus } from '../../api/incidents'

const STYLES: Record<IncidentStatus, string> = {
  new: 'border-info/25 bg-info-dim text-info',
  investigating: 'border-warn/25 bg-warn-dim text-warn',
  contained: 'border-line-strong bg-surface-raised text-ink',
  resolved: 'border-ok/25 bg-ok-dim text-ok',
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize leading-4 ${STYLES[status]}`}
    >
      {status}
    </span>
  )
}
