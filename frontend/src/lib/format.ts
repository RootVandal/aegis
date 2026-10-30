/**
 * Formats an ISO timestamp as an unambiguous UTC string, e.g.
 * "2026-10-30 14:41:08 UTC". Security timelines are always shown in UTC so
 * events from different hosts and analysts line up.
 */
export function formatUtc(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'Invalid date'
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`
}

export function formatCount(value: number): string {
  return value.toLocaleString('en-US')
}
