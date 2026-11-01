import type { ReactNode } from 'react'

import type { ApiError } from '../api/client'

export function Panel({
  title,
  actions,
  children,
  padded = true,
}: {
  title: string
  actions?: ReactNode
  children: ReactNode
  padded?: boolean
}) {
  return (
    <section className="rounded-xl border border-line bg-surface shadow-[0_1px_2px_rgb(0_0_0/0.3)]">
      <div className="flex min-h-12 items-center justify-between gap-3 border-b border-line/70 px-5 py-2.5">
        <h2 className="text-[13px] font-semibold text-ink">{title}</h2>
        {actions}
      </div>
      <div className={padded ? 'overflow-x-auto px-5 py-4' : 'overflow-x-auto'}>{children}</div>
    </section>
  )
}

export function ErrorNotice({ error, what }: { error: ApiError; what: string }) {
  return (
    <div role="alert" className="rounded-lg border border-crit/30 bg-crit-dim px-4 py-3 text-[13px]">
      <p className="font-medium text-crit">Could not load {what}.</p>
      <p className="mt-1 text-ink-muted">{error.message}</p>
    </div>
  )
}

export const BUTTON =
  'inline-flex items-center justify-center gap-1.5 rounded-lg border border-line-strong bg-surface-raised px-3 py-1.5 text-[13px] font-medium text-ink transition-colors hover:border-ink-faint hover:bg-line disabled:cursor-not-allowed disabled:opacity-50'
export const BUTTON_PRIMARY =
  'inline-flex items-center justify-center gap-1.5 rounded-lg border border-transparent bg-accent-strong px-3 py-1.5 text-[13px] font-medium text-white shadow-sm transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50'
export const INPUT =
  'w-full rounded-lg border border-line-strong bg-canvas/60 px-3 py-1.5 text-[13px] text-ink placeholder:text-ink-faint transition-colors focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25'
