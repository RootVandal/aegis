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
    <section className="rounded-md border border-line bg-surface">
      <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-2">
        <h2 className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">{title}</h2>
        {actions}
      </div>
      <div className={padded ? 'overflow-x-auto px-4 py-3' : 'overflow-x-auto'}>{children}</div>
    </section>
  )
}

export function ErrorNotice({ error, what }: { error: ApiError; what: string }) {
  return (
    <div role="alert" className="rounded-md border border-crit/40 bg-crit-dim px-4 py-3 text-[13px]">
      <p className="font-medium text-crit">Could not load {what}.</p>
      <p className="mt-1 text-ink-muted">{error.message}</p>
    </div>
  )
}

export const BUTTON =
  'rounded-sm border border-line-strong px-2.5 py-1 text-[12px] text-ink-muted hover:border-ink-faint hover:text-ink disabled:cursor-not-allowed disabled:opacity-50'
export const BUTTON_PRIMARY =
  'rounded-sm border border-ok/50 bg-ok-dim px-2.5 py-1 text-[12px] font-medium text-ok hover:border-ok disabled:cursor-not-allowed disabled:opacity-50'
export const INPUT =
  'w-full rounded-sm border border-line-strong bg-canvas px-2 py-1 text-[13px] text-ink placeholder:text-ink-faint focus:border-ok focus:outline-none'
