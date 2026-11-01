/**
 * AEGIS mark: a faceted shield outline enclosing a stroked "A".
 * Pure geometry (straight segments only) so it stays crisp at 16px.
 */
export function LogoMark({ className = 'h-6 w-6' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinejoin="miter"
      className={className}
      aria-hidden="true"
    >
      <path d="M12 2 21 5v7l-9 10-9-10V5z" />
      <path d="M12 6.5 16 15M12 6.5 8 15M9.6 11.8h4.8" />
    </svg>
  )
}

export function Logo() {
  return (
    <div className="flex items-center gap-3">
      <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-accent-strong to-[#8b5cf6] text-white shadow-[0_4px_14px_rgb(91_99_240/0.35)]">
        <LogoMark className="h-5 w-5" />
      </span>
      <div className="leading-none">
        <div className="text-[15px] font-semibold tracking-[0.14em] text-ink">AEGIS</div>
        <div className="mt-1 text-[11px] text-ink-faint">Security Platform</div>
      </div>
    </div>
  )
}
