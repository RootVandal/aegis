import { NavLink } from 'react-router-dom'

import { NAV_ITEMS } from '../../navigation'
import { Logo } from '../Logo'

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Primary" className="flex h-full w-56 flex-col border-r border-line bg-surface">
      <div className="flex h-12 items-center border-b border-line px-4">
        <Logo />
      </div>

      <ul className="flex-1 overflow-y-auto py-2">
        {NAV_ITEMS.map((item) => (
          <li key={item.path}>
            {item.status === 'available' ? (
              <NavLink
                to={item.path}
                onClick={onNavigate}
                className={({ isActive }) =>
                  `flex items-center border-l-2 px-4 py-1.5 text-[13px] ${
                    isActive
                      ? 'border-ok bg-surface-raised text-ink'
                      : 'border-transparent text-ink-muted hover:bg-surface-raised hover:text-ink'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ) : (
              <span
                aria-disabled="true"
                title={`Planned for milestone ${item.milestone}`}
                className="flex cursor-not-allowed items-center justify-between border-l-2 border-transparent px-4 py-1.5 text-[13px] text-ink-faint"
              >
                {item.label}
                <span className="font-mono text-[10px] text-ink-faint">M{item.milestone}</span>
              </span>
            )}
          </li>
        ))}
      </ul>

      <p className="border-t border-line px-4 py-3 text-[11px] leading-relaxed text-ink-faint">
        Items marked <span className="font-mono">M#</span> are planned and not yet implemented.
      </p>
    </nav>
  )
}
