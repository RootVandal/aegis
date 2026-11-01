import {
  Activity,
  BellRing,
  Database,
  FlaskConical,
  LayoutDashboard,
  type LucideIcon,
  ScanSearch,
  ScrollText,
  Settings,
  ShieldAlert,
  Target,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'

import { NAV_GROUPS, NAV_ITEMS } from '../../navigation'
import { Logo } from '../Logo'

const ICONS: Record<string, LucideIcon> = {
  '/overview': LayoutDashboard,
  '/alerts': BellRing,
  '/incidents': ShieldAlert,
  '/investigation': ScanSearch,
  '/events': Database,
  '/rules': ScrollText,
  '/scenarios': FlaskConical,
  '/detection-testing': Target,
  '/health': Activity,
  '/settings': Settings,
}

const ITEM = 'flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors'

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Primary" className="flex h-full w-60 flex-col border-r border-line bg-surface/80 backdrop-blur">
      <div className="flex h-16 items-center px-5">
        <Logo />
      </div>

      <div className="flex-1 overflow-y-auto px-3 pb-4">
        {NAV_GROUPS.map((group) => (
          <div key={group} className="mt-4 first:mt-1">
            <p className="px-3 pb-1.5 text-[11px] font-medium text-ink-faint">{group}</p>
            <ul className="space-y-0.5">
              {NAV_ITEMS.filter((item) => item.group === group).map((item) => {
                const Icon = ICONS[item.path] ?? LayoutDashboard
                return (
                  <li key={item.path}>
                    {item.status === 'available' ? (
                      <NavLink
                        to={item.path}
                        onClick={onNavigate}
                        className={({ isActive }) =>
                          `${ITEM} ${
                            isActive
                              ? 'bg-accent-dim text-ink shadow-[inset_0_0_0_1px_rgb(124_134_255/0.25)]'
                              : 'text-ink-muted hover:bg-surface-raised hover:text-ink'
                          }`
                        }
                      >
                        {({ isActive }) => (
                          <>
                            <Icon
                              className={`h-4 w-4 shrink-0 ${isActive ? 'text-accent' : ''}`}
                              strokeWidth={1.75}
                              aria-hidden="true"
                            />
                            {item.label}
                          </>
                        )}
                      </NavLink>
                    ) : (
                      <span
                        aria-disabled="true"
                        title={`Planned for milestone ${item.milestone}`}
                        className={`${ITEM} cursor-not-allowed justify-between text-ink-faint`}
                      >
                        <span className="flex items-center gap-3">
                          <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} aria-hidden="true" />
                          {item.label}
                        </span>
                        <span className="text-[10px]">M{item.milestone}</span>
                      </span>
                    )}
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>

      <div className="m-3 rounded-lg border border-line bg-canvas/50 px-3 py-2.5 text-[11px] leading-relaxed text-ink-faint">
        Synthetic data is labeled everywhere. Local use only: no authentication.
      </div>
    </nav>
  )
}
