/**
 * Single source of truth for the sidebar.
 *
 * Pages that do not exist yet are listed as "planned" with the milestone that
 * delivers them. They render as disabled items, never as links, so the UI
 * does not pretend a feature works before it does.
 */

export interface NavItem {
  label: string
  path: string
  status: 'available' | 'planned'
  milestone?: number
}

export const NAV_ITEMS: readonly NavItem[] = [
  { label: 'Overview', path: '/overview', status: 'planned', milestone: 5 },
  { label: 'Event Explorer', path: '/events', status: 'planned', milestone: 2 },
  { label: 'Detection Rules', path: '/rules', status: 'planned', milestone: 3 },
  { label: 'Alerts', path: '/alerts', status: 'planned', milestone: 4 },
  { label: 'Incidents', path: '/incidents', status: 'planned', milestone: 4 },
  { label: 'Investigation', path: '/investigation', status: 'planned', milestone: 4 },
  { label: 'Scenario Lab', path: '/scenarios', status: 'planned', milestone: 6 },
  { label: 'Detection Testing', path: '/detection-testing', status: 'planned', milestone: 7 },
  { label: 'System Health', path: '/health', status: 'available' },
  { label: 'Settings', path: '/settings', status: 'planned', milestone: 8 },
]
