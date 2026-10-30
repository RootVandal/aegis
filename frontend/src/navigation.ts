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
  { label: 'Overview', path: '/overview', status: 'available' },
  { label: 'Event Explorer', path: '/events', status: 'available' },
  { label: 'Detection Rules', path: '/rules', status: 'available' },
  { label: 'Alerts', path: '/alerts', status: 'available' },
  { label: 'Incidents', path: '/incidents', status: 'available' },
  { label: 'Investigation', path: '/investigation', status: 'available' },
  { label: 'Scenario Lab', path: '/scenarios', status: 'available' },
  { label: 'Detection Testing', path: '/detection-testing', status: 'available' },
  { label: 'System Health', path: '/health', status: 'available' },
  { label: 'Settings', path: '/settings', status: 'planned', milestone: 8 },
]
