/**
 * Single source of truth for the sidebar.
 *
 * Pages that do not exist yet are listed as "planned" with the milestone that
 * delivers them. They render as disabled items, never as links, so the UI
 * does not pretend a feature works before it does.
 */

export type NavGroup = 'Monitor' | 'Data' | 'Lab' | 'System'

export interface NavItem {
  label: string
  path: string
  group: NavGroup
  status: 'available' | 'planned'
  milestone?: number
}

export const NAV_GROUPS: readonly NavGroup[] = ['Monitor', 'Data', 'Lab', 'System']

export const NAV_ITEMS: readonly NavItem[] = [
  { label: 'Overview', group: 'Monitor', path: '/overview', status: 'available' },
  { label: 'Alerts', group: 'Monitor', path: '/alerts', status: 'available' },
  { label: 'Incidents', group: 'Monitor', path: '/incidents', status: 'available' },
  { label: 'Investigation', group: 'Monitor', path: '/investigation', status: 'available' },
  { label: 'Event Explorer', group: 'Data', path: '/events', status: 'available' },
  { label: 'Detection Rules', group: 'Data', path: '/rules', status: 'available' },
  { label: 'Scenario Lab', group: 'Lab', path: '/scenarios', status: 'available' },
  { label: 'Detection Testing', group: 'Lab', path: '/detection-testing', status: 'available' },
  { label: 'System Health', group: 'System', path: '/health', status: 'available' },
  { label: 'Settings', group: 'System', path: '/settings', status: 'available' },
]
