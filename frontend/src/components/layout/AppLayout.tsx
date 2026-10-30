import { useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'

import { NAV_ITEMS } from '../../navigation'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

export function AppLayout() {
  const [menuOpen, setMenuOpen] = useState(false)
  const { pathname } = useLocation()
  const section = NAV_ITEMS.find((item) => pathname === item.path || pathname.startsWith(`${item.path}/`))
  const title = pathname === '/events/import' ? 'Import Events' : (section?.label ?? 'Not found')

  return (
    <div className="flex h-full">
      {/* Desktop: fixed sidebar. */}
      <div className="hidden md:block">
        <Sidebar />
      </div>

      {/* Small screens: the same sidebar as a dismissible drawer. */}
      {menuOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 bg-black/60"
            onClick={() => setMenuOpen(false)}
          />
          <div className="relative h-full w-56">
            <Sidebar onNavigate={() => setMenuOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar title={title} onOpenMenu={() => setMenuOpen(true)} />
        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
