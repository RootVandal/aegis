import { Navigate, Route, Routes } from 'react-router-dom'

import { AppLayout } from './components/layout/AppLayout'
import { AlertDetailPage } from './pages/alerts/AlertDetailPage'
import { AlertsPage } from './pages/alerts/AlertsPage'
import { EventDetailPage } from './pages/events/EventDetailPage'
import { EventExplorerPage } from './pages/events/EventExplorerPage'
import { ImportPage } from './pages/events/ImportPage'
import { NotFoundPage } from './pages/NotFoundPage'
import { RuleDetailPage } from './pages/rules/RuleDetailPage'
import { RulesPage } from './pages/rules/RulesPage'
import { SystemHealthPage } from './pages/SystemHealthPage'

export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        {/* The Overview dashboard arrives in milestone 5; until then land on the Event Explorer. */}
        <Route index element={<Navigate to="/events" replace />} />
        <Route path="/events" element={<EventExplorerPage />} />
        <Route path="/events/import" element={<ImportPage />} />
        <Route path="/events/:eventId" element={<EventDetailPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/health" element={<SystemHealthPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
