import { lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import { AppLayout } from './components/layout/AppLayout'

// Each page is its own chunk, so e.g. the charting library is only downloaded
// by the pages that draw charts.
const AlertDetailPage = lazy(() => import('./pages/alerts/AlertDetailPage').then((m) => ({ default: m.AlertDetailPage })))
const AlertsPage = lazy(() => import('./pages/alerts/AlertsPage').then((m) => ({ default: m.AlertsPage })))
const EventDetailPage = lazy(() => import('./pages/events/EventDetailPage').then((m) => ({ default: m.EventDetailPage })))
const EventExplorerPage = lazy(() => import('./pages/events/EventExplorerPage').then((m) => ({ default: m.EventExplorerPage })))
const ImportPage = lazy(() => import('./pages/events/ImportPage').then((m) => ({ default: m.ImportPage })))
const IncidentDetailPage = lazy(() => import('./pages/incidents/IncidentDetailPage').then((m) => ({ default: m.IncidentDetailPage })))
const IncidentsPage = lazy(() => import('./pages/incidents/IncidentsPage').then((m) => ({ default: m.IncidentsPage })))
const InvestigationPage = lazy(() => import('./pages/investigation/InvestigationPage').then((m) => ({ default: m.InvestigationPage })))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage').then((m) => ({ default: m.NotFoundPage })))
const OverviewPage = lazy(() => import('./pages/overview/OverviewPage').then((m) => ({ default: m.OverviewPage })))
const RuleDetailPage = lazy(() => import('./pages/rules/RuleDetailPage').then((m) => ({ default: m.RuleDetailPage })))
const RulesPage = lazy(() => import('./pages/rules/RulesPage').then((m) => ({ default: m.RulesPage })))
const ScenarioLabPage = lazy(() => import('./pages/scenarios/ScenarioLabPage').then((m) => ({ default: m.ScenarioLabPage })))
const ScenarioPage = lazy(() => import('./pages/scenarios/ScenarioPage').then((m) => ({ default: m.ScenarioPage })))
const SystemHealthPage = lazy(() => import('./pages/SystemHealthPage').then((m) => ({ default: m.SystemHealthPage })))

export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/events" element={<EventExplorerPage />} />
        <Route path="/events/import" element={<ImportPage />} />
        <Route path="/events/:eventId" element={<EventDetailPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
        <Route path="/investigation" element={<InvestigationPage />} />
        <Route path="/scenarios" element={<ScenarioLabPage />} />
        <Route path="/scenarios/:scenarioId" element={<ScenarioPage />} />
        <Route path="/health" element={<SystemHealthPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
