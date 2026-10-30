import { Navigate, Route, Routes } from 'react-router-dom'

import { AppLayout } from './components/layout/AppLayout'
import { NotFoundPage } from './pages/NotFoundPage'
import { SystemHealthPage } from './pages/SystemHealthPage'

export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        {/* The Overview dashboard arrives in milestone 5; until then land on System Health. */}
        <Route index element={<Navigate to="/health" replace />} />
        <Route path="/health" element={<SystemHealthPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
