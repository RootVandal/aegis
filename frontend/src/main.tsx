import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import { App } from './App'
import { HealthProvider } from './health/HealthContext'
import './index.css'

const root = document.getElementById('root')
if (!root) throw new Error('Root element #root is missing from index.html.')

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <HealthProvider>
        <App />
      </HealthProvider>
    </BrowserRouter>
  </StrictMode>,
)
