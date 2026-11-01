import { useState } from 'react'

import { apiGet } from '../api/client'
import { ErrorNotice, BUTTON, Panel } from '../components/Panel'
import { formatCount } from '../lib/format'
import { useApi } from '../lib/useApi'

interface EffectiveSettings {
  version: string
  environment: string
  database: string
  cors_origins: string[]
  auto_detect: boolean
  log_level: string
  max_ingest_bytes: number
  max_ingest_records: number
  max_record_bytes: number
  max_request_body_bytes: number
  attack_version: string
  rule_count: number
  authentication: string
}

const DRAFT_PREFIX = 'aegis.scenario-draft.'

function storedDrafts(): string[] {
  try {
    return Object.keys(localStorage).filter((key) => key.startsWith(DRAFT_PREFIX))
  } catch {
    return []
  }
}

export function SettingsPage() {
  const settings = useApi((signal) => apiGet<EffectiveSettings>('/api/v1/settings', { signal }), 'settings')
  const [drafts, setDrafts] = useState(storedDrafts)

  const clearDrafts = () => {
    try {
      drafts.forEach((key) => localStorage.removeItem(key))
    } catch {
      // Storage unavailable: nothing to clear.
    }
    setDrafts(storedDrafts())
  }

  const s = settings.data
  return (
    <div className="mx-auto max-w-4xl space-y-5 p-4 md:px-8 md:py-7">
      <p className="text-[13px] text-ink-muted">
        Server settings come from <code className="font-mono text-ink">AEGIS_*</code> environment variables (see{' '}
        <code className="font-mono text-ink">.env.example</code>) and are shown here read-only. Restart the backend to
        apply changes. Detection rule parameters are configured on each rule's page.
      </p>
      {settings.status === 'error' && <ErrorNotice error={settings.error} what="settings" />}
      {s && (
        <Panel title="Server configuration">
          <dl className="grid grid-cols-1 gap-x-8 gap-y-2 text-[13px] sm:grid-cols-2">
            <Row label="Version" value={`v${s.version}`} />
            <Row label="Environment" value={s.environment} />
            <Row label="Database" value={s.database} />
            <Row label="Log level" value={s.log_level} />
            <Row label="Auto-detect after import" value={s.auto_detect ? 'on' : 'off'} />
            <Row label="Detection rules" value={`${s.rule_count} (ATT&CK ${s.attack_version})`} />
            <Row label="Import body limit" value={`${formatCount(s.max_ingest_bytes)} bytes`} />
            <Row label="Records per import" value={formatCount(s.max_ingest_records)} />
            <Row label="Bytes per record" value={formatCount(s.max_record_bytes)} />
            <Row label="Other request bodies" value={`${formatCount(s.max_request_body_bytes)} bytes`} />
            <Row label="CORS origins" value={s.cors_origins.join(', ') || 'none'} />
            <Row label="Authentication" value={s.authentication} warn />
          </dl>
        </Panel>
      )}
      <Panel title="This browser">
        <p className="text-[13px] text-ink-muted">
          Scenario Lab keeps unsent answers in this browser's local storage. Nothing else is stored client-side.
        </p>
        <div className="mt-2 flex items-center gap-3 text-[13px]">
          <span className="font-mono text-ink">{drafts.length} saved draft(s)</span>
          <button type="button" className={BUTTON} disabled={drafts.length === 0} onClick={clearDrafts}>
            Clear scenario drafts
          </button>
        </div>
      </Panel>
    </div>
  )
}

function Row({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line/60 pb-1.5">
      <dt className="text-ink-muted">{label}</dt>
      <dd className={`text-right font-mono ${warn ? 'text-warn' : 'text-ink'}`}>{value}</dd>
    </div>
  )
}
