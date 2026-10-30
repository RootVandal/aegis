import { useState } from 'react'
import { Link } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { fetchRules, fetchRuns, runDetection, type DetectionRun } from '../../api/detection'
import { SeverityBadge } from '../../components/Badges'
import { BUTTON_PRIMARY, ErrorNotice, Panel } from '../../components/Panel'
import { formatCount, formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

export function RulesPage() {
  const [reloadToken, setReloadToken] = useState(0)
  const rules = useApi((signal) => fetchRules(signal), 'rules', reloadToken)
  const runs = useApi((signal) => fetchRuns(signal), 'runs', reloadToken)
  const [running, setRunning] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)

  const run = async () => {
    setRunning(true)
    setRunError(null)
    try {
      await runDetection()
      setReloadToken((token) => token + 1)
    } catch (cause) {
      setRunError(cause instanceof ApiError ? cause.message : 'Detection run failed.')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-[13px] text-ink-muted">
          Deterministic rules evaluated over all stored events. They run automatically after each import; run them
          manually after changing a rule's parameters. Each rule documents its logic, ATT&amp;CK mapping and known
          limitations.
        </p>
        <button type="button" className={BUTTON_PRIMARY} onClick={() => void run()} disabled={running}>
          {running ? 'Running…' : 'Run detections now'}
        </button>
      </div>
      {runError && <p role="alert" className="text-[12px] text-crit">{runError}</p>}

      {rules.status === 'error' && <ErrorNotice error={rules.error} what="rules" />}
      <Panel title="Detection rules" padded={false}>
        {rules.status === 'loading' && <p className="px-4 py-4 text-[13px] text-ink-muted">Loading rules…</p>}
        {rules.status === 'success' && (
          <table className="w-full min-w-[860px] text-left text-[12px]">
            <thead className="border-b border-line text-[11px] uppercase tracking-wider text-ink-faint">
              <tr>
                {['Rule', 'Name', 'Severity', 'ATT&CK', 'Version', 'State', 'Alerts'].map((h) => (
                  <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rules.data.map((rule) => (
                <tr key={rule.id} className="align-top hover:bg-surface-raised">
                  <td className="whitespace-nowrap px-3 py-2 pl-4 font-mono">
                    <Link to={`/rules/${rule.id}`} className="text-ink hover:text-ok">
                      {rule.id}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Link to={`/rules/${rule.id}`} className="text-ink hover:text-ok">
                      {rule.name}
                    </Link>
                    <p className="mt-0.5 text-ink-faint">{rule.description}</p>
                  </td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={rule.severity} />
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-ink-muted">
                    {rule.mitre.map((m) => m.id).join(', ') || '—'}
                  </td>
                  <td className="px-3 py-2 font-mono">v{rule.version}</td>
                  <td className="whitespace-nowrap px-3 py-2">
                    {rule.enabled ? <span className="text-ok">enabled</span> : <span className="text-ink-faint">disabled</span>}
                    {rule.customized && <span className="ml-1.5 text-warn">· tuned</span>}
                  </td>
                  <td className="px-3 py-2 font-mono">
                    {rule.alert_count > 0 ? (
                      <Link to={`/alerts?rule_id=${rule.id}`} className="text-ink hover:text-ok">
                        {formatCount(rule.alert_count)}
                      </Link>
                    ) : (
                      <span className="text-ink-faint">0</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Recent detection runs" padded={false}>
        {runs.status === 'success' && runs.data.length === 0 && (
          <p className="px-4 py-4 text-[13px] text-ink-muted">Detection has not run yet. It runs after the first import.</p>
        )}
        {runs.status === 'success' && runs.data.length > 0 && <RunsTable runs={runs.data} />}
      </Panel>
    </div>
  )
}

function RunsTable({ runs }: { runs: DetectionRun[] }) {
  return (
    <table className="w-full min-w-[640px] text-left text-[12px]">
      <thead className="border-b border-line text-[11px] uppercase tracking-wider text-ink-faint">
        <tr>
          {['#', 'Trigger', 'Finished (UTC)', 'Events', 'Findings', 'New alerts', 'Already known'].map((h) => (
            <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-line font-mono">
        {runs.map((run) => (
          <tr key={run.id}>
            <td className="px-3 py-1.5 pl-4 text-ink-faint">{run.id}</td>
            <td className="px-3 py-1.5">{run.trigger}</td>
            <td className="px-3 py-1.5 text-ink-muted">{formatUtc(run.completed_at).replace(' UTC', '')}</td>
            <td className="px-3 py-1.5">{formatCount(run.events_evaluated)}</td>
            <td className="px-3 py-1.5">{formatCount(run.findings_count)}</td>
            <td className="px-3 py-1.5 text-ink">{formatCount(run.alerts_created)}</td>
            <td className="px-3 py-1.5 text-ink-muted">{formatCount(run.alerts_existing)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
