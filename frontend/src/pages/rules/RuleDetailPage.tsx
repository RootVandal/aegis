import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { fetchRule, updateRule, type ParamValue, type RuleDetail } from '../../api/detection'
import { SeverityBadge } from '../../components/Badges'
import { BUTTON, ErrorNotice, Panel } from '../../components/Panel'
import { useApi } from '../../lib/useApi'
import { ParamEditor } from './ParamEditor'

export function RuleDetailPage() {
  const { ruleId = '' } = useParams()
  const rule = useApi((signal) => fetchRule(ruleId, signal), ruleId)
  // PATCH returns the updated rule, so it replaces the loaded one directly
  // instead of re-fetching (which would unmount the page while loading).
  const [updated, setUpdated] = useState<RuleDetail | null>(null)
  const current = updated?.id === ruleId ? updated : rule.data

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 md:p-6">
      <Link to="/rules" className="text-[12px] text-ink-muted hover:text-ink">
        ← Detection Rules
      </Link>
      {rule.status === 'loading' && !current && <p className="text-[13px] text-ink-muted">Loading rule…</p>}
      {rule.status === 'error' && <ErrorNotice error={rule.error} what="this rule" />}
      {current && <RuleView rule={current} onUpdated={setUpdated} />}
    </div>
  )
}

function RuleView({ rule, onUpdated }: { rule: RuleDetail; onUpdated: (rule: RuleDetail) => void }) {
  const [toggling, setToggling] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const toggle = async () => {
    setToggling(true)
    try {
      onUpdated(await updateRule(rule.id, { enabled: !rule.enabled }))
    } finally {
      setToggling(false)
    }
  }
  const saveParams = async (params: Record<string, ParamValue>) => {
    const saved = await updateRule(rule.id, { params })
    setNotice(
      Object.keys(params).length === 0
        ? 'Defaults restored. They apply from the next detection run.'
        : 'Saved. The new parameters apply from the next detection run.',
    )
    onUpdated(saved)
  }

  return (
    <>
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-base font-medium text-ink">{rule.name}</h2>
          <SeverityBadge severity={rule.severity} />
          <span className="font-mono text-[12px] text-ink-muted">
            {rule.id} · v{rule.version}
          </span>
          <span className={`text-[12px] ${rule.enabled ? 'text-ok' : 'text-ink-faint'}`}>
            {rule.enabled ? 'enabled' : 'disabled'}
          </span>
          <button type="button" className={BUTTON} disabled={toggling} onClick={() => void toggle()}>
            {rule.enabled ? 'Disable' : 'Enable'}
          </button>
          {rule.alert_count > 0 && (
            <Link to={`/alerts?rule_id=${rule.id}`} className="text-[12px] text-ok hover:underline">
              {rule.alert_count} alert(s) →
            </Link>
          )}
        </div>
        <p className="max-w-3xl text-[13px] text-ink-muted">{rule.description}</p>
      </header>

      {/* min-w-0: grid items default to min-width:auto and would not shrink. */}
      <div className="grid gap-4 lg:grid-cols-[3fr_2fr]">
        <div className="min-w-0 space-y-4">
          <Panel title="Detection logic">
            <List items={rule.logic} ordered />
            <h3 className="mb-1 mt-3 text-[11px] uppercase tracking-wider text-ink-faint">Required fields</h3>
            <ul className="flex flex-wrap gap-1.5">
              {rule.required_fields.map((field) => (
                <li key={field} className="rounded-sm border border-line-strong px-1.5 py-0.5 font-mono text-[11px]">
                  {field}
                </li>
              ))}
            </ul>
          </Panel>

          <Panel title={`MITRE ATT&CK (${rule.attack_version})`}>
            {rule.mitre_details.length === 0 && <p className="text-[13px] text-ink-muted">No defensible mapping.</p>}
            <div className="space-y-3">
              {rule.mitre_details.map((m) => (
                <div key={m.id} className="text-[12px]">
                  <a
                    href={m.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-ink hover:text-ok"
                  >
                    {m.id} {m.name} ↗
                  </a>
                  <span className="ml-2 text-ink-faint">{m.tactics.join(', ')}</span>
                  <dl className="mt-1 grid grid-cols-[90px_1fr] gap-x-3 gap-y-0.5 text-ink-muted">
                    <dt className="text-ink-faint">Why</dt>
                    <dd>{m.relationship}</dd>
                    <dt className="text-ink-faint">Telemetry</dt>
                    <dd>{m.telemetry}</dd>
                    <dt className="text-ink-faint">Not covered</dt>
                    <dd>{m.limitations}</dd>
                  </dl>
                </div>
              ))}
            </div>
            <p className="mt-3 border-t border-line pt-2 text-[11px] text-ink-faint">
              A mapping describes behavior the rule may detect. It does not identify an adversary, and the rule does not
              cover every way the technique can be performed.
            </p>
          </Panel>

          <Panel title="Investigation steps">
            <List items={rule.investigation_steps} ordered />
          </Panel>

          <div className="grid gap-4 md:grid-cols-2">
            <Panel title="Common false positives">
              <List items={rule.false_positives} />
            </Panel>
            <Panel title="Known limitations">
              <List items={rule.limitations} />
            </Panel>
          </div>
        </div>

        <div className="min-w-0 space-y-4">
          <Panel title="Parameters">
            {notice && (
              <p role="status" className="mb-3 rounded-sm border border-ok/40 bg-ok-dim px-2 py-1 text-[12px] text-ok">
                {notice}
              </p>
            )}
            {/* key: rebuild the form from server values after every save or reset. */}
            <ParamEditor key={JSON.stringify(rule.params)} rule={rule} onSave={saveParams} />
          </Panel>
          <Panel title="What an alert cannot tell you">
            <List items={rule.unknowns} />
          </Panel>
          <Panel title="Change history">
            <ul className="space-y-1 text-[12px]">
              {rule.changelog.map((change) => (
                <li key={change.version}>
                  <span className="font-mono text-ink">v{change.version}</span>{' '}
                  <span className="font-mono text-ink-faint">{change.date}</span>{' '}
                  <span className="text-ink-muted">{change.description}</span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
    </>
  )
}

function List({ items, ordered = false }: { items: string[]; ordered?: boolean }) {
  const Tag = ordered ? 'ol' : 'ul'
  return (
    <Tag className={`space-y-1 pl-5 text-[13px] text-ink-muted ${ordered ? 'list-decimal' : 'list-disc'}`}>
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </Tag>
  )
}
