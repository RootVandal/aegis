import { useState } from 'react'
import { Link } from 'react-router-dom'

import { ApiError } from '../../api/client'
import {
  fetchEvaluationCases,
  fetchEvaluationDatasets,
  fetchEvaluationRun,
  fetchEvaluationRuns,
  startEvaluationRun,
  type EvaluationCase,
  type Metric,
  type RunDetail,
} from '../../api/evaluation'
import { BUTTON, BUTTON_PRIMARY, ErrorNotice, INPUT, Panel } from '../../components/Panel'
import { formatUtc } from '../../lib/format'
import { useApi } from '../../lib/useApi'

/** Undefined metrics are shown as n/a, never as 0% or 100%. */
export function formatMetric(value: Metric): string {
  return value === null ? 'n/a' : `${(value * 100).toFixed(1)}%`
}

const UNDEFINED_HINT: Record<string, string> = {
  precision: 'Undefined: the rule never fired on this suite.',
  recall: 'Undefined: no case in the suite contains this behavior.',
  f1: 'Undefined: no TP, FP or FN.',
}

export function DetectionTestingPage() {
  const [reload, setReload] = useState(0)
  const datasets = useApi((signal) => fetchEvaluationDatasets(signal), 'datasets')
  const runs = useApi((signal) => fetchEvaluationRuns(signal), 'runs', reload)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const runId = selectedId ?? runs.data?.[0]?.id ?? null
  const run = useApi(
    (signal) => (runId === null ? Promise.resolve(null) : fetchEvaluationRun(runId, signal)),
    String(runId),
    reload,
  )
  const [settings, setSettings] = useState<'current' | 'defaults'>('current')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const dataset = datasets.data?.[0]

  const execute = async () => {
    setBusy(true)
    setError(null)
    try {
      const created = await startEvaluationRun(settings)
      setSelectedId(created.id)
      setReload((r) => r + 1)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'The evaluation failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-5 p-4 md:px-8 md:py-7">
      <p className="max-w-4xl text-[13px] text-ink-muted">
        Runs every detection rule against a labeled suite of small test cases and counts how often it is right. All
        numbers come from executing the rules now; nothing is precomputed.
      </p>
      <p role="note" className="max-w-4xl rounded-sm border border-warn/40 bg-warn-dim px-3 py-2 text-[12px] text-warn">
        The suite is synthetic and was written together with the rules. Good scores show the rules behave as designed
        on these cases; they do not show how the rules perform on real telemetry, where attacks and benign activity
        are far more varied.
      </p>

      {datasets.status === 'error' && <ErrorNotice error={datasets.error} what="the test suite" />}
      {dataset && (
        <Panel title={`${dataset.name} · ${dataset.version}`}>
          <p className="text-[12px] text-ink-muted">
            {dataset.case_count} cases:{' '}
            {Object.entries(dataset.categories)
              .map(([category, count]) => `${count} ${category}`)
              .join(' · ')}
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-[12px]">
            <label className="flex items-center gap-2">
              <span className="text-ink-faint">Rule parameters</span>
              <select aria-label="Rule parameters" className={`${INPUT} w-auto`} value={settings}
                      onChange={(e) => setSettings(e.target.value as 'current' | 'defaults')}>
                <option value="current">current configuration</option>
                <option value="defaults">rule defaults</option>
              </select>
            </label>
            <button type="button" className={BUTTON_PRIMARY} disabled={busy} onClick={() => void execute()}>
              {busy ? 'Running…' : 'Run evaluation'}
            </button>
            {error && <span role="alert" className="text-crit">{error}</span>}
          </div>
        </Panel>
      )}

      {runs.status === 'success' && runs.data.length === 0 && (
        <p className="text-[13px] text-ink-muted">No evaluation has been run yet.</p>
      )}
      {run.data && dataset && <RunView run={run.data} definitions={dataset.metric_definitions} datasetId={dataset.id} />}

      {runs.data && runs.data.length > 0 && (
        <Panel title="Run history" padded={false}>
          <table className="w-full min-w-[640px] text-left text-[12px]">
            <thead className="border-b border-line text-[12px] font-medium text-ink-faint">
              <tr>
                {['#', 'When (UTC)', 'Parameters', 'Dataset', 'Precision', 'Recall', 'F1'].map((h) => (
                  <th key={h} className="whitespace-nowrap px-3 py-2 font-medium first:pl-4">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line font-mono">
              {runs.data.map((summary) => (
                <tr key={summary.id} className={summary.id === runId ? 'bg-surface-raised' : ''}>
                  <td className="px-3 py-1.5 pl-4">
                    <button type="button" className="hover:text-accent" onClick={() => setSelectedId(summary.id)}>
                      #{summary.id}
                    </button>
                  </td>
                  <td className="px-3 py-1.5 text-ink-muted">{formatUtc(summary.created_at).replace(' UTC', '')}</td>
                  <td className="px-3 py-1.5">{summary.settings_source}</td>
                  <td className="px-3 py-1.5 text-ink-faint">{summary.dataset_version}</td>
                  <td className="px-3 py-1.5">{formatMetric(summary.micro.precision)}</td>
                  <td className="px-3 py-1.5">{formatMetric(summary.micro.recall)}</td>
                  <td className="px-3 py-1.5">{formatMetric(summary.micro.f1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  )
}

function MetricCell({ value, kind }: { value: Metric; kind: 'precision' | 'recall' | 'f1' }) {
  return (
    <td className={`px-3 py-1.5 text-right ${value === null ? 'text-ink-faint' : ''}`} title={value === null ? UNDEFINED_HINT[kind] : undefined}>
      {formatMetric(value)}
    </td>
  )
}

function RunView({ run, definitions, datasetId }: { run: RunDetail; definitions: Record<string, string>; datasetId: string }) {
  const { micro, macro } = run.results.totals
  const rules = Object.entries(run.results.per_rule)
  return (
    <>
      <Panel title={`Run #${run.id} · ${formatUtc(run.created_at)} · ${run.settings_source} parameters`}>
        <div className="grid gap-4 text-[12px] md:grid-cols-3">
          {(['precision', 'recall', 'f1'] as const).map((kind) => (
            <div key={kind}>
              <div className="text-ink-muted">{kind === 'f1' ? 'F1' : kind[0]!.toUpperCase() + kind.slice(1)} (all rules)</div>
              <div className="mt-1 text-2xl font-semibold text-ink">{formatMetric(micro[kind])}</div>
              <div className="font-mono text-[11px] text-ink-faint">
                macro {formatMetric(macro[kind].value)} over {macro[kind].rules} rule(s)
              </div>
            </div>
          ))}
        </div>
        <p className="mt-3 font-mono text-[12px] text-ink-muted">
          TP {micro.tp} · FP {micro.fp} · FN {micro.fn} · TN {micro.tn} ·{' '}
          {run.input_handling_ok ? 'malformed input rejected as expected' : 'malformed input NOT handled as expected'}
        </p>
        {run.comparison && <Comparison comparison={run.comparison} />}
      </Panel>

      <Panel title="Per rule" padded={false}>
        <table className="w-full min-w-[980px] text-left text-[12px]">
          <thead className="border-b border-line text-[12px] font-medium text-ink-faint">
            <tr>
              {['Rule', 'Version', 'TP', 'FP', 'FN', 'TN', 'Precision', 'Recall', 'F1', 'False positives', 'Missed'].map((h) => (
                <th key={h} className={`whitespace-nowrap px-3 py-2 font-medium first:pl-4 ${['TP', 'FP', 'FN', 'TN', 'Precision', 'Recall', 'F1'].includes(h) ? 'text-right' : ''}`}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line font-mono tabular-nums">
            {rules.map(([ruleId, m]) => (
              <tr key={ruleId} className="align-top">
                <td className="whitespace-nowrap px-3 py-1.5 pl-4">
                  <Link to={`/rules/${ruleId}`} className="text-ink hover:text-accent">{ruleId}</Link>
                  {run.rules[ruleId] && !run.rules[ruleId].enabled && <span className="ml-1 text-ink-faint">(disabled)</span>}
                </td>
                <td className="px-3 py-1.5">v{run.rules[ruleId]?.version}</td>
                <td className="px-3 py-1.5 text-right">{m.tp}</td>
                <td className="px-3 py-1.5 text-right">{m.fp}</td>
                <td className="px-3 py-1.5 text-right">{m.fn}</td>
                <td className="px-3 py-1.5 text-right text-ink-muted">{m.tn}</td>
                <MetricCell value={m.precision} kind="precision" />
                <MetricCell value={m.recall} kind="recall" />
                <MetricCell value={m.f1} kind="f1" />
                <td className="px-3 py-1.5 text-ink-muted">{m.fp_cases.join(', ') || '—'}</td>
                <td className="px-3 py-1.5 text-ink-muted">{m.fn_cases.join(', ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-[2fr_1fr] [&>*]:min-w-0">
        <Cases run={run} datasetId={datasetId} />
        <Panel title="How the numbers are calculated">
          <dl className="space-y-1.5 text-[12px]">
            {Object.entries(definitions).map(([term, text]) => (
              <div key={term}>
                <dt className="inline font-mono text-ink">{term}</dt> <dd className="inline text-ink-muted">{text}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-[12px] text-ink-muted">
            TN counts include cases written for other rules, so they are large and not very informative; AEGIS does not
            report specificity for that reason.
          </p>
        </Panel>
      </div>
    </>
  )
}

function Comparison({ comparison }: { comparison: NonNullable<RunDetail['comparison']> }) {
  const changes = Object.entries(comparison.rules)
  return (
    <div className="mt-3 border-t border-line pt-2 text-[12px]">
      <span className="text-ink-faint">Compared with run #{comparison.previous_run_id}: </span>
      {comparison.dataset_changed && <span className="text-warn">the test suite changed. </span>}
      {changes.length === 0 ? (
        <span className="text-ink-muted">identical results, rule versions and parameters.</span>
      ) : (
        <ul className="mt-1 space-y-0.5 font-mono">
          {changes.map(([ruleId, change]) => (
            <li key={ruleId} className="text-ink-muted">
              {ruleId}:{' '}
              {Object.entries(change.delta)
                .filter(([, d]) => d !== 0)
                .map(([k, d]) => `${k.toUpperCase()} ${d > 0 ? '+' : ''}${d}`)
                .join(', ') || 'no count change'}
              {change.version[0] !== change.version[1] && ` · version v${change.version[0]} → v${change.version[1]}`}
              {change.params_changed && ' · parameters changed'}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Cases({ run, datasetId }: { run: RunDetail; datasetId: string }) {
  const cases = useApi((signal) => fetchEvaluationCases(datasetId, signal), datasetId)
  const [onlyErrors, setOnlyErrors] = useState(true)
  const [open, setOpen] = useState<string | null>(null)
  const byId = new Map<string, EvaluationCase>((cases.data ?? []).map((c) => [c.id, c]))
  const rows = run.results.cases.filter(
    (c) => !onlyErrors || Object.values(c.outcomes).some((o) => o === 'fp' || o === 'fn') || !c.input_handled_as_expected,
  )
  return (
    <Panel
      title={`Test cases (${rows.length} shown)`}
      padded={false}
      actions={
        <label className="flex items-center gap-1.5 text-[12px] text-ink-muted">
          <input type="checkbox" checked={onlyErrors} onChange={(e) => setOnlyErrors(e.target.checked)} />
          only misclassified
        </label>
      }
    >
      <ul className="divide-y divide-line">
        {rows.map((result) => {
          const definition = byId.get(result.case_id)
          const wrong = Object.entries(result.outcomes).filter(([, o]) => o === 'fp' || o === 'fn')
          return (
            <li key={result.case_id} className="px-4 py-2 text-[12px]">
              <button type="button" className="w-full text-left" onClick={() => setOpen(open === result.case_id ? null : result.case_id)}
                      aria-expanded={open === result.case_id}>
                <span className="font-mono text-ink">{result.case_id}</span>{' '}
                <span className="rounded-sm border border-line-strong px-1 text-[11px] text-ink-muted">{result.category}</span>{' '}
                <span className="text-ink-muted">{definition?.title}</span>
                {wrong.map(([ruleId, outcome]) => (
                  <span key={ruleId} className={`ml-2 font-mono text-[11px] ${outcome === 'fp' ? 'text-warn' : 'text-crit'}`}>
                    {outcome.toUpperCase()} {ruleId}
                  </span>
                ))}
              </button>
              {open === result.case_id && definition && (
                <div className="mt-2 space-y-1">
                  <p className="text-ink-muted">{definition.description}</p>
                  <p className="font-mono text-ink-faint">
                    expected: {result.expected.join(', ') || 'none'} · fired: {result.fired.join(', ') || 'none'}
                    {result.rejected > 0 && ` · ${result.rejected} record(s) rejected`}
                  </p>
                  <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-sm bg-canvas p-2 font-mono text-[11px] text-ink-muted">
                    {JSON.stringify(definition.records, null, 2)}
                  </pre>
                </div>
              )}
            </li>
          )
        })}
      </ul>
      <div className="border-t border-line px-4 py-2">
        <button type="button" className={BUTTON} onClick={() => setOnlyErrors((v) => !v)}>
          {onlyErrors ? 'Show all cases' : 'Show only misclassified'}
        </button>
      </div>
    </Panel>
  )
}
