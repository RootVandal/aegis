import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import type { TimePoint } from '../../api/dashboard'
import { formatCount } from '../../lib/format'

/*
 * Chart tokens. Series colors are categorical slots 1-2 (dark steps) from the
 * data-viz reference palette, validated against the AEGIS panel surface
 * #11151d: CVD dE 26.8, normal-vision dE 31.8, both >= 3:1 contrast.
 * Text never uses the series colors; identity comes from the swatches.
 */
const SURFACE = '#11151d'
const SERIES = [
  { key: 'synthetic', label: 'Synthetic', color: '#3987e5' },
  { key: 'imported', label: 'Imported', color: '#d95926' },
] as const
const AXIS_TEXT = '#9aa3b4'
const GRID = '#222936'

function bucketLabel(iso: string, bucket: 'hour' | 'day' | 'month'): string {
  const date = new Date(iso)
  const day = date.toISOString().slice(5, 10) // MM-DD
  if (bucket === 'hour') return `${day} ${date.toISOString().slice(11, 13)}:00`
  if (bucket === 'month') return date.toISOString().slice(0, 7)
  return day
}

/** Stacked columns of events per time bucket, split by data origin. */
export function EventsChart({ points, bucket }: { points: TimePoint[]; bucket: 'hour' | 'day' | 'month' }) {
  const [showTable, setShowTable] = useState(false)
  const data = points.map((p) => ({ ...p, label: bucketLabel(p.start, bucket) }))

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-4 text-[12px] text-ink-muted">
        {/* Legend: always present for two series; rect keys mirror the bar marks. */}
        <ul className="flex gap-4" aria-label="Legend">
          {SERIES.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-[2px]" style={{ background: s.color }} aria-hidden="true" />
              {s.label}
            </li>
          ))}
        </ul>
        <span className="text-ink-faint">per {bucket} (UTC)</span>
        <button
          type="button"
          className="ml-auto text-[12px] text-ink-muted underline-offset-2 hover:text-ink hover:underline"
          onClick={() => setShowTable((v) => !v)}
          aria-expanded={showTable}
        >
          {showTable ? 'Show chart' : 'Show as table'}
        </button>
      </div>

      {showTable ? (
        <div className="max-h-64 overflow-auto">
          <table className="w-full text-left text-[12px]">
            <thead className="sticky top-0 bg-surface text-[12px] font-medium text-ink-faint">
              <tr>
                <th className="py-1 pr-4 font-medium">Period (UTC)</th>
                <th className="py-1 pr-4 text-right font-medium">Synthetic</th>
                <th className="py-1 text-right font-medium">Imported</th>
              </tr>
            </thead>
            <tbody className="font-mono tabular-nums">
              {data.map((p) => (
                <tr key={p.start} className="border-t border-line/60">
                  <td className="py-1 pr-4">{p.label}</td>
                  <td className="py-1 pr-4 text-right">{formatCount(p.synthetic)}</td>
                  <td className="py-1 text-right">{formatCount(p.imported)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="h-56" role="img" aria-label={`Events per ${bucket}, split by data origin`}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -12 }} barCategoryGap="20%">
              <CartesianGrid vertical={false} stroke={GRID} strokeWidth={1} />
              <XAxis
                dataKey="label"
                tick={{ fill: AXIS_TEXT, fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: GRID }}
                interval="preserveStartEnd"
                minTickGap={16}
              />
              <YAxis
                tick={{ fill: AXIS_TEXT, fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
                tickFormatter={(value: number) => (value >= 1000 ? `${Math.round(value / 100) / 10}K` : String(value))}
              />
              <Tooltip cursor={{ fill: 'rgba(255,255,255,0.04)' }} content={<ChartTooltip />} isAnimationActive={false} />
              {SERIES.map((s, index) => (
                <Bar
                  key={s.key}
                  dataKey={s.key}
                  name={s.label}
                  stackId="origin"
                  fill={s.color}
                  maxBarSize={24}
                  // The 2px surface-coloured stroke is the gap between stacked segments.
                  stroke={SURFACE}
                  strokeWidth={2}
                  radius={index === SERIES.length - 1 ? [4, 4, 0, 0] : 0}
                  isAnimationActive={false}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}

interface TooltipProps {
  active?: boolean
  label?: string
  payload?: { dataKey?: unknown; value?: unknown }[]
}

/** Values lead, labels follow; series are keyed with a short line, not a box. */
function ChartTooltip({ active, label, payload }: TooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-sm border border-line-strong bg-surface-raised px-2.5 py-1.5 text-[12px] shadow-lg">
      <div className="mb-1 text-ink-faint">{label}</div>
      {SERIES.map((s) => {
        const value = Number(payload.find((p) => p.dataKey === s.key)?.value ?? 0)
        return (
          <div key={s.key} className="flex items-center gap-2">
            <span className="inline-block h-0.5 w-3" style={{ background: s.color }} aria-hidden="true" />
            <span className="font-medium text-ink tabular-nums">{formatCount(value)}</span>
            <span className="text-ink-muted">{s.label}</span>
          </div>
        )
      })}
    </div>
  )
}
