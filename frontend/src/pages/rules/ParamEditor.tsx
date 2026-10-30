import { useState, type FormEvent } from 'react'

import { ApiError } from '../../api/client'
import type { ParamValue, RuleDetail } from '../../api/detection'
import { BUTTON, BUTTON_PRIMARY, INPUT } from '../../components/Panel'

type Draft = Record<string, string | boolean>

/** Text representation used while editing; converted back on save. */
function toDraft(value: ParamValue): string | boolean {
  if (typeof value === 'boolean') return value
  if (Array.isArray(value)) return value.join('\n')
  if (typeof value === 'object') return JSON.stringify(value, null, 2)
  return String(value)
}

function fromDraft(text: string | boolean, original: ParamValue): ParamValue {
  if (typeof original === 'boolean') return Boolean(text)
  const raw = String(text)
  if (typeof original === 'number') return raw.trim() === '' ? NaN : Number(raw)
  if (Array.isArray(original)) {
    const lines = raw.split('\n').map((line) => line.trim()).filter(Boolean)
    // Lists of numbers (ports) stay numeric so the backend validates them as such.
    return typeof original[0] === 'number' ? lines.map(Number) : lines
  }
  if (typeof original === 'object') return JSON.parse(raw) as Record<string, string>
  return raw
}

export function ParamEditor({
  rule,
  onSave,
}: {
  rule: RuleDetail
  onSave: (params: Record<string, ParamValue>) => Promise<void>
}) {
  const [draft, setDraft] = useState<Draft>(() =>
    Object.fromEntries(Object.entries(rule.params).map(([k, v]) => [k, toDraft(v)])),
  )
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [message, setMessage] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const schema = rule.params_schema.properties ?? {}

  const save = async (params: Record<string, ParamValue>) => {
    setSaving(true)
    setErrors({})
    setMessage(null)
    try {
      // On success the parent reloads the rule and re-creates this form, so
      // the confirmation is shown by the parent, not here.
      await onSave(params)
    } catch (cause) {
      if (cause instanceof ApiError) {
        const byField: Record<string, string> = {}
        for (const detail of cause.details) {
          const field = String(detail.loc[2] ?? 'params')
          byField[field] = detail.msg
        }
        setErrors(byField)
        setMessage(cause.message)
      } else {
        setMessage('Saving failed.')
      }
    } finally {
      setSaving(false)
    }
  }

  const submit = (event: FormEvent) => {
    event.preventDefault()
    // Send only values that differ from the defaults, so future default
    // changes in a new rule version still apply to untouched parameters.
    const overrides: Record<string, ParamValue> = {}
    const parseErrors: Record<string, string> = {}
    for (const [key, defaultValue] of Object.entries(rule.default_params)) {
      try {
        const value = fromDraft(draft[key] ?? '', defaultValue)
        if (JSON.stringify(value) !== JSON.stringify(defaultValue)) overrides[key] = value
      } catch {
        parseErrors[key] = 'Not valid JSON.'
      }
    }
    if (Object.keys(parseErrors).length > 0) {
      setErrors(parseErrors)
      return
    }
    void save(overrides)
  }

  return (
    <form onSubmit={submit} className="space-y-3 text-[12px]" aria-label="Rule parameters">
      {Object.entries(rule.default_params).map(([key, defaultValue]) => {
        const property = schema[key] ?? {}
        const value = draft[key]
        const id = `param-${key}`
        return (
          <div key={key}>
            <label htmlFor={id} className="mb-1 flex min-w-0 items-baseline justify-between gap-3">
              <span className="shrink-0 font-mono text-ink">{key}</span>
              <span className="truncate font-mono text-[11px] text-ink-faint" title={JSON.stringify(defaultValue)}>
                default: {JSON.stringify(defaultValue)}
              </span>
            </label>
            {property.description && <p className="mb-1 text-ink-faint">{property.description}</p>}
            {typeof defaultValue === 'boolean' ? (
              <input
                id={id}
                type="checkbox"
                checked={Boolean(value)}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.checked })}
              />
            ) : property.enum ? (
              <select id={id} className={INPUT} value={String(value)} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}>
                {property.enum.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            ) : typeof defaultValue === 'number' ? (
              <input
                id={id}
                type="number"
                className={INPUT}
                min={property.minimum}
                max={property.maximum}
                value={String(value)}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
              />
            ) : (
              <textarea
                id={id}
                className={`${INPUT} font-mono`}
                rows={Array.isArray(defaultValue) ? Math.min(8, Math.max(2, defaultValue.length)) : 6}
                value={String(value)}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
              />
            )}
            {Array.isArray(defaultValue) && <p className="mt-0.5 text-ink-faint">One value per line.</p>}
            {errors[key] && <p className="mt-0.5 text-crit">{errors[key]}</p>}
          </div>
        )
      })}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        <button type="submit" className={BUTTON_PRIMARY} disabled={saving}>
          {saving ? 'Saving…' : 'Save parameters'}
        </button>
        <button type="button" className={BUTTON} disabled={saving || !rule.customized} onClick={() => void save({})}>
          Reset to defaults
        </button>
        {message && <span className={Object.keys(errors).length ? 'text-crit' : 'text-ink-muted'}>{message}</span>}
      </div>
    </form>
  )
}
