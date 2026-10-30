import { useState, type FormEvent } from 'react'

import { SEVERITIES, type EventFacets, type EventFilters } from '../../api/events'
import { BUTTON, BUTTON_PRIMARY, INPUT } from '../../components/Panel'

// <input type="datetime-local"> has no timezone. AEGIS treats it as UTC and
// says so in the label; the URL always carries an explicit "Z".
export function localInputToUtc(value: string): string | undefined {
  return value ? `${value}:00Z` : undefined
}

export function utcToLocalInput(value: string | undefined): string {
  return value ? value.slice(0, 16) : ''
}

const TEXT_FIELDS = [
  { name: 'hostname', label: 'Host', placeholder: 'ws-fin-01' },
  { name: 'username', label: 'User', placeholder: 'a.kowalski' },
  { name: 'source_ip', label: 'Source IP', placeholder: '10.10.1.11' },
] as const

/**
 * Editable copy of the filters. Nothing is sent until "Apply", so typing
 * never fires a request per keystroke and the URL changes once per search.
 */
export function FilterBar({
  filters,
  facets,
  onApply,
}: {
  filters: EventFilters
  facets: EventFacets | null
  onApply: (next: EventFilters) => void
}) {
  const [draft, setDraft] = useState<EventFilters>(filters)
  const set = (name: keyof EventFilters, value: string) =>
    setDraft((current) => ({ ...current, [name]: value || undefined }))

  const submit = (event: FormEvent) => {
    event.preventDefault()
    onApply({ ...draft, page: undefined })
  }

  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Event filters">
      <div className="flex gap-2">
        <input
          aria-label="Search"
          className={INPUT}
          placeholder="Search host, user, IP, process, command line, event ID…"
          value={draft.q ?? ''}
          onChange={(e) => set('q', e.target.value)}
        />
        <button type="submit" className={BUTTON_PRIMARY}>
          Apply
        </button>
        <button type="button" className={BUTTON} onClick={() => onApply({})}>
          Clear
        </button>
      </div>

      <div className="grid grid-cols-2 gap-x-3 gap-y-2 text-[12px] sm:grid-cols-3 lg:grid-cols-4">
        <Field label="From (UTC)">
          <input
            type="datetime-local"
            className={INPUT}
            value={utcToLocalInput(draft.start)}
            onChange={(e) => set('start', localInputToUtc(e.target.value) ?? '')}
          />
        </Field>
        <Field label="To (UTC)">
          <input
            type="datetime-local"
            className={INPUT}
            value={utcToLocalInput(draft.end)}
            onChange={(e) => set('end', localInputToUtc(e.target.value) ?? '')}
          />
        </Field>
        <Field label="Event type">
          <select className={INPUT} value={draft.event_type ?? ''} onChange={(e) => set('event_type', e.target.value)}>
            <option value="">Any</option>
            {facets?.event_types.map((f) => (
              <option key={f.value} value={f.value}>
                {f.value} ({f.count})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Severity">
          <select className={INPUT} value={draft.severity ?? ''} onChange={(e) => set('severity', e.target.value)}>
            <option value="">Any</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </Field>
        {TEXT_FIELDS.map((field) => (
          <Field key={field.name} label={field.label}>
            <input
              className={INPUT}
              placeholder={field.placeholder}
              value={draft[field.name] ?? ''}
              onChange={(e) => set(field.name, e.target.value)}
            />
          </Field>
        ))}
        <Field label="Data origin">
          <select className={INPUT} value={draft.data_origin ?? ''} onChange={(e) => set('data_origin', e.target.value)}>
            <option value="">Any</option>
            <option value="synthetic">synthetic</option>
            <option value="imported">imported</option>
          </select>
        </Field>
      </div>
    </form>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-ink-faint">{label}</span>
      {children}
    </label>
  )
}
