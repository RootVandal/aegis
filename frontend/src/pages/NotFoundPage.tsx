import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <div className="p-6 text-[13px]">
      <p className="text-ink">This page does not exist.</p>
      <p className="mt-1 text-ink-muted">
        It may belong to a feature that is not implemented yet.{' '}
        <Link to="/health" className="text-ok underline-offset-2 hover:underline">
          Go to System Health
        </Link>
      </p>
    </div>
  )
}
