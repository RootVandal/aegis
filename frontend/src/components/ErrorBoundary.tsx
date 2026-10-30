import { Component, type ErrorInfo, type ReactNode } from 'react'

interface State {
  error: Error | null
}

/**
 * Catches rendering errors in a page so one broken view shows a message
 * instead of blanking the whole application. The layout and navigation stay
 * usable; the error details go to the browser console, not the screen.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('AEGIS page error', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div role="alert" className="m-6 rounded-md border border-crit/40 bg-crit-dim px-4 py-3 text-[13px]">
          <p className="font-medium text-crit">This page failed to render.</p>
          <p className="mt-1 text-ink-muted">
            The rest of AEGIS still works: choose another page in the navigation, or reload. Details are in the browser
            console.
          </p>
        </div>
      )
    }
    return this.props.children
  }
}
