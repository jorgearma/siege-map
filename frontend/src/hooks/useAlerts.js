import { useMemo } from 'react'
import useApi from './useApi'

/**
 * Alerts = what the API knows (polled) + what the WebSocket just announced.
 * The API wins for anything it already has: it carries the latest state
 * (hits, resolved) of each alert.
 */
export default function useAlerts(live) {
  const data = useApi('/api/alerts?limit=40', 20000)
  return useMemo(() => {
    const byId = new Map()
    for (const a of live) byId.set(a.id, a)
    for (const a of data?.history || []) byId.set(a.id, a)
    for (const a of data?.active || []) byId.set(a.id, a)
    const all = [...byId.values()].sort((a, b) => b.ts.localeCompare(a.ts))
    return {
      all,
      active: all.filter((a) => a.status === 'active'),
      today: data?.today || {},
      enabled: data ? data.enabled !== false : true,
      loaded: Boolean(data),
    }
  }, [data, live])
}
