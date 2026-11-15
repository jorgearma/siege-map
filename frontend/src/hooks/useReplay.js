import { useCallback, useEffect, useRef, useState } from 'react'

const DURATION_MS = 30000

/**
 * Time-lapse: plays the last `hours` of stored history in 30 seconds.
 * The backend sends down-sampled frames; each tick turns one frame into
 * synthetic events that the globe draws exactly like live ones.
 */
export default function useReplay(hours = 24) {
  const [state, setState] = useState({ active: false, loading: false, error: null })
  const [events, setEvents] = useState([])
  const timer = useRef(null)

  const stop = useCallback(() => {
    clearInterval(timer.current)
    timer.current = null
    setEvents([])
    setState({ active: false, loading: false, error: null })
  }, [])

  const start = useCallback(async () => {
    clearInterval(timer.current)
    setEvents([])
    setState({ active: true, loading: true, error: null })
    let data
    try {
      const res = await fetch(`/api/replay?hours=${hours}&buckets=240`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      data = await res.json()
    } catch (e) {
      setState({ active: false, loading: false, error: e.message })
      return
    }
    const frames = data.frames || []
    const total = (data.totals || []).reduce((a, b) => a + b, 0)
    if (!total) {
      setState({ active: false, loading: false, error: 'No stored history yet' })
      return
    }
    const startMs = new Date(data.start).getTime()
    const stepMs = data.bucket_seconds * 1000
    let i = 0
    let shown = 0
    const tick = () => {
      if (i >= frames.length) {
        clearInterval(timer.current)
        timer.current = null
        setState((s) => ({ ...s, done: true, progress: 1 }))
        return
      }
      const batch = frames[i].map(([lat, lon, kind, cc, count], j) => ({
        id: `replay-${i}-${j}`,
        ip: '',
        count,
        source: kind === 'ssh' ? 'ssh' : 'http',
        event_type: kind === 'visit' ? 'visit_desktop' : kind === 'ssh' ? 'failed_password' : 'scanner',
        geo: { lat, lon, country_code: cc },
      }))
      shown += data.totals[i] || 0
      i += 1
      if (batch.length) setEvents((prev) => [...batch, ...prev].slice(0, 500))
      setState({
        active: true, loading: false, error: null, done: false,
        progress: i / frames.length,
        clock: new Date(startMs + i * stepMs),
        shown, total, totals: data.totals, hours,
      })
    }
    timer.current = setInterval(tick, DURATION_MS / Math.max(1, frames.length))
    tick()
  }, [hours])

  useEffect(() => () => clearInterval(timer.current), [])

  return { ...state, events, start, stop }
}
