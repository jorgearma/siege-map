import { useEffect, useRef, useState, useCallback } from 'react'

const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`

export default function useWebSocket() {
  const [events, setEvents] = useState([])
  const [config, setConfig] = useState(null)
  const [connected, setConnected] = useState(false)
  const initialIdsRef = useRef(new Set())
  const wsRef = useRef(null)
  const reconnectRef = useRef(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      console.log('WebSocket connected')
    }

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)

        if (msg.type === 'ping') {
          return // ignore keepalive pings
        } else if (msg.type === 'config') {
          setConfig(msg.data)
        } else if (msg.type === 'initial') {
          // Mark historical IDs so the map skips animating them
          msg.data.forEach((ev) => initialIdsRef.current.add(ev.id))
          setEvents(msg.data)
        } else if (msg.type === 'events') {
          setEvents((prev) => {
            const merged = [...msg.data, ...prev]
            return merged.slice(0, 500) // keep last 500 in UI
          })
        }
      } catch (err) {
        console.error('WS parse error:', err)
      }
    }

    ws.onclose = () => {
      setConnected(false)
      console.log('WebSocket disconnected, reconnecting in 3s...')
      reconnectRef.current = setTimeout(connect, 3000)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  return { events, initialIds: initialIdsRef.current, config, connected }
}
