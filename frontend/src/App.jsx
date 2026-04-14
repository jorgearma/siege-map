import React, { useState, useEffect, useRef } from 'react'
import useWebSocket from './hooks/useWebSocket'
import WorldMap from './components/WorldMap'
import EventFeed from './components/EventFeed'
import StatsPanel from './components/StatsPanel'
import Charts from './components/Charts'
import AttackerProfile from './components/AttackerProfile'
import ExportPanel from './components/ExportPanel'
import FeedFilters from './components/FeedFilters'

/* ── Matrix Rain Background ─────────────────────────── */
function MatrixRain() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let w, h, columns, drops

    const chars =
      'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF{}[]<>|/\\:;=+-*&^%$#@!'

    function resize() {
      w = canvas.width = window.innerWidth
      h = canvas.height = window.innerHeight
      columns = Math.floor(w / 16)
      drops = Array.from({ length: columns }, () => Math.random() * -50)
    }

    resize()
    window.addEventListener('resize', resize)

    function draw() {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.06)'
      ctx.fillRect(0, 0, w, h)
      ctx.font = '14px monospace'

      for (let i = 0; i < drops.length; i++) {
        if (drops[i] < 0) { drops[i] += 0.3; continue }
        const char = chars[Math.floor(Math.random() * chars.length)]
        const x = i * 16
        const y = drops[i] * 16
        ctx.fillStyle = '#00ff41'
        ctx.globalAlpha = 0.85
        ctx.fillText(char, x, y)
        ctx.globalAlpha = 0.08
        ctx.fillText(chars[Math.floor(Math.random() * chars.length)], x, y - 16)
        ctx.globalAlpha = 1
        drops[i]++
        if (y > h && Math.random() > 0.98) drops[i] = Math.random() * -30
      }
    }

    const interval = setInterval(draw, 70)
    return () => { clearInterval(interval); window.removeEventListener('resize', resize) }
  }, [])

  return <canvas ref={canvasRef} className="matrix-rain" />
}

/* ── Uptime counter ─────────────────────────────────── */
function Uptime() {
  const [seconds, setSeconds] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setSeconds((s) => s + 1), 1000)
    return () => clearInterval(id)
  }, [])
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  return (
    <span>
      {String(h).padStart(2, '0')}:{String(m).padStart(2, '0')}:{String(s).padStart(2, '0')}
    </span>
  )
}

/* ── Time Windows ───────────────────────────────────── */
const WINDOWS = [
  { label: '5m',  value: '5m'  },
  { label: '15m', value: '15m' },
  { label: '1h',  value: '1h'  },
  { label: '24h', value: '24h' },
  { label: 'ALL', value: ''    },
]

/* ── Main App ───────────────────────────────────────── */
export default function App() {
  const { events, initialIds, config, connected } = useWebSocket()
  const [timeWindow, setTimeWindow] = useState('')
  const [selectedIp, setSelectedIp] = useState(null)
  const [sourceFilter, setSourceFilter] = useState('all')

  function handleIpClick(ip) { setSelectedIp(ip) }
  function handleCloseDrawer() { setSelectedIp(null) }

  return (
    <div className="app">
      <MatrixRain />
      <div className="crt-overlay" />

      <div className="app-content">
        {/* ── Header ── */}
        <header className="header">
          <div className="header-left">
            <div className="terminal-prompt">&gt;_</div>
            <h1 className="glitch" data-text="SIEGE-MAP">
              SIEGE-MAP
            </h1>
            <span className={`status ${connected ? 'online' : 'offline'}`}>
              <span className="status-dot" />
              {connected ? 'LIVE_STREAM' : 'DISCONNECTED'}
            </span>
          </div>
          <div className="header-right">
            <ExportPanel window={timeWindow} />
            <div className="window-selector">
              <span className="selector-label">TIME_WINDOW:</span>
              {WINDOWS.map((w) => (
                <button
                  key={w.value}
                  className={timeWindow === w.value ? 'active' : ''}
                  onClick={() => setTimeWindow(w.value)}
                >
                  [{w.label}]
                </button>
              ))}
            </div>
          </div>
        </header>

        {/* ── Main grid ── */}
        <main className="main-grid">
          <section className="map-section">
            <div className="section-label">
              <span className="label-bracket">[</span>
              THREAT_MAP
              <span className="label-bracket">]</span>
              <span className="label-line" />
            </div>
            <WorldMap events={events} initialIds={initialIds} config={config} onIpClick={handleIpClick} />
          </section>

          <aside className="sidebar">
            <StatsPanel window={timeWindow} onIpClick={handleIpClick} />
            <EventFeed events={events} onIpClick={handleIpClick} activeFilter={sourceFilter} />
          </aside>
        </main>

        {/* ── Charts + Feed Filters ── */}
        <footer className="charts-section">
          <Charts window={timeWindow} />
          <div className="feed-filters-section">
            <FeedFilters
              events={events}
              activeFilter={sourceFilter}
              onChange={setSourceFilter}
            />
          </div>
        </footer>

        {/* ── System footer ── */}
        <div className="system-footer">
          <span>LOW_INTERACTION_HONEYPOT</span>
          <span className="footer-sep">::</span>
          <span>SENSOR: {config?.vps_label || '...'}</span>
          <span className="footer-sep">::</span>
          <span>UPTIME: <Uptime /></span>
          <span className="footer-sep">::</span>
          <span>EVENTS: {events.length}</span>
        </div>
      </div>

      {/* ── Attacker profile drawer ── */}
      {selectedIp && (
        <AttackerProfile ip={selectedIp} onClose={handleCloseDrawer} />
      )}
    </div>
  )
}
