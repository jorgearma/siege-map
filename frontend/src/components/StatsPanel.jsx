import React, { useEffect, useState, useRef, useCallback } from 'react'
import { isKnownRoute } from '../config/knownRoutes'

function useFetch(url, interval = 5000) {
  const [data, setData] = useState(null)
  useEffect(() => {
    let active = true
    async function load() {
      try {
        const res = await fetch(url)
        if (res.ok && active) setData(await res.json())
      } catch {
        // retry next cycle
      }
    }
    load()
    const id = setInterval(load, interval)
    return () => { active = false; clearInterval(id) }
  }, [url, interval])
  return data
}

function formatCount(n) {
  if (n == null) return '—'
  return n.toLocaleString()
}

/* ── Color system ─────────────────────────────────────── */
const PATTERN_COLORS = {
  DICTIONARY_ATTACK:   '#ff0040',
  CREDENTIAL_STUFFING: '#ff6600',
  PASSWORD_SPRAYING:   '#ffb000',
  SINGLE_PROBE:        '#00d4ff',
}

const PATTERN_LABELS = {
  DICTIONARY_ATTACK:   'DICT ATTACK',
  CREDENTIAL_STUFFING: 'CRED STUFF',
  PASSWORD_SPRAYING:   'PASS SPRAY',
  SINGLE_PROBE:        'SINGLE PROBE',
}

function StatusBadge({ status }) {
  const s = status
  const color = s >= 200 && s < 300 ? '#00ff41'
              : s >= 300 && s < 400 ? '#00bfff'
              : s >= 400 && s < 500 ? '#ffd700'
              : '#ff2020'
  return (
    <span className="stat-status-badge" style={{ color, borderColor: color + '44', background: color + '0d' }}>
      {status}
    </span>
  )
}

const IP_TABS = [
  { key: 'all',    label: 'ALL',      color: '#00ff41' },
  { key: 'ssh',    label: 'SSH',      color: '#ff2020' },
  { key: 'http',   label: 'HTTP',     color: '#ffd700' },
  { key: 'visits', label: 'VISITS',   color: '#1e90ff' },
  { key: 'recent', label: 'RECENT',   color: '#cc88ff' },
]

function formatTime(ts) {
  if (!ts) return '--:--:--'
  try { return new Date(ts).toLocaleTimeString('en-US', { hour12: false }) }
  catch { return ts.slice(11, 19) }
}

/* ── Glitch skull messages ─────────────────────────── */
const GLITCH_LINES = [
  'CONNECTION_LOST',
  'BREACH_DETECTED',
  'SIGNAL_CORRUPT',
  'SYS_FAULT',
  'PKT_OVERFLOW',
  'AUTH_HIJACKED',
]

const SKULL = `  ░▒▓██▓▒░
 ░█▀░░░░▀█░
 █│▀▀░▀▀│█
 █│ ●░● │█
 ░█░▄▄▄░█░
  ░▀█▀█▀░
   ░▀▀▀░`

function TotalCard({ total }) {
  const [glitching, setGlitching] = useState(false)
  const [glitchMsg, setGlitchMsg] = useState('')
  const intervalRef = useRef(null)

  const triggerGlitch = useCallback(() => {
    const msg = GLITCH_LINES[Math.floor(Math.random() * GLITCH_LINES.length)]
    setGlitchMsg(msg)
    setGlitching(true)
    setTimeout(() => setGlitching(false), 1200)
  }, [])

  useEffect(() => {
    const first = 8000 + Math.random() * 7000
    const t1 = setTimeout(() => {
      triggerGlitch()
      intervalRef.current = setInterval(() => triggerGlitch(), 18000 + Math.random() * 7000)
    }, first)
    return () => {
      clearTimeout(t1)
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [triggerGlitch])

  return (
    <div className={`stat-card total-card${glitching ? ' total-card--glitch' : ''}`}>
      {/* Glitch overlay */}
      <div className={`glitch-overlay${glitching ? ' active' : ''}`}>
        <div className="glitch-scanline-burst" />
        <pre className="glitch-skull">{SKULL}</pre>
        <span className="glitch-msg">{glitchMsg}</span>
      </div>

      {/* Normal content */}
      <div className={`total-card-content${glitching ? ' total-content--glitch' : ''}`}>
        <div className="stat-value-wrapper">
          <span className="stat-value">{formatCount(total)}</span>
        </div>
        <span className="stat-label">EVENTS CAPTURED</span>
      </div>
    </div>
  )
}

export default function StatsPanel({ window: timeWindow, onIpClick }) {
  const [activeIpTab, setActiveIpTab] = useState('all')
  const [activeHttpTab, setActiveHttpTab] = useState('bots')
  const qs = timeWindow ? `?window=${timeWindow}` : ''
  const sep = qs ? '&' : '?'

  const total     = useFetch(`/api/stats/total${qs}`)
  const countries = useFetch(`/api/stats/countries${qs}`)
  const ipsAll    = useFetch(`/api/stats/ips${qs}${sep}limit=500`)
  const ipsSsh    = useFetch(`/api/stats/ips${qs}${sep}limit=500&source=ssh`)
  const ipsHttp   = useFetch(`/api/stats/ips${qs}${sep}limit=500&source=http`)
  const ipsVisits = useFetch(`/api/stats/ips${qs}${sep}limit=500&source=visits`)
  const recentEvt = useFetch(`/api/events?limit=10`, 3000)
  const usernames   = useFetch(`/api/stats/usernames${qs}${sep}limit=500`)
  const httpRoutes  = useFetch(`/api/stats/http-routes${qs}${sep}limit=500`)
  const patterns  = useFetch(`/api/stats/patterns${qs}`, 10000)

  const maxCountry = countries?.countries?.[0]?.count || 1

  const patternEntries = Object.entries(patterns?.patterns || {})
  const maxPattern = Math.max(1, ...patternEntries.map(([, v]) => v))

  const allUsers = usernames?.usernames || []
  const sshUsers = allUsers.filter((u) => !u.username.startsWith('/') && !u.username.startsWith('POST ') && !u.username.startsWith('('))

  const allRoutes  = httpRoutes?.routes || []
  const realRoutes = allRoutes.filter((r) => isKnownRoute(r.path))
  const botRoutes  = allRoutes.filter((r) => !isKnownRoute(r.path))

  const recentEvents = recentEvt?.events || []

  const ipMap = {
    all:    ipsAll?.ips    || [],
    ssh:    ipsSsh?.ips    || [],
    http:   ipsHttp?.ips   || [],
    visits: ipsVisits?.ips || [],
  }

  const visibleIps = activeIpTab !== 'recent' ? (ipMap[activeIpTab] || []) : []
  const maxVisible = visibleIps[0]?.count || 1
  const activeTabColor = IP_TABS.find((t) => t.key === activeIpTab)?.color || '#00ff41'

  return (
    <div className="stats-panel">
      {/* ── Total Counter (hero) with glitch effect ── */}
      <TotalCard total={total?.total} />

      {/* ── Attack Patterns ── */}
      {patternEntries.length > 0 && (
        <div className="stat-card">
          <div className="stat-card-header">ATTACK PATTERNS</div>
          <ul className="stat-list">
            {patternEntries
              .sort(([, a], [, b]) => b - a)
              .map(([pattern, count]) => {
                const pColor = PATTERN_COLORS[pattern] || '#00ff41'
                return (
                  <li key={pattern}>
                    <span
                      className="stat-name mono"
                      style={{ color: pColor }}
                    >
                      {PATTERN_LABELS[pattern] || pattern}
                    </span>
                    <span className="stat-count" style={{ color: pColor, textShadow: `0 0 6px ${pColor}55` }}>
                      {formatCount(count)}
                    </span>
                    <span
                      className="stat-bar-track"
                      style={{
                        width: `${(count / maxPattern) * 100}%`,
                        background: pColor,
                      }}
                    />
                  </li>
                )
              })}
          </ul>
        </div>
      )}

      {/* ── Top Origins ── */}
      <div className="stat-card">
        <div className="stat-card-header">TOP ORIGINS</div>
        <ul className="stat-list">
          {(countries?.countries || []).map((c) => (
            <li key={c.country}>
              <span className="stat-name">{c.country}</span>
              <span className="stat-count">{formatCount(c.count)}</span>
              <span
                className="stat-bar-track"
                style={{ width: `${(c.count / maxCountry) * 100}%` }}
              />
            </li>
          ))}
        </ul>
      </div>

      {/* ── IPs with source tabs ── */}
      <div className="stat-card stat-card--ips">
        <div className="stat-card-header">IP ADDRESSES</div>
        <div className="stat-ip-tabs">
          {IP_TABS.map((tab) => (
            <button
              key={tab.key}
              className={`stat-ip-tab${activeIpTab === tab.key ? ' active' : ''}`}
              style={activeIpTab === tab.key ? {
                color: tab.color,
                borderColor: tab.color + '60',
                background: tab.color + '0d',
                textShadow: `0 0 10px ${tab.color}66`,
                boxShadow: `0 0 8px ${tab.color}10`,
              } : {}}
              onClick={() => setActiveIpTab(tab.key)}
            >
              {tab.label}
              <span className="stat-ip-tab-count">
                {tab.key === 'recent' ? recentEvents.length : (ipMap[tab.key]?.length || 0)}
              </span>
            </button>
          ))}
        </div>

        {/* IP list */}
        {activeIpTab !== 'recent' && (
          <ul className="stat-list">
            {visibleIps.length === 0 && (
              <li><span className="stat-empty">NO DATA</span></li>
            )}
            {visibleIps.map((i) => (
              <li key={i.ip}>
                <span
                  className="stat-name mono ip-clickable"
                  onClick={() => onIpClick?.(i.ip)}
                  title={`View profile for ${i.ip}`}
                >
                  {i.ip}
                </span>
                <span className="stat-count">{formatCount(i.count)}</span>
                <span
                  className="stat-bar-track"
                  style={{
                    width: `${(i.count / maxVisible) * 100}%`,
                    background: activeTabColor,
                  }}
                />
              </li>
            ))}
          </ul>
        )}

        {/* RECENT tab */}
        {activeIpTab === 'recent' && (
          <div className="stat-recent-list">
            {recentEvents.length === 0 && (
              <span className="stat-empty">NO DATA</span>
            )}
            {recentEvents.map((e, idx) => (
              <div key={e.id || idx} className="stat-recent-row">
                <span className="stat-recent-time">{formatTime(e.timestamp)}</span>
                <span
                  className="stat-recent-ip ip-clickable"
                  onClick={() => onIpClick?.(e.ip)}
                  title={`View profile for ${e.ip}`}
                >
                  {e.ip}
                </span>
                <span
                  className="stat-recent-type"
                  style={{
                    color: e.source === 'ssh' ? '#ff2020'
                         : e.event_type?.startsWith('visit_') ? '#1e90ff'
                         : '#ffd700',
                  }}
                >
                  {e.source === 'ssh' ? 'SSH' : e.event_type?.startsWith('visit_') ? 'VISIT' : 'HTTP'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── SSH Targets ── */}
      <div className="stat-card stat-card--ssh">
        <div className="stat-card-header" style={{ color: '#ff0040' }}>
          SSH TARGETS
          <span className="stat-card-count">{sshUsers.length}</span>
        </div>
        <div className="stat-tag-cloud">
          {sshUsers.length === 0 && (
            <span className="stat-empty">NO DATA</span>
          )}
          {sshUsers.map((u) => (
            <span
              key={u.username}
              className="stat-tag stat-tag--ssh"
              title={`${u.count} attempts`}
            >
              {u.username}
              <span className="stat-tag-count">{u.count}</span>
            </span>
          ))}
        </div>
      </div>

      {/* ── HTTP Routes Probed ── */}
      <div className="stat-card stat-card--http">
        <div className="stat-card-header" style={{ color: '#ffd700' }}>
          HTTP ROUTES
          <span className="stat-card-count">{allRoutes.length}</span>
        </div>

        <div className="stat-http-tabs">
          <button
            className={`stat-http-tab${activeHttpTab === 'bots' ? ' active active--bot' : ''}`}
            onClick={() => setActiveHttpTab('bots')}
          >
            BOTS
            <span className="stat-ip-tab-count">{botRoutes.length}</span>
          </button>
          <button
            className={`stat-http-tab${activeHttpTab === 'real' ? ' active active--real' : ''}`}
            onClick={() => setActiveHttpTab('real')}
          >
            REAL
            <span className="stat-ip-tab-count">{realRoutes.length}</span>
          </button>
        </div>

        {activeHttpTab === 'bots' && (
          <div className="stat-routes-list">
            {botRoutes.length === 0 && <span className="stat-empty">NO BOT PROBES</span>}
            {botRoutes.map((r) => (
              <div key={r.path} className="stat-route-item stat-route-item--bot">
                <span className="stat-route-path">{r.path}</span>
                {r.status > 0 && <StatusBadge status={r.status} />}
                <span className="stat-route-count">{r.count}</span>
              </div>
            ))}
          </div>
        )}

        {activeHttpTab === 'real' && (
          <div className="stat-routes-list">
            {realRoutes.length === 0 && <span className="stat-empty">NO REAL TRAFFIC</span>}
            {realRoutes.map((r) => (
              <div key={r.path} className="stat-route-item stat-route-item--real">
                <span className="stat-route-path stat-route-path--real">{r.path}</span>
                {r.status > 0 && <StatusBadge status={r.status} />}
                <span className="stat-route-count">{r.count}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
