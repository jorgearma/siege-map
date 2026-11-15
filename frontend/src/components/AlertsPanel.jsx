import React, { useEffect, useRef, useState } from 'react'
import { SEVERITIES, SEVERITY_COLOR, ago } from '../lib/severity'

const RULE_LABEL = {
  login_success: 'LOGIN ACCEPTED',
  exploit_2xx: 'EXPLOIT 2XX',
  high_score: 'HIGH SCORE',
  campaign: 'CAMPAIGN',
  burst: 'BURST',
  country_surge: 'COUNTRY SURGE',
  user_spray: 'USER SPRAY',
}

function SeverityTag({ severity }) {
  const color = SEVERITY_COLOR[severity]
  return <span className="alert-sev" style={{ color, borderColor: color }}>{severity}</span>
}

function AlertRow({ alert, onIpClick }) {
  const active = alert.status === 'active'
  const clickable = Boolean(alert.ip)
  return (
    <li
      className={`alert-row${active ? ' alert-row--active' : ''}${clickable ? ' alert-row--link' : ''}`}
      style={{ borderLeftColor: SEVERITY_COLOR[alert.severity] }}
      onClick={clickable ? () => onIpClick?.(alert.ip) : undefined}
      title={clickable ? 'Open the dossier of this address' : undefined}
    >
      <div className="alert-row-head">
        <SeverityTag severity={alert.severity} />
        <span className="alert-rule">{RULE_LABEL[alert.rule] || alert.rule}</span>
        <span className="alert-time">
          {active ? <span className="alert-live">● ACTIVE</span> : 'resolved'} · {ago(alert.ts)}
          {alert.hits > 1 ? ` · ×${alert.hits}` : ''}
        </span>
      </div>
      <div className="alert-title">{alert.title}</div>
      {alert.detail && <div className="alert-detail">{alert.detail}</div>}
    </li>
  )
}

/** Sidebar card: what needs attention now, then the recent history. */
export default function AlertsPanel({ alerts, onIpClick }) {
  const [filter, setFilter] = useState('ALL')
  if (!alerts.enabled) return null
  const shown = alerts.all.filter((a) => filter === 'ALL' || a.severity === filter)
  const active = shown.filter((a) => a.status === 'active')
  const past = shown.filter((a) => a.status !== 'active').slice(0, 12)
  const count = (sev) => alerts.all.filter((a) => a.severity === sev).length

  return (
    <div className="stat-card alerts-card">
      <div className="stat-card-header">
        ALERTS
        <span className="stat-card-count">{alerts.active.length} ACTIVE · {alerts.today.total || 0} TODAY</span>
      </div>
      <div className="alert-filters" role="group" aria-label="Filter by severity">
        <button className={filter === 'ALL' ? 'active' : ''} onClick={() => setFilter('ALL')}>ALL</button>
        {SEVERITIES.map((s) => (
          <button
            key={s} className={filter === s ? 'active' : ''} onClick={() => setFilter(s)}
            style={filter === s ? { color: SEVERITY_COLOR[s], borderColor: SEVERITY_COLOR[s] } : undefined}
          >
            {s} {count(s) || ''}
          </button>
        ))}
      </div>
      {!alerts.loaded && <div className="alert-empty">LOADING…</div>}
      {alerts.loaded && !shown.length && (
        <div className="alert-empty">
          NO ALERTS{filter !== 'ALL' ? ` AT ${filter}` : ''} — nothing above this sensor&apos;s baseline
        </div>
      )}
      <ul className="alert-list">
        {active.map((a) => <AlertRow key={a.id} alert={a} onIpClick={onIpClick} />)}
        {past.map((a) => <AlertRow key={a.id} alert={a} onIpClick={onIpClick} />)}
      </ul>
    </div>
  )
}

/** Small header chip: how many HIGH/CRITICAL alerts are active, coloured by the worst one. */
export function AlertChip({ alerts }) {
  const serious = alerts.active.filter((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH')
  if (!serious.length) return null
  const top = serious.find((a) => a.severity === 'CRITICAL') || serious[0]
  const color = SEVERITY_COLOR[top.severity]
  return (
    <span
      className="alert-chip" role="status" style={{ color, borderColor: color }}
      title={serious.map((a) => `[${a.severity}] ${a.title}`).join('\n')}
    >
      ▲ {serious.length} {serious.length === 1 ? 'ALERT' : 'ALERTS'}
    </span>
  )
}

/** Brief pop-up for each alert announced over the WebSocket. */
export function AlertToasts({ live, onIpClick }) {
  const [toasts, setToasts] = useState([])
  const seen = useRef(new Set())

  useEffect(() => {
    const fresh = live.filter((a) => !seen.current.has(a.id))
    if (!fresh.length) return
    fresh.forEach((a) => seen.current.add(a.id))
    setToasts((t) => [...fresh, ...t].slice(0, 3))
    const ids = new Set(fresh.map((a) => a.id))
    const timer = setTimeout(() => setToasts((t) => t.filter((a) => !ids.has(a.id))), 9000)
    return () => clearTimeout(timer)
  }, [live])

  if (!toasts.length) return null
  return (
    <div className="alert-toasts" aria-live="polite">
      {toasts.map((a) => (
        <div
          key={a.id} className="alert-toast" style={{ borderColor: SEVERITY_COLOR[a.severity] }}
          onClick={() => { if (a.ip) onIpClick?.(a.ip); setToasts((t) => t.filter((x) => x.id !== a.id)) }}
        >
          <SeverityTag severity={a.severity} />
          <span className="alert-toast-title">{a.title}</span>
        </div>
      ))}
    </div>
  )
}
