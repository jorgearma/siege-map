import React, { useEffect, useState } from 'react'
import useApi from '../hooks/useApi'

/**
 * Corner read-outs laid over the globe: the sphere leaves the four corners of
 * its panel empty. Data comes from GET /api/stats/hud; the clocks tick locally.
 */

const RAD = Math.PI / 180

/** Sun altitude in degrees at (lat, lon): low-precision almanac formula, fine to ~1°. */
function sunAltitude(date, lat, lon) {
  const d = date.getTime() / 86400000 - 10957.5          // days since J2000.0
  const g = (357.529 + 0.98560028 * d) * RAD
  const L = (280.459 + 0.98564736 * d + 1.915 * Math.sin(g) + 0.02 * Math.sin(2 * g)) * RAD
  const e = (23.439 - 0.00000036 * d) * RAD
  const decl = Math.asin(Math.sin(e) * Math.sin(L))
  const ra = Math.atan2(Math.cos(e) * Math.sin(L), Math.cos(L))
  const gmst = (18.697374558 + 24.06570982441908 * d) * 15   // degrees
  const ha = (gmst + lon) * RAD - ra
  return Math.asin(
    Math.sin(lat * RAD) * Math.sin(decl) + Math.cos(lat * RAD) * Math.cos(decl) * Math.cos(ha)
  ) / RAD
}

function phaseOf(alt) {
  if (alt > -0.833) return { key: 'day', label: 'DAY', icon: '☀' }
  if (alt > -6) return { key: 'twilight', label: 'TWILIGHT', icon: '◐' }
  return { key: 'night', label: 'NIGHT', icon: '☾' }
}

const pad = (n) => String(n).padStart(2, '0')

function clock(ms) {
  const d = new Date(ms)
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
}

function duration(total) {
  const d = Math.floor(total / 86400)
  const h = Math.floor((total % 86400) / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  return `${d ? `${d}d ` : ''}${pad(h)}:${pad(m)}:${pad(s)}`
}

function offsetLabel(min) {
  const sign = min < 0 ? '-' : '+'
  const abs = Math.abs(min)
  return `UTC${sign}${pad(Math.floor(abs / 60))}${abs % 60 ? `:${pad(abs % 60)}` : ''}`
}

function flag(code) {
  if (!code || code.length !== 2 || code === 'XX') return ''
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)))
}

function Block({ corner, title, children }) {
  return (
    <div className={`hud-block hud-block--${corner}`}>
      <div className="hud-title">{title}</div>
      {children}
    </div>
  )
}

function Row({ label, children }) {
  return (
    <div className="hud-row">
      <span className="hud-key">{label}</span>
      <span className="hud-val">{children}</span>
    </div>
  )
}

function IpLink({ ip, onIpClick }) {
  return (
    <button className="hud-ip" onClick={() => onIpClick?.(ip)} title="Open attacker profile">
      {ip}
    </button>
  )
}

export default function GlobeHud({ config, onIpClick, showRecords = true }) {
  const hud = useApi('/api/stats/hud', 15000)
  const [now, setNow] = useState(() => Date.now())
  const [fetchedAt, setFetchedAt] = useState(() => Date.now())

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])
  useEffect(() => { if (hud) setFetchedAt(Date.now()) }, [hud])

  const uptime = hud ? hud.uptime_seconds + Math.max(0, Math.round((now - fetchedAt) / 1000)) : null
  const phase = config ? phaseOf(sunAltitude(new Date(now), config.vps_lat, config.vps_lon)) : null
  const rec = hud?.records

  return (
    <div className="globe-hud" aria-label="Sensor status">
      <Block corner="tl" title="SENSOR">
        <Row label="UPTIME">{uptime == null ? '--:--:--' : duration(uptime)}</Row>
        <Row label="EVENTS TODAY">{hud ? hud.today.events.toLocaleString() : '—'}</Row>
        <Row label="UNIQUE IPS">{hud ? hud.today.unique_ips.toLocaleString() : '—'}</Row>
      </Block>

      <Block corner="tr" title={config?.vps_label || 'VPS'}>
        <Row label={hud ? offsetLabel(hud.utc_offset_min) : 'LOCAL'}>
          {hud ? clock(now + hud.utc_offset_min * 60000) : '--:--:--'}
        </Row>
        <Row label="UTC">{clock(now)}</Row>
        {phase && (
          <Row label="SKY">
            <span className={`hud-phase hud-phase--${phase.key}`}>{phase.icon} {phase.label}</span>
          </Row>
        )}
      </Block>

      {showRecords && rec && (rec.farthest || rec.top_ip || rec.busiest_minute) && (
        <Block corner="bl" title="TODAY'S RECORDS">
          {rec.farthest && (
            <Row label="FARTHEST">
              {flag(rec.farthest.country_code)}{' '}
              {rec.farthest.city && rec.farthest.city !== 'Unknown' ? rec.farthest.city : rec.farthest.country}
              {' · '}{rec.farthest.km.toLocaleString()} km
            </Row>
          )}
          {rec.top_ip && (
            <Row label="MOST ACTIVE">
              {flag(rec.top_ip.country_code)} <IpLink ip={rec.top_ip.ip} onIpClick={onIpClick} />
              {' · '}{rec.top_ip.count.toLocaleString()}
            </Row>
          )}
          {rec.busiest_minute && (
            <Row label="PEAK MINUTE">
              {rec.busiest_minute.minute} · {rec.busiest_minute.count.toLocaleString()} ev
            </Row>
          )}
        </Block>
      )}
    </div>
  )
}
