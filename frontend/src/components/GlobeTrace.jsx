import React, { useEffect, useState } from 'react'
import { geoDistance } from 'd3-geo'
import { PATTERNS } from '../lib/severity'

/**
 * "Trace lock" read-out docked on the right of the globe: replaces the hover
 * tooltip. The globe draws the brackets on the tower and the leader line that
 * ends on this panel; here we only print what is known about the origin.
 *
 * The basics come from the scene (no request). Pattern, score and TTPs are
 * fetched from GET /api/attacker/{ip} once the pointer rests on a tower.
 */

const EARTH_KM = 6371
const RAD = Math.PI / 180
const COMPASS = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW']
const GLYPHS = '0123456789ABCDEF.:'
const PROFILE_TTL = 60000
const REDUCE_MOTION = typeof window !== 'undefined'
  && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

const profiles = new Map()   // ip -> {at, data}; data is null when the API has nothing

function cached(ip) {
  const hit = profiles.get(ip)
  return hit && Date.now() - hit.at < PROFILE_TTL ? hit : null
}

/** undefined while loading, null when there is no profile, else the profile. */
function useProfile(ip) {
  const [state, setState] = useState({ ip: '', data: null })
  useEffect(() => {
    if (!ip) return undefined
    const hit = cached(ip)
    if (hit) { setState({ ip, data: hit.data }); return undefined }
    let active = true
    // Wait a moment: sweeping the pointer across the globe must not fire requests
    const timer = setTimeout(async () => {
      let data = null
      try {
        const res = await fetch(`/api/attacker/${encodeURIComponent(ip)}`)
        if (res.ok) data = await res.json()
      } catch {
        // no profile: the panel still shows what the scene knows
      }
      if (profiles.size > 200) profiles.clear()
      profiles.set(ip, { at: Date.now(), data })
      if (active) setState({ ip, data })
    }, 250)
    return () => { active = false; clearTimeout(timer) }
  }, [ip])
  if (!ip) return null
  return state.ip === ip ? state.data : undefined
}

/** Text that resolves left to right out of random glyphs. */
function useDecode(text) {
  const [shown, setShown] = useState(text)
  useEffect(() => {
    if (REDUCE_MOTION || !text) { setShown(text); return undefined }
    let frame = 0
    const total = 12
    const id = setInterval(() => {
      frame += 1
      const solved = Math.floor((frame / total) * text.length)
      setShown(
        text.slice(0, solved)
        + [...text.slice(solved)].map((c) => (c === '.' || c === ':'
          ? c : GLYPHS[Math.floor(Math.random() * 16)])).join(''),
      )
      if (frame >= total) { clearInterval(id); setShown(text) }
    }, 28)
    return () => clearInterval(id)
  }, [text])
  return shown
}

function flag(code) {
  if (!code || code.length !== 2 || code === 'XX') return ''
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)))
}

function bearingDeg(from, to) {
  const p1 = from[1] * RAD
  const p2 = to[1] * RAD
  const dl = (to[0] - from[0]) * RAD
  const b = Math.atan2(
    Math.sin(dl) * Math.cos(p2),
    Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl),
  ) / RAD
  return (b + 360) % 360
}

function scoreColor(score) {
  if (score >= 70) return 'var(--red)'
  if (score >= 40) return 'var(--amber)'
  return 'var(--green)'
}

function Row({ label, children }) {
  return (
    <div className="trace-row">
      <span className="trace-key">{label}</span>
      <span className="trace-val">{children}</span>
    </div>
  )
}

function Body({ origin, color, label, vps }) {
  const hostile = origin.kind !== 'visit'
  const profile = useProfile(hostile ? origin.ip : '')
  const title = useDecode(origin.ip || label.toUpperCase())
  const [, tick] = useState(0)
  // The scene mutates `origin` in place (count, last): re-read it on a timer
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 500)
    return () => clearInterval(id)
  }, [])

  const here = [origin.lon, origin.lat]
  const km = vps ? Math.round(geoDistance(here, vps) * EARTH_KM) : null
  const deg = vps ? Math.round(bearingDeg(vps, here)) : null
  const live = performance.now() - origin.last < 20000
  const place = [origin.city && origin.city !== 'Unknown' ? origin.city : null, origin.country || origin.cc]
    .filter(Boolean).join(', ')
  const pattern = profile?.attack_pattern
  const patternMeta = PATTERNS[pattern]
  const score = profile?.threat_score
  const org = profile?.geo?.org || profile?.geo?.asn

  return (
    <>
      <div className="trace-head">
        <span className="trace-lock">TRACE LOCK</span>
        <span className="trace-kind">{label.toUpperCase()}</span>
      </div>

      <div className="trace-ip">{title}</div>
      <div className="trace-place">{flag(origin.cc)} {place || 'Unknown location'}</div>
      {org && <div className="trace-org">{org}</div>}

      <div className="trace-rule" />

      <Row label="SIGNAL">
        <span className={live ? 'trace-live' : 'trace-quiet'}>{live ? '● TRANSMITTING' : '○ QUIET'}</span>
      </Row>
      <Row label="EVENTS">{origin.count.toLocaleString()}</Row>
      {km != null && (
        <Row label="RANGE">
          {km.toLocaleString()} km · {String(deg).padStart(3, '0')}° {COMPASS[Math.round(deg / 45) % 8]}
        </Row>
      )}

      {hostile && origin.ip && (
        <>
          <div className="trace-rule" />
          {profile === undefined && <div className="trace-wait">ANALYSING</div>}
          {profile === null && <div className="trace-none">NO PROFILE ON RECORD</div>}
          {profile && (
            <>
              {pattern && (
                <Row label="PATTERN">
                  <span style={{ color: patternMeta?.color }}>{patternMeta?.short || pattern}</span>
                </Row>
              )}
              {profile.unique_usernames > 0 && (
                <Row label="ACCOUNTS">{profile.unique_usernames.toLocaleString()} tried</Row>
              )}
              {typeof score === 'number' && (
                <div className="trace-score" style={{ '--score': scoreColor(score) }}>
                  <span className="trace-key">THREAT</span>
                  <span className="trace-bar" aria-hidden="true">
                    {Array.from({ length: 10 }, (_, i) => (
                      <i key={i} className={i < Math.round(score / 10) ? 'on' : ''} />
                    ))}
                  </span>
                  <span className="trace-score-num">{score}</span>
                </div>
              )}
              {profile.mitre_ttps?.length > 0 && (
                <div className="trace-ttps">
                  {profile.mitre_ttps.slice(0, 4).map((ttp) => <span key={ttp}>{ttp}</span>)}
                </div>
              )}
            </>
          )}
        </>
      )}

      {origin.ip && <div className="trace-foot">CLICK TOWER → FULL DOSSIER</div>}
    </>
  )
}

export default function GlobeTrace({ origin, color, label, vps, panelRef }) {
  return (
    <div
      ref={panelRef}
      className={`globe-trace${origin ? ' is-on' : ''}`}
      style={{ '--trace': color || 'var(--green)' }}
      aria-live="polite"
    >
      {origin && (
        <div className="trace-inner" key={`${origin.ip}|${origin.kind}|${origin.lat},${origin.lon}`}>
          <Body origin={origin} color={color} label={label} vps={vps} />
        </div>
      )}
    </div>
  )
}
