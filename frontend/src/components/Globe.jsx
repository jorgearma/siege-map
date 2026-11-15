import React, { useEffect, useRef, useState } from 'react'
import { geoOrthographic, geoPath, geoGraticule10, geoInterpolate, geoDistance } from 'd3-geo'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'
import GlobeHud from './GlobeHud'
import GlobeTrace from './GlobeTrace'

/**
 * Wireframe globe drawn on a 2D canvas (d3-geo orthographic projection).
 * No WebGL and no external tiles: the country shapes ship inside the bundle,
 * so it works under a strict CSP and on phones.
 *
 * Drag to rotate, wheel / pinch to zoom, click a tower to open its dossier.
 * Hovering a tower locks onto it: brackets and a leader line drawn here, and
 * the read-out itself in GlobeTrace, docked on the right.
 */

const LAND = feature(world, world.objects.countries)
const GRATICULE = geoGraticule10()

const SSH_COLOR = '#ff2020'
const HTTP_COLOR = '#ffd700'
const VISITOR_COLOR = '#1e90ff'

const ARC_MS = 1500
const ARC_STEPS = 36
const ARC_LIFT = 0.28
const ARC_TAIL = 0.45
const MAX_ARCS = 120
const HALF_PI = Math.PI / 2
const TAU = Math.PI * 2
const RAD = Math.PI / 180

// Shield dome over the VPS (radians of arc on the ground, height in globe radii)
const DOME_R = 0.065
const DOME_H = 0.045
const DOME_HIT = 0.7            // hostile arcs die at this fraction of DOME_R
const DOME_SEGS = 40
const DOME_RINGS = [0, 0.6, 1.1] // elevation of each ring, radians
const IMPACT_MS = 1100
const MAX_IMPACTS = 16
const HEAT_PER_HIT = 0.07
const HEAT_TAU = 5000           // ms for the target to cool down
const COOL_TAU = 25000          // ms for an origin to fade to an ember
const CHARGE_MS = 180           // pulse climbing the tower before it fires

// Origins are signal towers: height (in globe radii) grows with their events
const TARGET_H = 0.24           // the VPS tower stands a little above any origin
const towerHeight = (count) => Math.min(0.18, 0.025 + Math.log2(1 + count) * 0.016)

const REDUCE_MOTION = typeof window !== 'undefined'
  && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

function kindOf(e) {
  if (e.source === 'ssh') return 'ssh'
  if (e.event_type?.startsWith('visit_')) return 'visit'
  return 'http'
}
const COLORS = { ssh: SSH_COLOR, http: HTTP_COLOR, visit: VISITOR_COLOR }
const LABELS = { ssh: 'SSH', http: 'HTTP probe', visit: 'Visit' }

// ── Spherical helpers ([lon, lat] in degrees, angles in radians) ──
function bearing(a, b) {
  const p1 = a[1] * RAD
  const p2 = b[1] * RAD
  const dl = (b[0] - a[0]) * RAD
  return Math.atan2(
    Math.sin(dl) * Math.cos(p2),
    Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl),
  )
}
function destination(c, theta, delta) {
  const p1 = c[1] * RAD
  const sinP2 = Math.sin(p1) * Math.cos(delta) + Math.cos(p1) * Math.sin(delta) * Math.cos(theta)
  const l2 = c[0] * RAD + Math.atan2(
    Math.sin(theta) * Math.sin(delta) * Math.cos(p1),
    Math.cos(delta) - Math.sin(p1) * sinP2,
  )
  return [l2 / RAD, Math.asin(Math.max(-1, Math.min(1, sinP2))) / RAD]
}

const easeOutCubic = (x) => 1 - (1 - x) ** 3
const easeOutBack = (x) => 1 + 2.70158 * (x - 1) ** 3 + 1.70158 * (x - 1) ** 2

// Target colour by pressure: green → amber → red
function heatRgb(h) {
  const stops = [[0, 255, 65], [255, 190, 0], [255, 40, 40]]
  const x = Math.max(0, Math.min(1, h)) * 2
  const i = Math.min(1, Math.floor(x))
  const f = x - i
  return stops[i].map((v, n) => Math.round(v + (stops[i + 1][n] - v) * f))
}

// Pre-rendered radial glows: far cheaper than shadowBlur on every mark
const sprites = new Map()
function glowSprite(color) {
  let c = sprites.get(color)
  if (!c) {
    c = document.createElement('canvas')
    c.width = c.height = 64
    const g = c.getContext('2d')
    const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32)
    grad.addColorStop(0, `${color}ff`)
    grad.addColorStop(0.25, `${color}77`)
    grad.addColorStop(1, `${color}00`)
    g.fillStyle = grad
    g.fillRect(0, 0, 64, 64)
    sprites.set(color, c)
  }
  return c
}

// Height of an arc at progress v (0..1 along its own, possibly shortened, path)
function arcLift(arc, v) {
  // h0: the arc leaves from the tip of its tower, not from the ground
  return 1 + ARC_LIFT * Math.sin(Math.PI * v * arc.uEnd) + arc.corr * v ** 4 + arc.h0 * (1 - v) ** 4
}

export default function Globe({ events, initialIds, config, onIpClick, paused = false, replaying = false }) {
  const wrapRef = useRef(null)
  const canvasRef = useRef(null)
  const traceRef = useRef(null)
  const [hover, setHover] = useState(null)   // the origin under the pointer

  // Mutable scene state: read by the draw loop, never triggers a re-render
  const scene = useRef({
    rotation: [10, -25, 0],
    zoom: 1,
    dragging: false,
    lastInteraction: 0,
    origins: new Map(),   // key -> {lat, lon, kind, count, ip, cc, born, last, fired}
    arcs: [],             // {interp, color, start, h0, uEnd, corr, blocked, bearing, hit}
    impacts: [],          // {start, color, blocked, lonlat, lift, bearing, sparks}
    hits: [],             // timestamps of blocked hits in the last minute
    heat: 0,              // 0..1 pressure on the target
    kick: 0,              // reticle spring (displacement / velocity)
    kickVel: 0,
    shieldFlash: 0,
    spin: 0,
    seen: new Set(),
    screen: [],           // [{x, y, origin}] of visible points (hit testing)
    hover: null,          // origin under the pointer (same object as in `origins`)
    hoverSince: 0,
    hoverMark: null,      // where it is on screen this frame, if visible
    vps: null,
  })

  // ── VPS position: start centred between it and the Atlantic ──
  useEffect(() => {
    if (!config) return
    const s = scene.current
    s.vps = [config.vps_lon, config.vps_lat]
    s.rotation = [-config.vps_lon + 20, -Math.max(-40, Math.min(40, config.vps_lat - 15)), 0]
  }, [config])

  // ── Feed events into the scene ──
  useEffect(() => {
    const s = scene.current
    const now = performance.now()
    // oldest first so `born` order matches arrival
    for (let i = events.length - 1; i >= 0; i--) {
      const e = events[i]
      if (!e.geo || (!e.geo.lat && !e.geo.lon) || s.seen.has(e.id)) continue
      s.seen.add(e.id)
      const kind = kindOf(e)
      const live = !initialIds?.has(e.id)
      const key = e.ip ? `${e.ip}|${kind}` : `${e.geo.lat},${e.geo.lon}|${kind}`
      let o = s.origins.get(key)
      if (o) {
        o.count += e.count || 1
        if (live) o.last = now
      } else {
        o = {
          lat: e.geo.lat, lon: e.geo.lon, kind, ip: e.ip || '', count: e.count || 1,
          cc: e.geo.country_code, country: e.geo.country, city: e.geo.city,
          // The backlog fades in staggered and already cooled down
          born: live || REDUCE_MOTION ? now : now + Math.random() * 900,
          last: live ? now : now - COOL_TAU * 1.5,
          fired: 0,
        }
        s.origins.set(key, o)
      }
      // Animate only what arrives live, not the backlog sent on connect
      if (s.vps && live && s.arcs.length < MAX_ARCS) {
        const from = [e.geo.lon, e.geo.lat]
        const dist = geoDistance(from, s.vps)
        // Attacks die on the shield; legitimate visits go through to the target
        const blocked = kind !== 'visit' && dist > DOME_R
        const uEnd = blocked ? 1 - (DOME_R * DOME_HIT) / dist : 1
        const domeLift = 1 + DOME_H * Math.sqrt(1 - DOME_HIT * DOME_HIT)
        const start = now + Math.random() * 250
        o.fired = start
        s.arcs.push({
          interp: geoInterpolate(from, s.vps),
          color: COLORS[kind],
          start: start + (REDUCE_MOTION ? 0 : CHARGE_MS),
          h0: towerHeight(o.count),
          uEnd,
          // bends the last stretch so the head lands exactly on the dome
          corr: blocked ? domeLift - 1 - ARC_LIFT * Math.sin(Math.PI * uEnd) : 0,
          blocked,
          bearing: bearing(s.vps, from),
          hit: false,
        })
      }
    }
    if (s.seen.size > 4000) s.seen = new Set(events.map((e) => e.id))
    // Keep the scene bounded: drop the points that have been quiet longest
    if (s.origins.size > 600) {
      const sorted = [...s.origins.entries()].sort((a, b) => a[1].last - b[1].last)
      sorted.slice(0, s.origins.size - 600).forEach(([k]) => s.origins.delete(k))
    }
  }, [events, initialIds])

  // ── Draw loop ──
  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    const ctx = canvas.getContext('2d')
    const s = scene.current
    const reduceMotion = REDUCE_MOTION
    let width = 0
    let height = 0
    let raf = 0
    let last = performance.now()
    let cx = 0
    let cy = 0
    let centre = [0, 0]

    const projection = geoOrthographic().clipAngle(90)
    // Same view without horizon clipping: arcs are lifted off the surface
    // and stay visible slightly behind the edge
    const unclipped = geoOrthographic().clipAngle(null)
    const path = geoPath(projection, ctx)

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      width = wrap.clientWidth
      height = wrap.clientHeight
      canvas.width = Math.max(1, Math.round(width * dpr))
      canvas.height = Math.max(1, Math.round(height * dpr))
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    const observer = new ResizeObserver(resize)
    observer.observe(wrap)
    resize()

    function visible(lonlat) {
      return geoDistance(lonlat, centre) < HALF_PI - 0.02
    }

    // Screen position of a point floating `lift` globe radii from the centre.
    // Lifted points stay visible a little past the horizon.
    function lifted(lonlat, lift) {
      const limit = Math.acos(Math.min(1, 1 / lift)) + HALF_PI - 0.02
      if (geoDistance(lonlat, centre) > limit) return null
      const flat = unclipped(lonlat)
      if (!flat) return null
      return [cx + (flat[0] - cx) * lift, cy + (flat[1] - cy) * lift]
    }

    function glow(color, x, y, r, alpha) {
      if (alpha <= 0.004 || r <= 0) return
      ctx.globalAlpha = Math.min(1, alpha)
      ctx.drawImage(glowSprite(color), x - r, y - r, r * 2, r * 2)
    }

    // Circle of angular radius `delta` around the VPS, following the sphere
    function ringPoints(delta, lift, segs) {
      const pts = []
      for (let i = 0; i <= segs; i++) {
        pts.push(lifted(destination(s.vps, (i / segs) * TAU, delta), lift))
      }
      return pts
    }
    function strokePoints(pts) {
      ctx.beginPath()
      let pen = false
      for (const pt of pts) {
        if (!pt) { pen = false; continue }
        if (pen) ctx.lineTo(pt[0], pt[1])
        else ctx.moveTo(pt[0], pt[1])
        pen = true
      }
      ctx.stroke()
    }

    function registerHit(arc, now) {
      s.impacts.push({
        start: now,
        color: arc.color,
        blocked: arc.blocked,
        lonlat: arc.interp(arc.uEnd),
        lift: arcLift(arc, 1),
        bearing: arc.bearing,
        sparks: reduceMotion ? [] : Array.from({ length: arc.blocked ? 9 : 6 }, () => ({
          a: (Math.random() - 0.5) * (arc.blocked ? 2.2 : TAU),
          v: 14 + Math.random() * 26,
          life: 380 + Math.random() * 420,
        })),
      })
      if (s.impacts.length > MAX_IMPACTS) s.impacts.splice(0, s.impacts.length - MAX_IMPACTS)
      if (arc.blocked) {
        s.heat = Math.min(1, s.heat + HEAT_PER_HIT)
        s.shieldFlash = Math.min(1, s.shieldFlash + 0.5)
        s.kickVel = Math.max(-9, s.kickVel - 3.2)
        s.hits.push(now)
        if (s.hits.length > 3000) s.hits.shift()
      } else {
        s.kickVel = Math.max(-9, s.kickVel - 1.2)
      }
    }

    // Origins: a thin tower rising from the surface. Height is volume, the lit
    // tip is recency. Seen from above a tower collapses into its tip, so the
    // tip always carries the colour and the click target.
    function drawOrigins(now) {
      s.screen = []
      s.hoverMark = null
      const marks = []
      for (const o of s.origins.values()) {
        const age = now - o.born
        if (age < 0) continue
        const lonlat = [o.lon, o.lat]
        const d = geoDistance(lonlat, centre)
        let top = 1 + towerHeight(o.count)
        if (!reduceMotion && age < 600) top = 1 + (top - 1) * Math.max(0.05, easeOutBack(age / 600))
        // Behind the horizon only the part that clears the limb is drawn
        const grounded = d < HALF_PI - 0.02
        let bottom = 1
        if (!grounded) {
          if (d > HALF_PI + 1) continue
          bottom = 1 / Math.cos(d - HALF_PI + 0.02)
          if (bottom >= top) continue
        }
        const flat = unclipped(lonlat)
        if (!flat) continue
        const dx = flat[0] - cx
        const dy = flat[1] - cy
        const m = {
          o, age, grounded, top, bottom, dx, dy,
          bx: cx + dx * bottom, by: cy + dy * bottom,
          tx: cx + dx * top, ty: cy + dy * top,
          tip: Math.min(2.6, 1.3 + Math.log2(1 + o.count) * 0.2),
          heat: Math.exp(-(now - o.last) / COOL_TAU),
        }
        marks.push(m)
        if (o === s.hover) s.hoverMark = m
        s.screen.push({ x: m.tx, y: m.ty, r: m.tip + 1, origin: o })
        if (grounded) s.screen.push({ x: m.bx, y: m.by, r: 1.5, origin: o })
      }

      // Glow pass: additive, so busy regions melt into one hot blob
      ctx.globalCompositeOperation = 'lighter'
      for (const m of marks) {
        const pulse = reduceMotion ? 0.5 : (Math.sin((now - m.o.born) / 420) + 1) / 2
        const color = COLORS[m.o.kind]
        glow(color, m.tx, m.ty, m.tip * 2.4 + 3 + m.heat * (5 + pulse * 4), 0.12 + m.heat * 0.55)
        if (m.grounded) glow(color, m.bx, m.by, 5, 0.1 + m.heat * 0.15)
        if (reduceMotion) continue
        if (m.age < 450) glow('#ffffff', m.tx, m.ty, 9, 0.8 * (1 - m.age / 450))
        const f = now - m.o.fired - CHARGE_MS
        if (f >= 0 && f < 400) glow('#ffffff', m.tx, m.ty, 11, 0.9 * (1 - f / 400))
      }
      ctx.globalCompositeOperation = 'source-over'

      ctx.lineCap = 'butt'
      for (const m of marks) {
        const color = COLORS[m.o.kind]
        // Stem: faint at the foot, solid at the tip
        if (Math.hypot(m.tx - m.bx, m.ty - m.by) > 0.5) {
          const grad = ctx.createLinearGradient(m.bx, m.by, m.tx, m.ty)
          grad.addColorStop(0, `${color}22`)
          grad.addColorStop(1, color)
          ctx.globalAlpha = 0.35 + 0.65 * m.heat
          ctx.strokeStyle = grad
          ctx.lineWidth = 1.2
          ctx.beginPath()
          ctx.moveTo(m.bx, m.by)
          ctx.lineTo(m.tx, m.ty)
          ctx.stroke()
        }
        // Foot
        if (m.grounded) {
          ctx.globalAlpha = 0.35 + 0.4 * m.heat
          ctx.fillStyle = color
          ctx.beginPath()
          ctx.arc(m.bx, m.by, 1, 0, TAU)
          ctx.fill()
        }
        // Tip: white-hot while it is actively firing
        ctx.globalAlpha = 0.5 + 0.5 * m.heat
        ctx.fillStyle = color
        ctx.beginPath()
        ctx.arc(m.tx, m.ty, m.tip, 0, TAU)
        ctx.fill()
        if (m.heat > 0.6) {
          ctx.globalAlpha = (m.heat - 0.6) / 0.4
          ctx.fillStyle = '#ffffff'
          ctx.beginPath()
          ctx.arc(m.tx, m.ty, m.tip * 0.5, 0, TAU)
          ctx.fill()
        }
        if (reduceMotion) continue
        // Birth ping, on the ground
        if (m.grounded && m.age < 750) {
          const k = m.age / 750
          ctx.globalAlpha = (1 - k) * 0.9
          ctx.strokeStyle = color
          ctx.lineWidth = 1.4 - k
          ctx.beginPath()
          ctx.arc(m.bx, m.by, 1 + easeOutCubic(k) * 14, 0, TAU)
          ctx.stroke()
        }
        const f = now - m.o.fired
        if (f >= 0 && f < CHARGE_MS) {
          // Charge: a spark climbs the stem, then the arc leaves from the tip
          const l = Math.max(m.bottom, 1 + (m.top - 1) * (f / CHARGE_MS))
          ctx.globalAlpha = 1
          ctx.fillStyle = '#ffffff'
          ctx.beginPath()
          ctx.arc(cx + m.dx * l, cy + m.dy * l, 1.4, 0, TAU)
          ctx.fill()
        } else if (f >= CHARGE_MS && f < CHARGE_MS + 400) {
          const k = (f - CHARGE_MS) / 400
          ctx.globalAlpha = (1 - k) * 0.9
          ctx.strokeStyle = '#ffffff'
          ctx.lineWidth = 1.1
          ctx.beginPath()
          ctx.arc(m.tx, m.ty, m.tip + 1 + easeOutCubic(k) * 8, 0, TAU)
          ctx.stroke()
        }
      }
      ctx.globalAlpha = 1
    }

    // Arcs: great circle lifted off the surface, with a bright head.
    // Once the head lands, the tail keeps going and is swallowed by the impact.
    function drawArcs(now) {
      const alive = []
      for (const arc of s.arcs) {
        const t = ((now - arc.start) / ARC_MS) * 1.15
        if (t < 0) { alive.push(arc); continue }
        if (t >= 1 && !arc.hit) { arc.hit = true; registerHit(arc, now) }
        const head = Math.min(1, t)
        const tail = Math.max(0, t - ARC_TAIL)
        if (tail >= 1) continue
        alive.push(arc)
        ctx.strokeStyle = arc.color
        ctx.lineWidth = 1.4
        ctx.lineCap = 'round'
        let prev = null
        let headPoint = null
        for (let i = 0; i <= ARC_STEPS; i++) {
          const v = tail + ((head - tail) * i) / ARC_STEPS
          const pt = lifted(arc.interp(v * arc.uEnd), arcLift(arc, v))
          if (!pt) { prev = null; continue }
          if (prev) {
            ctx.globalAlpha = 0.12 + 0.75 * (i / ARC_STEPS)
            ctx.beginPath()
            ctx.moveTo(prev[0], prev[1])
            ctx.lineTo(pt[0], pt[1])
            ctx.stroke()
          }
          prev = pt
          if (i === ARC_STEPS) headPoint = pt
        }
        if (headPoint && t < 1) {
          ctx.globalCompositeOperation = 'lighter'
          glow(arc.color, headPoint[0], headPoint[1], 9, 0.9)
          ctx.globalCompositeOperation = 'source-over'
          ctx.globalAlpha = 1
          ctx.fillStyle = '#ffffff'
          ctx.beginPath()
          ctx.arc(headPoint[0], headPoint[1], 1.8, 0, TAU)
          ctx.fill()
        }
      }
      ctx.globalAlpha = 1
      s.arcs = alive
    }

    // Wireframe dome: idle it barely shows, and lights up where it is struck
    function drawShield(now, rgb) {
      const struck = []
      for (const im of s.impacts) {
        if (!im.blocked) continue
        const k = (now - im.start) / 650
        if (k < 1) struck.push([im.bearing, (1 - k) * (1 - k)])
      }
      const idle = 0.1 + s.shieldFlash * 0.22
      const boostAt = (theta) => {
        // a faint highlight sweeps round the dome so it never looks dead
        let b = reduceMotion ? 0 : 0.22 * Math.max(0, Math.cos(theta - now / 1500)) ** 8
        for (const [hb, w] of struck) {
          let d = Math.abs(theta - hb) % TAU
          if (d > Math.PI) d = TAU - d
          const f = Math.max(0, 1 - d / 1.1)
          b += w * f * f
        }
        return b
      }
      const colour = `rgb(${rgb[0]},${rgb[1]},${rgb[2]})`
      ctx.strokeStyle = colour
      ctx.lineWidth = 1

      DOME_RINGS.forEach((phi, ringIndex) => {
        const pts = ringPoints(DOME_R * Math.cos(phi), 1 + DOME_H * Math.sin(phi), DOME_SEGS)
        if (ringIndex === 0 && pts.every(Boolean)) {
          ctx.globalAlpha = 0.035 + s.shieldFlash * 0.08
          ctx.fillStyle = colour
          ctx.beginPath()
          pts.forEach((pt, i) => (i ? ctx.lineTo(pt[0], pt[1]) : ctx.moveTo(pt[0], pt[1])))
          ctx.fill()
        }
        for (let i = 0; i < DOME_SEGS; i++) {
          const a = pts[i]
          const b = pts[i + 1]
          if (!a || !b) continue
          ctx.globalAlpha = Math.min(1, idle + boostAt(((i + 0.5) / DOME_SEGS) * TAU))
          ctx.beginPath()
          ctx.moveTo(a[0], a[1])
          ctx.lineTo(b[0], b[1])
          ctx.stroke()
        }
      })

      for (let r = 0; r < 8; r++) {
        const theta = (r / 8) * TAU
        const rib = []
        for (let j = 0; j <= 6; j++) {
          const phi = (j / 6) * HALF_PI
          rib.push(lifted(destination(s.vps, theta, DOME_R * Math.cos(phi)), 1 + DOME_H * Math.sin(phi)))
        }
        ctx.globalAlpha = Math.min(1, idle * 0.7 + boostAt(theta))
        strokePoints(rib)
      }
      ctx.globalAlpha = 1
    }

    function drawImpacts(now) {
      s.impacts = s.impacts.filter((im) => now - im.start < IMPACT_MS)
      const vpsFlat = unclipped(s.vps)
      // Under a burst the waves pile up: thin them so the target stays readable
      const crowd = Math.min(1, 3 / s.impacts.length)
      for (const im of s.impacts) {
        const age = now - im.start

        // Shockwave: rings that travel over the ground, bending with the globe
        if (!reduceMotion) {
          const r0 = im.blocked ? DOME_R : 0.008
          const spread = im.blocked ? 0.17 : 0.09
          ctx.strokeStyle = im.color
          for (let j = 0; j < 2; j++) {
            const k = (age - j * 160) / (IMPACT_MS - 160)
            if (k <= 0 || k >= 1) continue
            ctx.globalAlpha = (1 - k) ** 1.5 * 0.85 * crowd
            ctx.lineWidth = 2 - k * 1.4
            strokePoints(ringPoints(r0 + spread * easeOutCubic(k), 1, 48))
          }
        }

        const at = lifted(im.lonlat, im.lift)
        if (!at) continue
        ctx.globalCompositeOperation = 'lighter'
        // Flash where the head landed
        if (age < 320) {
          const k = age / 320
          glow(im.color, at[0], at[1], 12 + 26 * (1 - k), (1 - k) ** 2)
          glow('#ffffff', at[0], at[1], 6 + 10 * (1 - k), (1 - k) ** 2)
        }
        // Sparks: bounce back off the shield, or burst all round on the target
        let baseAngle = 0
        if (vpsFlat) {
          const dx = at[0] - vpsFlat[0]
          const dy = at[1] - vpsFlat[1]
          if (Math.hypot(dx, dy) > 1) baseAngle = Math.atan2(dy, dx)
        }
        ctx.lineWidth = 1.3
        ctx.lineCap = 'round'
        for (const sp of im.sparks) {
          const k = age / sp.life
          if (k >= 1) continue
          const ang = baseAngle + sp.a
          const d = sp.v * easeOutCubic(k)
          const d0 = d - Math.min(d, 5 * (1 - k) + 1)
          ctx.globalAlpha = 1 - k
          ctx.strokeStyle = k < 0.25 ? '#ffffff' : im.color
          ctx.beginPath()
          ctx.moveTo(at[0] + Math.cos(ang) * d0, at[1] + Math.sin(ang) * d0)
          ctx.lineTo(at[0] + Math.cos(ang) * d, at[1] + Math.sin(ang) * d)
          ctx.stroke()
        }
        ctx.globalCompositeOperation = 'source-over'
      }
      ctx.globalAlpha = 1
    }

    // The VPS is a tower too, a bit taller and thicker than any attacker's.
    // It pokes through the dome and stays readable near the horizon.
    function drawTargetTower(now, rgb) {
      const d = geoDistance(s.vps, centre)
      if (d > HALF_PI + 0.7) return
      const top = 1 + TARGET_H
      const bottom = d > HALF_PI ? 1 / Math.cos(d - HALF_PI) : 1
      if (bottom >= top) return
      const flat = unclipped(s.vps)
      if (!flat) return
      const ax = cx + (flat[0] - cx) * bottom
      const ay = cy + (flat[1] - cy) * bottom
      const tx = cx + (flat[0] - cx) * top
      const ty = cy + (flat[1] - cy) * top
      const colour = `rgb(${rgb[0]},${rgb[1]},${rgb[2]})`
      if (Math.hypot(tx - ax, ty - ay) > 0.5) {
        const grad = ctx.createLinearGradient(ax, ay, tx, ty)
        grad.addColorStop(0, `rgba(${rgb[0]},${rgb[1]},${rgb[2]},0.25)`)
        grad.addColorStop(1, colour)
        ctx.strokeStyle = grad
        ctx.lineWidth = 2
        ctx.lineCap = 'butt'
        ctx.beginPath()
        ctx.moveTo(ax, ay)
        ctx.lineTo(tx, ty)
        ctx.stroke()
        // A pulse climbs the stem; faster under pressure
        if (!reduceMotion) {
          const k = (now % 1600) / 1600
          const l = bottom + (top - bottom) * k
          ctx.globalAlpha = 0.9 * (1 - k * 0.5)
          ctx.fillStyle = '#ffffff'
          ctx.beginPath()
          ctx.arc(cx + (flat[0] - cx) * l, cy + (flat[1] - cy) * l, 1.3, 0, TAU)
          ctx.fill()
          ctx.globalAlpha = 1
        }
      }
      // Tip: flares white when the shield takes a hit
      const pulse = reduceMotion ? 0.5 : (Math.sin(now / 380) + 1) / 2
      ctx.shadowColor = colour
      ctx.shadowBlur = 10 + pulse * 6 + s.shieldFlash * 14
      ctx.fillStyle = colour
      ctx.beginPath()
      ctx.arc(tx, ty, 3.2 + s.shieldFlash * 1.5, 0, TAU)
      ctx.fill()
      ctx.shadowBlur = 0
      ctx.fillStyle = '#ffffff'
      ctx.globalAlpha = 0.6 + 0.4 * Math.min(1, s.shieldFlash * 2)
      ctx.beginPath()
      ctx.arc(tx, ty, 1.5, 0, TAU)
      ctx.fill()
      ctx.globalAlpha = 1
    }

    // Layered reticle: recoils on every hit, heats up under a burst
    function drawReticle(now, p, rgb) {
      const colour = `rgb(${rgb[0]},${rgb[1]},${rgb[2]})`
      const sc = Math.max(0.6, Math.min(1.4, 1 + s.kick))
      const [x, y] = p
      ctx.strokeStyle = colour
      ctx.fillStyle = colour
      ctx.lineCap = 'butt'

      // inner ring: three arcs
      ctx.lineWidth = 1.4
      for (let i = 0; i < 3; i++) {
        const a = s.spin + (i * TAU) / 3
        ctx.beginPath()
        ctx.arc(x, y, 7 * sc, a, a + 1.4)
        ctx.stroke()
      }
      // outer ring: four short arcs, turning the other way
      ctx.lineWidth = 1
      ctx.globalAlpha = 0.8
      for (let i = 0; i < 4; i++) {
        const a = -s.spin * 0.55 + (i * TAU) / 4
        ctx.beginPath()
        ctx.arc(x, y, 16 * sc, a, a + 0.7)
        ctx.stroke()
      }
      // cross ticks
      ctx.globalAlpha = 1
      ctx.beginPath()
      for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
        ctx.moveTo(x + dx * 9.5 * sc, y + dy * 9.5 * sc)
        ctx.lineTo(x + dx * 13.5 * sc, y + dy * 13.5 * sc)
      }
      ctx.stroke()
      // corner brackets
      const c = 21 * sc
      const l = 5
      ctx.globalAlpha = 0.55 + s.heat * 0.45
      ctx.beginPath()
      for (const [dx, dy] of [[1, 1], [-1, 1], [1, -1], [-1, -1]]) {
        ctx.moveTo(x + dx * (c - l), y + dy * c)
        ctx.lineTo(x + dx * c, y + dy * c)
        ctx.lineTo(x + dx * c, y + dy * (c - l))
      }
      ctx.stroke()

      // core, with a sonar ping
      if (!reduceMotion) {
        const k = (now % 2000) / 2000
        ctx.globalAlpha = (1 - k) * 0.7
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.arc(x, y, 2.5 + k * 9, 0, TAU)
        ctx.stroke()
      }
      ctx.globalAlpha = 1
      ctx.shadowColor = colour
      ctx.shadowBlur = 8 + s.heat * 10
      ctx.beginPath()
      ctx.arc(x, y, 2.6, 0, TAU)
      ctx.fill()
      ctx.shadowBlur = 0

      ctx.font = '11px "Share Tech Mono", monospace'
      ctx.fillText('TARGET', x + c + 6, y - c + 4)
      if (s.hits.length) {
        ctx.globalAlpha = 0.8
        ctx.font = '10px "Share Tech Mono", monospace'
        ctx.fillText(`${s.hits.length} HITS/MIN`, x + c + 6, y - c + 17)
        ctx.globalAlpha = 1
      }
    }

    // Hover lock: brackets close in on the tower tip and a leader line runs
    // to the read-out panel on the right
    function drawLock(now) {
      const m = s.hoverMark
      if (!m) return
      const color = COLORS[m.o.kind]
      const k = reduceMotion ? 1 : Math.min(1, (now - s.hoverSince) / 220)
      const h = 9 + (1 - easeOutCubic(k)) * 16
      const l = 4
      ctx.globalAlpha = 1
      ctx.strokeStyle = color
      ctx.lineWidth = 1.3
      ctx.lineCap = 'butt'
      ctx.beginPath()
      for (const [dx, dy] of [[1, 1], [-1, 1], [1, -1], [-1, -1]]) {
        ctx.moveTo(m.tx + dx * (h - l), m.ty + dy * h)
        ctx.lineTo(m.tx + dx * h, m.ty + dy * h)
        ctx.lineTo(m.tx + dx * h, m.ty + dy * (h - l))
      }
      ctx.stroke()

      const panel = traceRef.current
      if (!panel) return
      const wr = wrap.getBoundingClientRect()
      const pr = panel.getBoundingClientRect()
      const ax = pr.left - wr.left
      const ay = pr.top - wr.top + 13
      // Narrow layouts dock the panel below the globe: no room for a leader
      if (!pr.width || ax < m.tx + h + 24) return
      const sx = m.tx + h + 3
      const ex = Math.max(sx + 6, ax - 26)
      ctx.globalAlpha = 0.85 * k
      ctx.lineWidth = 1
      ctx.setLineDash([4, 3])
      ctx.lineDashOffset = reduceMotion ? 0 : -now / 30
      ctx.beginPath()
      ctx.moveTo(sx, m.ty)
      ctx.lineTo(ex, ay)
      ctx.lineTo(ax - 4, ay)
      ctx.stroke()
      ctx.setLineDash([])
      ctx.fillStyle = color
      ctx.fillRect(ax - 5, ay - 2, 4, 4)
      ctx.fillRect(ex - 1.5, ay - 1.5, 3, 3)
      ctx.globalAlpha = 1
    }

    function draw(now) {
      raf = requestAnimationFrame(draw)
      const dt = Math.min(64, now - last)
      last = now
      if (!width || !height) return

      // Slow spin, paused while the user is looking around
      if (!reduceMotion && !paused && !s.dragging && !s.hover && now - s.lastInteraction > 2500) {
        s.rotation[0] += dt * 0.004
      }

      // Target dynamics: cooling, shield flash, recoil spring, hit rate
      s.heat *= Math.exp(-dt / HEAT_TAU)
      s.shieldFlash *= Math.exp(-dt / 250)
      if (reduceMotion) {
        s.kick = 0
        s.kickVel = 0
      } else {
        const step = Math.min(dt, 34) / 1000
        s.kickVel += (-260 * s.kick - 16 * s.kickVel) * step
        s.kick = Math.max(-0.3, s.kick + s.kickVel * step)
        s.spin += dt * (0.0011 + s.heat * 0.0045)
      }
      while (s.hits.length && now - s.hits[0] > 60000) s.hits.shift()

      const radius = Math.min(width, height) * 0.44 * s.zoom
      cx = width / 2
      cy = height / 2
      projection.scale(radius).translate([cx, cy]).rotate(s.rotation)
      unclipped.scale(radius).translate([cx, cy]).rotate(s.rotation)
      centre = [-s.rotation[0], -s.rotation[1]]

      ctx.clearRect(0, 0, width, height)

      // Atmosphere
      const halo = ctx.createRadialGradient(cx, cy, radius * 0.92, cx, cy, radius * 1.22)
      halo.addColorStop(0, 'rgba(0,255,65,0.16)')
      halo.addColorStop(1, 'rgba(0,255,65,0)')
      ctx.fillStyle = halo
      ctx.beginPath()
      ctx.arc(cx, cy, radius * 1.22, 0, TAU)
      ctx.fill()

      // Sphere
      const body = ctx.createRadialGradient(cx - radius * 0.35, cy - radius * 0.4, radius * 0.1, cx, cy, radius)
      body.addColorStop(0, '#07160b')
      body.addColorStop(1, '#010402')
      ctx.fillStyle = body
      ctx.beginPath()
      path({ type: 'Sphere' })
      ctx.fill()

      ctx.lineWidth = 0.5
      ctx.strokeStyle = 'rgba(0,255,65,0.07)'
      ctx.beginPath()
      path(GRATICULE)
      ctx.stroke()

      ctx.fillStyle = 'rgba(0,255,65,0.085)'
      ctx.strokeStyle = 'rgba(0,255,65,0.42)'
      ctx.lineWidth = 0.6
      ctx.beginPath()
      path(LAND)
      ctx.fill()
      ctx.stroke()

      ctx.strokeStyle = 'rgba(0,255,65,0.5)'
      ctx.lineWidth = 1
      ctx.beginPath()
      path({ type: 'Sphere' })
      ctx.stroke()

      drawOrigins(now)
      drawArcs(now)

      if (s.vps) {
        const rgb = heatRgb(s.heat)
        drawShield(now, rgb)
        drawImpacts(now)
        if (visible(s.vps)) {
          const p = projection(s.vps)
          if (p) drawReticle(now, p, rgb)
        }
        drawTargetTower(now, rgb)
      }
      drawLock(now)
    }
    raf = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(raf)
      observer.disconnect()
    }
  }, [paused])

  // ── Pointer interaction ──
  useEffect(() => {
    const canvas = canvasRef.current
    const s = scene.current
    const pointers = new Map()
    let moved = 0
    let pinch = 0

    function lock(origin) {
      if (origin === s.hover) return
      s.hover = origin
      s.hoverSince = performance.now()
      setHover(origin)
    }
    function nearest(x, y) {
      let best = null
      let bestD = 14
      for (const pt of s.screen) {
        const d = Math.hypot(pt.x - x, pt.y - y) - pt.r
        if (d < bestD) { bestD = d; best = pt }
      }
      return best
    }
    function local(ev) {
      const r = canvas.getBoundingClientRect()
      return [ev.clientX - r.left, ev.clientY - r.top]
    }

    function down(ev) {
      canvas.setPointerCapture(ev.pointerId)
      pointers.set(ev.pointerId, [ev.clientX, ev.clientY])
      s.dragging = true
      moved = 0
      if (pointers.size === 2) {
        const [a, b] = [...pointers.values()]
        pinch = Math.hypot(a[0] - b[0], a[1] - b[1])
      }
    }
    function move(ev) {
      const prev = pointers.get(ev.pointerId)
      if (!prev) {
        const [x, y] = local(ev)
        const hit = nearest(x, y)
        canvas.style.cursor = hit ? 'pointer' : 'grab'
        lock(hit ? hit.origin : null)
        return
      }
      pointers.set(ev.pointerId, [ev.clientX, ev.clientY])
      s.lastInteraction = performance.now()
      if (pointers.size === 2) {
        const [a, b] = [...pointers.values()]
        const dist = Math.hypot(a[0] - b[0], a[1] - b[1])
        if (pinch) s.zoom = Math.max(0.7, Math.min(3, s.zoom * (dist / pinch)))
        pinch = dist
        moved += 10
        return
      }
      const dx = ev.clientX - prev[0]
      const dy = ev.clientY - prev[1]
      moved += Math.abs(dx) + Math.abs(dy)
      const k = 0.28 / s.zoom
      s.rotation[0] += dx * k
      s.rotation[1] = Math.max(-80, Math.min(80, s.rotation[1] - dy * k))
      lock(null)
    }
    function up(ev) {
      pointers.delete(ev.pointerId)
      if (pointers.size < 2) pinch = 0
      if (pointers.size === 0) {
        s.dragging = false
        s.lastInteraction = performance.now()
        if (moved < 6) {
          const [x, y] = local(ev)
          const hit = nearest(x, y)
          if (hit?.origin.ip) onIpClick?.(hit.origin.ip)
        }
      }
    }
    function wheel(ev) {
      ev.preventDefault()
      s.zoom = Math.max(0.7, Math.min(3, s.zoom * (ev.deltaY < 0 ? 1.1 : 0.9)))
      s.lastInteraction = performance.now()
    }
    function leave() { lock(null) }

    canvas.addEventListener('pointerdown', down)
    canvas.addEventListener('pointermove', move)
    canvas.addEventListener('pointerup', up)
    canvas.addEventListener('pointercancel', up)
    canvas.addEventListener('pointerleave', leave)
    canvas.addEventListener('wheel', wheel, { passive: false })
    return () => {
      canvas.removeEventListener('pointerdown', down)
      canvas.removeEventListener('pointermove', move)
      canvas.removeEventListener('pointerup', up)
      canvas.removeEventListener('pointercancel', up)
      canvas.removeEventListener('pointerleave', leave)
      canvas.removeEventListener('wheel', wheel)
    }
  }, [onIpClick])

  return (
    <div className="globe-wrap" ref={wrapRef}>
      <canvas
        ref={canvasRef}
        className="globe-canvas"
        role="img"
        aria-label="Rotating globe showing where SSH attacks, HTTP probes and visits come from"
      />
      <GlobeTrace
        origin={hover}
        color={hover ? COLORS[hover.kind] : undefined}
        label={hover ? LABELS[hover.kind] : ''}
        vps={scene.current.vps}
        panelRef={traceRef}
      />
      <GlobeHud config={config} onIpClick={onIpClick} showRecords={!replaying} />
      <div className="globe-legend">
        <span><i style={{ background: SSH_COLOR }} />SSH</span>
        <span><i style={{ background: HTTP_COLOR }} />HTTP</span>
        <span><i style={{ background: VISITOR_COLOR }} />VISITS</span>
      </div>
      <div className="globe-hint">DRAG · ZOOM · CLICK A TOWER</div>
    </div>
  )
}
