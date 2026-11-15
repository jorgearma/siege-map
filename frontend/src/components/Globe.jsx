import React, { useEffect, useRef, useState } from 'react'
import { geoOrthographic, geoPath, geoGraticule10, geoInterpolate, geoDistance } from 'd3-geo'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'

/**
 * Wireframe globe drawn on a 2D canvas (d3-geo orthographic projection).
 * No WebGL and no external tiles: the country shapes ship inside the bundle,
 * so it works under a strict CSP and on phones.
 *
 * Drag to rotate, wheel / pinch to zoom, click a point to open its dossier.
 */

const LAND = feature(world, world.objects.countries)
const GRATICULE = geoGraticule10()

const SSH_COLOR = '#ff2020'
const HTTP_COLOR = '#ffd700'
const VISITOR_COLOR = '#1e90ff'

const ARC_MS = 1500
const ARC_STEPS = 36
const ARC_LIFT = 0.28
const MAX_ARCS = 120
const HALF_PI = Math.PI / 2

function kindOf(e) {
  if (e.source === 'ssh') return 'ssh'
  if (e.event_type?.startsWith('visit_')) return 'visit'
  return 'http'
}
const COLORS = { ssh: SSH_COLOR, http: HTTP_COLOR, visit: VISITOR_COLOR }
const LABELS = { ssh: 'SSH', http: 'HTTP probe', visit: 'Visit' }

export default function Globe({ events, initialIds, config, onIpClick, paused = false }) {
  const wrapRef = useRef(null)
  const canvasRef = useRef(null)
  const [hover, setHover] = useState(null)

  // Mutable scene state: read by the draw loop, never triggers a re-render
  const scene = useRef({
    rotation: [10, -25, 0],
    zoom: 1,
    dragging: false,
    lastInteraction: 0,
    origins: new Map(),   // key -> {lat, lon, kind, count, ip, cc, born}
    arcs: [],             // {interp, color, start}
    impacts: [],          // {start, color}
    seen: new Set(),
    screen: [],           // [{x, y, origin}] of visible points (hit testing)
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
      const key = e.ip ? `${e.ip}|${kind}` : `${e.geo.lat},${e.geo.lon}|${kind}`
      const o = s.origins.get(key)
      if (o) {
        o.count += e.count || 1
        o.last = now
      } else {
        s.origins.set(key, {
          lat: e.geo.lat, lon: e.geo.lon, kind, ip: e.ip || '', count: e.count || 1,
          cc: e.geo.country_code, country: e.geo.country, city: e.geo.city, born: now, last: now,
        })
      }
      // Animate only what arrives live, not the backlog sent on connect
      if (s.vps && !initialIds?.has(e.id) && s.arcs.length < MAX_ARCS) {
        s.arcs.push({
          interp: geoInterpolate([e.geo.lon, e.geo.lat], s.vps),
          color: COLORS[kind],
          start: now + Math.random() * 250,
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
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    let width = 0
    let height = 0
    let raf = 0
    let last = performance.now()

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
      return geoDistance(lonlat, [-s.rotation[0], -s.rotation[1]]) < HALF_PI - 0.02
    }

    function draw(now) {
      raf = requestAnimationFrame(draw)
      const dt = Math.min(64, now - last)
      last = now
      if (!width || !height) return

      // Slow spin, paused while the user is looking around
      if (!reduceMotion && !paused && !s.dragging && now - s.lastInteraction > 2500) {
        s.rotation[0] += dt * 0.004
      }

      const radius = Math.min(width, height) * 0.44 * s.zoom
      const cx = width / 2
      const cy = height / 2
      projection.scale(radius).translate([cx, cy]).rotate(s.rotation)
      unclipped.scale(radius).translate([cx, cy]).rotate(s.rotation)
      const centre = [-s.rotation[0], -s.rotation[1]]

      ctx.clearRect(0, 0, width, height)

      // Atmosphere
      const halo = ctx.createRadialGradient(cx, cy, radius * 0.92, cx, cy, radius * 1.22)
      halo.addColorStop(0, 'rgba(0,255,65,0.16)')
      halo.addColorStop(1, 'rgba(0,255,65,0)')
      ctx.fillStyle = halo
      ctx.beginPath()
      ctx.arc(cx, cy, radius * 1.22, 0, Math.PI * 2)
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

      // Origins
      s.screen = []
      for (const o of s.origins.values()) {
        const lonlat = [o.lon, o.lat]
        if (!visible(lonlat)) continue
        const p = projection(lonlat)
        if (!p) continue
        const size = Math.min(7, 2.2 + Math.log2(1 + o.count) * 0.8)
        const pulse = reduceMotion ? 0.5 : (Math.sin((now - o.born) / 420) + 1) / 2
        const color = COLORS[o.kind]
        ctx.globalAlpha = 0.16 + pulse * 0.14
        ctx.fillStyle = color
        ctx.beginPath()
        ctx.arc(p[0], p[1], size + 3 + pulse * 3, 0, Math.PI * 2)
        ctx.fill()
        ctx.globalAlpha = 1
        ctx.beginPath()
        ctx.arc(p[0], p[1], size, 0, Math.PI * 2)
        ctx.fill()
        ctx.lineWidth = 1
        ctx.strokeStyle = '#010402'
        ctx.stroke()
        s.screen.push({ x: p[0], y: p[1], r: size, origin: o })
      }

      // Arcs: great circle lifted off the surface, with a bright head
      const alive = []
      for (const arc of s.arcs) {
        const t = (now - arc.start) / ARC_MS
        if (t < 0) { alive.push(arc); continue }
        if (t >= 1) { s.impacts.push({ start: now, color: arc.color }); continue }
        alive.push(arc)
        const head = Math.min(1, t * 1.15)
        const tail = Math.max(0, head - 0.45)
        ctx.strokeStyle = arc.color
        ctx.lineWidth = 1.4
        ctx.lineCap = 'round'
        let prev = null
        let headPoint = null
        for (let i = 0; i <= ARC_STEPS; i++) {
          const u = tail + ((head - tail) * i) / ARC_STEPS
          const lonlat = arc.interp(u)
          const lift = 1 + ARC_LIFT * Math.sin(Math.PI * u)
          // Lifted points stay visible a little past the horizon
          const limit = Math.acos(Math.min(1, 1 / lift)) + HALF_PI - 0.02
          if (geoDistance(lonlat, centre) > limit) { prev = null; continue }
          const flat = unclipped(lonlat)
          if (!flat) { prev = null; continue }
          const x = cx + (flat[0] - cx) * lift
          const y = cy + (flat[1] - cy) * lift
          if (prev) {
            ctx.globalAlpha = 0.12 + 0.75 * (i / ARC_STEPS)
            ctx.beginPath()
            ctx.moveTo(prev[0], prev[1])
            ctx.lineTo(x, y)
            ctx.stroke()
          }
          prev = [x, y]
          if (i === ARC_STEPS) headPoint = prev
        }
        ctx.globalAlpha = 1
        if (headPoint) {
          ctx.fillStyle = '#ffffff'
          ctx.shadowColor = arc.color
          ctx.shadowBlur = 10
          ctx.beginPath()
          ctx.arc(headPoint[0], headPoint[1], 1.8, 0, Math.PI * 2)
          ctx.fill()
          ctx.shadowBlur = 0
        }
      }
      s.arcs = alive

      // Target
      if (s.vps && visible(s.vps)) {
        const p = projection(s.vps)
        if (p) {
          s.impacts = s.impacts.filter((im) => now - im.start < 700).slice(-12)
          for (const im of s.impacts) {
            const k = (now - im.start) / 700
            ctx.globalAlpha = 1 - k
            ctx.strokeStyle = im.color
            ctx.lineWidth = 1.5
            ctx.beginPath()
            ctx.arc(p[0], p[1], 5 + k * 22, 0, Math.PI * 2)
            ctx.stroke()
          }
          ctx.globalAlpha = 1
          const spin = reduceMotion ? 0 : now / 900
          ctx.strokeStyle = '#00ff41'
          ctx.lineWidth = 1.2
          ctx.beginPath()
          ctx.arc(p[0], p[1], 9, spin, spin + Math.PI * 1.4)
          ctx.stroke()
          ctx.beginPath()
          ctx.moveTo(p[0] - 15, p[1]); ctx.lineTo(p[0] - 5, p[1])
          ctx.moveTo(p[0] + 5, p[1]); ctx.lineTo(p[0] + 15, p[1])
          ctx.moveTo(p[0], p[1] - 15); ctx.lineTo(p[0], p[1] - 5)
          ctx.moveTo(p[0], p[1] + 5); ctx.lineTo(p[0], p[1] + 15)
          ctx.stroke()
          ctx.fillStyle = '#00ff41'
          ctx.beginPath()
          ctx.arc(p[0], p[1], 2.5, 0, Math.PI * 2)
          ctx.fill()
          ctx.font = '11px "Share Tech Mono", monospace'
          ctx.fillText('TARGET', p[0] + 16, p[1] - 10)
        }
      } else {
        s.impacts = []
      }
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
        setHover(hit ? { x: hit.x, y: hit.y, o: hit.origin } : null)
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
      setHover(null)
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
    function leave() { setHover(null) }

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
      {hover && (
        <div className="globe-tip" style={{ left: hover.x, top: hover.y }}>
          <span className="globe-tip-kind">
            <i style={{ background: COLORS[hover.o.kind] }} />
            {LABELS[hover.o.kind]}
          </span>
          {hover.o.ip && <span className="globe-tip-ip">{hover.o.ip}</span>}
          <span className="globe-tip-geo">
            {[hover.o.city && hover.o.city !== 'Unknown' ? hover.o.city : null, hover.o.country || hover.o.cc]
              .filter(Boolean).join(', ')}
          </span>
          <span className="globe-tip-count">{hover.o.count.toLocaleString()} events</span>
        </div>
      )}
      <div className="globe-legend">
        <span><i style={{ background: SSH_COLOR }} />SSH</span>
        <span><i style={{ background: HTTP_COLOR }} />HTTP</span>
        <span><i style={{ background: VISITOR_COLOR }} />VISITS</span>
      </div>
      <div className="globe-hint">DRAG · ZOOM · CLICK A POINT</div>
    </div>
  )
}
