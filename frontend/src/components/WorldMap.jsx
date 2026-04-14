import React, { useEffect, useRef, useMemo, useState, useCallback } from 'react'
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet'
import L from 'leaflet'

// Fix default marker icon
delete L.Icon.Default.prototype._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
})

const VPS_ICON = new L.DivIcon({
  className: 'vps-marker',
  html: '<div class="vps-pulse"></div>',
  iconSize: [20, 20],
  iconAnchor: [10, 10],
})

/* ── Color palette ─────────────────────────────────── */
// SSH attacks → red | HTTP bots → yellow | Real traffic → blue
const SSH_COLOR     = '#ff2020'
const HTTP_COLOR    = '#ffd700'
const VISITOR_COLOR = '#1e90ff'

const EVENT_COLORS = {
  // SSH events — red
  failed_password:     SSH_COLOR,
  invalid_user:        SSH_COLOR,
  connection_closed:   SSH_COLOR,
  disconnected:        SSH_COLOR,
  max_auth_exceeded:   SSH_COLOR,
  received_disconnect: SSH_COLOR,
  bad_protocol:        SSH_COLOR,
  // HTTP bots/threats — yellow
  git_exposure:        HTTP_COLOR,
  secret_probe:        HTTP_COLOR,
  cms_scan:            HTTP_COLOR,
  php_probe:           HTTP_COLOR,
  path_traversal:      HTTP_COLOR,
  exploit_attempt:     HTTP_COLOR,
  scanner:             HTTP_COLOR,
  post_probe:          HTTP_COLOR,
  crawler:             HTTP_COLOR,
  auto_tool:           HTTP_COLOR,
  http_error:          HTTP_COLOR,
  // Real traffic — blue
  visit_desktop:       VISITOR_COLOR,
  visit_mobile:        VISITOR_COLOR,
  visit_tablet:        VISITOR_COLOR,
}

function getEventColor(type) {
  return EVENT_COLORS[type] || '#00ff41'
}

/* ── Data text fragments for particles ──────────────── */
const DATA_FRAGMENTS = [
  '0xA7F3', '0x4E2B', '0xFF01', '0xDEAD', '0xBEEF', '0xCAFE',
  'SYN>>', '>>ACK', 'RST||', 'PSH>>', '::22', ':SSH',
  'AUTH', 'FAIL', 'DENY', 'BRUT', 'SCAN', 'PRBE',
  '01101', '10010', '11001', '00110', '10101', '01010',
]

function randomFragment() {
  return DATA_FRAGMENTS[Math.floor(Math.random() * DATA_FRAGMENTS.length)]
}

/* ── Bezier math ───────────────────────────────────── */
function getControlPoint(from, to) {
  const mid = { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 }
  const dx = to.x - from.x
  const dy = to.y - from.y
  const dist = Math.sqrt(dx * dx + dy * dy)
  if (dist === 0) return mid
  const nx = -dy / dist
  const ny = dx / dist
  const curvature = Math.min(dist * 0.35, 150)
  return { x: mid.x + nx * curvature, y: mid.y + ny * curvature }
}

function bezierPoint(a, cp, b, t) {
  const u = 1 - t
  return {
    x: u * u * a.x + 2 * u * t * cp.x + t * t * b.x,
    y: u * u * a.y + 2 * u * t * cp.y + t * t * b.y,
  }
}

/* ── Particle Canvas Overlay ────────────────────────── */
function ParticleCanvas({ events, initialIds, config, onSelectOrigin }) {
  const map = useMap()
  const canvasRef = useRef(null)
  const stateRef = useRef({
    arcs: [],
    packets: [],
    impacts: [],
    origins: [],
    reticle: { angle: 0 },
    processedIds: new Set(),
    initializedHistorical: false,
  })

  // Create canvas
  useEffect(() => {
    const container = map.getContainer()
    const canvas = document.createElement('canvas')
    canvas.className = 'particle-canvas'
    canvas.style.position = 'absolute'
    canvas.style.top = '0'
    canvas.style.left = '0'
    canvas.style.pointerEvents = 'none'
    canvas.style.zIndex = '450'
    container.appendChild(canvas)
    canvasRef.current = canvas

    function resize() {
      const rect = container.getBoundingClientRect()
      canvas.width = rect.width * (window.devicePixelRatio || 1)
      canvas.height = rect.height * (window.devicePixelRatio || 1)
      canvas.style.width = rect.width + 'px'
      canvas.style.height = rect.height + 'px'
    }

    resize()
    map.on('resize', resize)
    window.addEventListener('resize', resize)

    return () => {
      if (canvas.parentNode) canvas.parentNode.removeChild(canvas)
      map.off('resize', resize)
      window.removeEventListener('resize', resize)
    }
  }, [map])

  // Click on map → toggle origin reticle
  useEffect(() => {
    const state = stateRef.current
    const HIT_RADIUS = 16 // px — click tolerance

    function onMapClick(e) {
      const clickPt = map.latLngToContainerPoint(e.latlng)
      let hit = null
      let minDist = Infinity

      state.origins.forEach((o) => {
        const oPt = map.latLngToContainerPoint([o.lat, o.lng])
        const dx = clickPt.x - oPt.x
        const dy = clickPt.y - oPt.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        if (dist < HIT_RADIUS && dist < minDist) {
          minDist = dist
          hit = o
        }
      })

      if (hit) {
        // Toggle clicked origin; deselect all others
        const wasSelected = hit.selected
        state.origins.forEach((o) => { o.selected = false })
        hit.selected = !wasSelected
        onSelectOrigin?.(hit.selected ? {
          lat: hit.lat, lng: hit.lng, ip: hit.ip,
          city: hit.city, country: hit.country,
          color: hit.color, hits: hit.hits,
        } : null)
      } else {
        state.origins.forEach((o) => { o.selected = false })
        onSelectOrigin?.(null)
      }
    }

    map.on('click', onMapClick)
    return () => map.off('click', onMapClick)
  }, [map, onSelectOrigin])

  // Spawn particles for new events (skip historical ones)
  useEffect(() => {
    if (!config) return
    const state = stateRef.current

    // On first run, mark all historical event IDs as already processed
    if (!state.initializedHistorical && initialIds.size > 0) {
      initialIds.forEach((id) => state.processedIds.add(id))
      state.initializedHistorical = true
    }

    events.forEach((event) => {
      if (state.processedIds.has(event.id)) return
      state.processedIds.add(event.id)

      if (!event.geo || (event.geo.lat === 0 && event.geo.lon === 0)) return

      const color = getEventColor(event.event_type)
      const from = { lat: event.geo.lat, lng: event.geo.lon }
      const to = { lat: config.vps_lat, lng: config.vps_lon }

      // Add persistent arc
      state.arcs.push({
        from,
        to,
        color,
        alpha: 1.0,
        birth: Date.now(),
      })

      // Add origin marker
      const existingOrigin = state.origins.find(
        (o) => o.lat === from.lat && o.lng === from.lng
      )
      if (existingOrigin) {
        existingOrigin.birth = Date.now()
        existingOrigin.hits = (existingOrigin.hits || 1) + 1
      } else {
        state.origins.push({
          lat: from.lat,
          lng: from.lng,
          color,
          birth: Date.now(),
          angle: 0,
          city: event.geo?.city || '',
          country: event.geo?.country || '',
          ip: event.ip || '',
          hits: 1,
          selected: false,
        })
      }
      if (state.origins.length > 60) state.origins = state.origins.slice(-50)

      // Spawn data packets (staggered)
      const count = 2 + Math.floor(Math.random() * 4)
      for (let i = 0; i < count; i++) {
        state.packets.push({
          from,
          to,
          color,
          progress: -i * 0.12,
          speed: 0.25 + Math.random() * 0.35,
          size: 1.5 + Math.random() * 2.5,
          fragment: randomFragment(),
          showText: Math.random() > 0.4,
          textFlicker: 0,
        })
      }
    })

    // Limit processed IDs memory
    if (state.processedIds.size > 2000) {
      const arr = [...state.processedIds]
      state.processedIds = new Set(arr.slice(-1000))
    }

    // Limit active arcs
    if (state.arcs.length > 60) {
      state.arcs = state.arcs.slice(-40)
    }
  }, [events, initialIds, config])

  // Animation loop
  useEffect(() => {
    let animId
    let lastTime = performance.now()
    const dpr = window.devicePixelRatio || 1

    function animate(now) {
      const dt = Math.min((now - lastTime) / 1000, 0.1)
      lastTime = now

      const canvas = canvasRef.current
      if (!canvas || !config) {
        animId = requestAnimationFrame(animate)
        return
      }

      const ctx = canvas.getContext('2d')
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, canvas.width / dpr, canvas.height / dpr)

      const state = stateRef.current
      const vpsScreen = map.latLngToContainerPoint([
        config.vps_lat,
        config.vps_lon,
      ])

      // ── Draw arcs ──
      state.arcs = state.arcs.filter((arc) => {
        arc.alpha -= dt * 0.12
        if (arc.alpha <= 0) return false

        const from = map.latLngToContainerPoint([arc.from.lat, arc.from.lng])
        const to = map.latLngToContainerPoint([arc.to.lat, arc.to.lng])
        const cp = getControlPoint(from, to)

        // Outer glow
        ctx.save()
        ctx.beginPath()
        ctx.moveTo(from.x, from.y)
        ctx.quadraticCurveTo(cp.x, cp.y, to.x, to.y)
        ctx.strokeStyle = arc.color
        ctx.lineWidth = 3
        ctx.globalAlpha = arc.alpha * 0.12
        ctx.shadowColor = arc.color
        ctx.shadowBlur = 20
        ctx.stroke()

        // Inner line
        ctx.beginPath()
        ctx.moveTo(from.x, from.y)
        ctx.quadraticCurveTo(cp.x, cp.y, to.x, to.y)
        ctx.strokeStyle = arc.color
        ctx.lineWidth = 1
        ctx.globalAlpha = arc.alpha * 0.4
        ctx.shadowBlur = 6
        ctx.stroke()
        ctx.restore()

        return true
      })

      // ── Draw packets ──
      state.packets = state.packets.filter((p) => {
        p.progress += p.speed * dt
        if (p.progress >= 1) {
          // Spawn impact
          state.impacts.push({
            x: vpsScreen.x,
            y: vpsScreen.y,
            radius: 0,
            maxRadius: 25 + Math.random() * 30,
            alpha: 1,
            color: p.color,
            rings: 2 + Math.floor(Math.random() * 2),
          })
          return false
        }
        if (p.progress < 0) return true

        const from = map.latLngToContainerPoint([p.from.lat, p.from.lng])
        const to = map.latLngToContainerPoint([p.to.lat, p.to.lng])
        const cp = getControlPoint(from, to)

        // Draw trail
        const trailLen = 0.1
        const trailSteps = 12
        for (let i = 0; i <= trailSteps; i++) {
          const t = p.progress - trailLen + (trailLen * i) / trailSteps
          if (t < 0 || t > 1) continue
          const pos = bezierPoint(from, cp, to, t)
          const frac = i / trailSteps

          ctx.save()
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, p.size * frac * 0.7, 0, Math.PI * 2)
          ctx.fillStyle = p.color
          ctx.globalAlpha = frac * 0.5
          ctx.fill()
          ctx.restore()
        }

        // Packet head
        const head = bezierPoint(from, cp, to, p.progress)

        // Glow
        ctx.save()
        ctx.beginPath()
        ctx.arc(head.x, head.y, p.size + 4, 0, Math.PI * 2)
        ctx.fillStyle = p.color
        ctx.globalAlpha = 0.15
        ctx.shadowColor = p.color
        ctx.shadowBlur = 20
        ctx.fill()
        ctx.restore()

        // Bright core
        ctx.save()
        ctx.beginPath()
        ctx.arc(head.x, head.y, p.size, 0, Math.PI * 2)
        ctx.fillStyle = '#ffffff'
        ctx.globalAlpha = 0.95
        ctx.shadowColor = p.color
        ctx.shadowBlur = 12
        ctx.fill()
        ctx.restore()

        // Color ring
        ctx.save()
        ctx.beginPath()
        ctx.arc(head.x, head.y, p.size + 1.5, 0, Math.PI * 2)
        ctx.strokeStyle = p.color
        ctx.lineWidth = 0.8
        ctx.globalAlpha = 0.7
        ctx.stroke()
        ctx.restore()

        // Data text fragment
        if (p.showText) {
          p.textFlicker += dt
          const flickerAlpha =
            Math.sin(p.textFlicker * 8) > 0.3 ? 0.7 : 0.2
          ctx.save()
          ctx.font = '9px "Share Tech Mono", monospace'
          ctx.fillStyle = p.color
          ctx.globalAlpha = flickerAlpha * (0.5 + p.progress * 0.5)
          ctx.fillText(p.fragment, head.x + 8, head.y - 6)
          ctx.restore()
        }

        return true
      })

      // ── Draw impacts ──
      state.impacts = state.impacts.filter((imp) => {
        imp.radius += dt * 120
        imp.alpha -= dt * 2.0
        if (imp.alpha <= 0) return false

        for (let r = 0; r < imp.rings; r++) {
          const ringRadius = imp.radius - r * 8
          if (ringRadius < 0) continue

          ctx.save()
          ctx.beginPath()
          ctx.arc(imp.x, imp.y, ringRadius, 0, Math.PI * 2)
          ctx.strokeStyle = imp.color
          ctx.lineWidth = 2 - r * 0.5
          ctx.globalAlpha = imp.alpha * (1 - r * 0.3)
          ctx.shadowColor = imp.color
          ctx.shadowBlur = 10
          ctx.stroke()
          ctx.restore()
        }

        // Flash at center
        if (imp.alpha > 0.5) {
          ctx.save()
          ctx.beginPath()
          ctx.arc(imp.x, imp.y, 6 * imp.alpha, 0, Math.PI * 2)
          ctx.fillStyle = '#ffffff'
          ctx.globalAlpha = imp.alpha * 0.6
          ctx.shadowColor = imp.color
          ctx.shadowBlur = 25
          ctx.fill()
          ctx.restore()
        }

        return true
      })

      // ── Origin markers ──
      state.origins.forEach((o) => {
        o.angle += dt * 0.8

        const pos = map.latLngToContainerPoint([o.lat, o.lng])

        if (o.selected) {
          // ── Full reticle when selected ──
          const oPulse = 0.5 + 0.5 * Math.sin(now / 600)
          const ringR1 = 14 + oPulse * 3
          const ringR2 = 22 + oPulse * 2

          ctx.save()

          // Core dot (larger when selected)
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, 4, 0, Math.PI * 2)
          ctx.fillStyle = o.color
          ctx.shadowColor = o.color
          ctx.shadowBlur = 14
          ctx.globalAlpha = 1
          ctx.fill()

          // Inner pulsing ring
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, ringR1, 0, Math.PI * 2)
          ctx.strokeStyle = o.color
          ctx.lineWidth = 1.2
          ctx.globalAlpha = 0.5 + oPulse * 0.3
          ctx.shadowBlur = 8
          ctx.stroke()

          // Outer rotating arcs (4 segments)
          ctx.globalAlpha = 0.35 + oPulse * 0.2
          ctx.lineWidth = 1
          for (let i = 0; i < 4; i++) {
            const a = o.angle + (i * Math.PI) / 2
            ctx.beginPath()
            ctx.arc(pos.x, pos.y, ringR2, a - 0.45, a + 0.45)
            ctx.stroke()
          }

          // Crosshair lines
          ctx.globalAlpha = 0.4
          ctx.lineWidth = 0.8
          const cLen = 18
          const cGap = 8
          ctx.beginPath()
          ctx.moveTo(pos.x - cLen, pos.y)
          ctx.lineTo(pos.x - cGap, pos.y)
          ctx.moveTo(pos.x + cGap, pos.y)
          ctx.lineTo(pos.x + cLen, pos.y)
          ctx.moveTo(pos.x, pos.y - cLen)
          ctx.lineTo(pos.x, pos.y - cGap)
          ctx.moveTo(pos.x, pos.y + cGap)
          ctx.lineTo(pos.x, pos.y + cLen)
          ctx.strokeStyle = o.color
          ctx.stroke()

          ctx.restore()
        } else {
          // ── Small dot (default) ──
          const dotPulse = 0.4 + 0.6 * Math.abs(Math.sin(now / 900 + o.lat))
          ctx.save()
          // Soft glow
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, 5, 0, Math.PI * 2)
          ctx.fillStyle = o.color
          ctx.globalAlpha = 0.12 * dotPulse
          ctx.shadowColor = o.color
          ctx.shadowBlur = 8
          ctx.fill()
          // Solid core
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, 2.5, 0, Math.PI * 2)
          ctx.fillStyle = o.color
          ctx.globalAlpha = 0.75
          ctx.shadowBlur = 4
          ctx.fill()
          ctx.restore()
        }
      })

      // ── VPS Reticle ──
      state.reticle.angle += dt * 0.5
      const angle = state.reticle.angle
      const vx = vpsScreen.x
      const vy = vpsScreen.y
      const pulse = 0.5 + 0.5 * Math.sin(now / 500)

      ctx.save()

      // Outer rotating ring
      ctx.beginPath()
      ctx.strokeStyle = '#00d4ff'
      ctx.lineWidth = 1
      ctx.globalAlpha = 0.25 + pulse * 0.15
      ctx.shadowColor = '#00d4ff'
      ctx.shadowBlur = 8
      const ringR = 22 + pulse * 4
      for (let i = 0; i < 4; i++) {
        const a = angle + (i * Math.PI) / 2
        const startA = a - 0.5
        const endA = a + 0.5
        ctx.beginPath()
        ctx.arc(vx, vy, ringR, startA, endA)
        ctx.stroke()
      }

      // Crosshair lines
      ctx.globalAlpha = 0.2 + pulse * 0.1
      ctx.lineWidth = 0.5
      const crossLen = 35 + pulse * 5
      const crossGap = 12
      // Horizontal
      ctx.beginPath()
      ctx.moveTo(vx - crossLen, vy)
      ctx.lineTo(vx - crossGap, vy)
      ctx.moveTo(vx + crossGap, vy)
      ctx.lineTo(vx + crossLen, vy)
      // Vertical
      ctx.moveTo(vx, vy - crossLen)
      ctx.lineTo(vx, vy - crossGap)
      ctx.moveTo(vx, vy + crossGap)
      ctx.lineTo(vx, vy + crossLen)
      ctx.stroke()

      // Target label
      ctx.font = '10px "Share Tech Mono", monospace'
      ctx.fillStyle = '#00d4ff'
      ctx.globalAlpha = 0.5 + pulse * 0.2
      ctx.fillText('TARGET', vx + 18, vy - 18)

      ctx.restore()

      // ── Limit arrays ──
      if (state.packets.length > 150) state.packets = state.packets.slice(-100)
      if (state.impacts.length > 30) state.impacts = state.impacts.slice(-20)

      animId = requestAnimationFrame(animate)
    }

    animId = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animId)
  }, [map, config])

  return null
}

/* ── Spy Intel Callout (HTML overlay + SVG connector) ── */
function IntelCallout({ origin, onIpClick, onClose }) {
  const map = useMap()
  const [pos, setPos] = useState(null)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const cardRef = useRef(null)

  useEffect(() => {
    if (!cardRef.current) return
    L.DomEvent.disableClickPropagation(cardRef.current)
    L.DomEvent.disableScrollPropagation(cardRef.current)
  }, [origin])

  useEffect(() => {
    const container = map.getContainer()
    setSize({ w: container.clientWidth, h: container.clientHeight })

    function update() {
      if (!origin) return
      const p = map.latLngToContainerPoint([origin.lat, origin.lng])
      setPos({ x: p.x, y: p.y })
      setSize({ w: container.clientWidth, h: container.clientHeight })
    }

    update()
    map.on('move zoom resize zoomanim', update)
    window.addEventListener('resize', update)
    return () => {
      map.off('move zoom resize zoomanim', update)
      window.removeEventListener('resize', update)
    }
  }, [map, origin])

  if (!origin || !pos) return null

  // Card placement: pick a quadrant offset that keeps the card in view
  const CARD_W = 260
  const CARD_H = 180
  const PAD = 24
  const placeRight = pos.x + 60 + CARD_W < size.w
  const placeBelow = pos.y + 40 + CARD_H < size.h

  const cardX = placeRight ? pos.x + 80 : pos.x - 80 - CARD_W
  const cardY = placeBelow ? pos.y + 30 : pos.y - 30 - CARD_H

  // Connector endpoints (anchor on card edge facing origin)
  const anchorX = placeRight ? cardX : cardX + CARD_W
  const anchorY = cardY + 24
  // Mid kink point for the polyline
  const kinkX = placeRight ? cardX - 14 : cardX + CARD_W + 14

  const color = origin.color || '#ff2020'

  return (
    <>
      {/* SVG connector line */}
      <svg
        className="intel-connector"
        width={size.w}
        height={size.h}
        style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none', zIndex: 460 }}
      >
        <defs>
          <filter id="intel-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* Animated dashed connector */}
        <polyline
          points={`${pos.x},${pos.y} ${kinkX},${pos.y} ${kinkX},${anchorY} ${anchorX},${anchorY}`}
          fill="none"
          stroke={color}
          strokeWidth="1"
          strokeDasharray="4 3"
          filter="url(#intel-glow)"
          opacity="0.85"
        >
          <animate attributeName="stroke-dashoffset" from="0" to="-14" dur="0.7s" repeatCount="indefinite" />
        </polyline>
        {/* Anchor diamond at card edge */}
        <rect
          x={anchorX - 3}
          y={anchorY - 3}
          width="6"
          height="6"
          fill={color}
          transform={`rotate(45 ${anchorX} ${anchorY})`}
          filter="url(#intel-glow)"
        />
      </svg>

      {/* Intel Card */}
      <div
        ref={cardRef}
        className="intel-callout"
        style={{
          position: 'absolute',
          left: cardX,
          top: cardY,
          width: CARD_W,
          zIndex: 470,
          '--callout-color': color,
        }}
      >
        <div className="intel-corner intel-corner--tl" />
        <div className="intel-corner intel-corner--tr" />
        <div className="intel-corner intel-corner--bl" />
        <div className="intel-corner intel-corner--br" />

        <div className="intel-header">
          <span className="intel-classified">// CLASSIFIED</span>
          <button className="intel-close" onClick={onClose} aria-label="close">×</button>
        </div>

        <div className="intel-status">
          <span className="intel-status-dot" />
          TRACE LOCKED
        </div>

        <div className="intel-rows">
          <div className="intel-row">
            <span className="intel-key">SUBJECT</span>
            <span className="intel-val intel-val--ip">{origin.ip || 'UNKNOWN'}</span>
          </div>
          <div className="intel-row">
            <span className="intel-key">ORIGIN</span>
            <span className="intel-val">
              {origin.city && origin.country ? `${origin.city}, ${origin.country}`
                : origin.country || 'UNKNOWN'}
            </span>
          </div>
          <div className="intel-row">
            <span className="intel-key">EVENTS</span>
            <span className="intel-val intel-val--num">{origin.hits || 1}</span>
          </div>
          <div className="intel-row">
            <span className="intel-key">COORDS</span>
            <span className="intel-val intel-val--coord">
              {origin.lat.toFixed(2)}° / {origin.lng.toFixed(2)}°
            </span>
          </div>
        </div>

        <button
          className="intel-action"
          disabled={!origin.ip}
          onClick={() => origin.ip && onIpClick?.(origin.ip)}
        >
          <span>OPEN FULL DOSSIER</span>
          <span className="intel-action-arrow">»</span>
        </button>
      </div>
    </>
  )
}

/* ── Main Map Component ─────────────────────────────── */
export default function WorldMap({ events, initialIds, config, onIpClick }) {
  const center = config ? [config.vps_lat, config.vps_lon] : [20, 0]
  const [selectedOrigin, setSelectedOrigin] = useState(null)

  const handleSelectOrigin = useCallback((o) => setSelectedOrigin(o), [])
  const handleCloseCallout = useCallback(() => setSelectedOrigin(null), [])

  return (
    <MapContainer
      center={center}
      zoom={2}
      className="world-map"
      zoomControl={true}
      scrollWheelZoom={true}
    >
      <TileLayer
        attribution='&copy; <a href="https://carto.com/">CARTO</a>'
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
      />

      {config && (
        <Marker position={[config.vps_lat, config.vps_lon]} icon={VPS_ICON}>
          <Popup>
            <b>{config.vps_label}</b>
            <br />
            TARGET_SERVER :: PORT 22
          </Popup>
        </Marker>
      )}

      <ParticleCanvas
        events={events}
        initialIds={initialIds}
        config={config}
        onSelectOrigin={handleSelectOrigin}
      />
      <IntelCallout
        origin={selectedOrigin}
        onIpClick={onIpClick}
        onClose={handleCloseCallout}
      />
    </MapContainer>
  )
}
