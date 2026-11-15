import React, { useEffect, useRef, useState } from 'react'

async function triggerDownload(url, filename) {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const blob = await res.blob()
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = filename
  link.click()
  URL.revokeObjectURL(link.href)
}

/** One [EXPORT] button in the header; the formats live in its menu. */
export default function ExportPanel({ window: timeWindow }) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(null)
  const [error, setError] = useState(null)
  const rootRef = useRef(null)

  const qs = timeWindow ? `?window=${timeWindow}` : ''
  const scope = timeWindow ? `last ${timeWindow}` : 'live window'
  const items = [
    { key: 'stix', label: 'STIX 2.1', ext: '.json', note: `indicators + ATT&CK · ${scope}`,
      url: `/api/export/stix${qs}`, file: 'stix_bundle.json' },
    { key: 'csv', label: 'EVENTS', ext: '.csv', note: `one row per event · ${scope}`,
      url: `/api/export/csv${qs}`, file: 'siege_events.csv' },
    { key: 'report', label: 'THREAT REPORT', ext: '.json', note: `top attackers and patterns · ${scope}`,
      url: `/api/export/report${qs}`, file: 'threat_report.json' },
    { key: 'md', label: 'EXECUTIVE REPORT', ext: '.md', note: 'readable summary · last 30 days',
      url: '/api/export/report.md?range=30d', file: 'threat_report.md' },
    { key: 'block', label: 'BLOCKLIST', ext: '.txt', note: 'repeat SSH offenders · last 7 days',
      url: '/api/export/blocklist', file: 'siege_blocklist.txt' },
  ]

  // Close on a click outside or Escape
  useEffect(() => {
    if (!open) return undefined
    function onDown(ev) { if (!rootRef.current?.contains(ev.target)) setOpen(false) }
    function onKey(ev) { if (ev.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  async function handle(item) {
    setLoading(item.key)
    setError(null)
    try {
      await triggerDownload(item.url, item.file)
      setOpen(false)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="export-panel" ref={rootRef}>
      <button
        className={`hdr-btn hdr-btn--cyan${open ? ' active' : ''}`}
        aria-haspopup="menu" aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        [EXPORT <span className="hdr-caret">{open ? '▴' : '▾'}</span>]
      </button>
      {open && (
        <div className="export-menu" role="menu">
          <div className="export-menu-title">DOWNLOAD</div>
          {items.map((item) => (
            <button
              key={item.key} role="menuitem" className="export-item"
              disabled={loading !== null} onClick={() => handle(item)}
            >
              <span className="export-item-label">
                {loading === item.key ? 'EXPORTING…' : item.label}
                <span className="export-item-ext">{item.ext}</span>
              </span>
              <span className="export-item-note">{item.note}</span>
            </button>
          ))}
          {error && <div className="export-error">ERR: {error}</div>}
        </div>
      )}
    </div>
  )
}
