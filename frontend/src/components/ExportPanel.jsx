import React, { useState } from 'react'

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

export default function ExportPanel({ window: timeWindow }) {
  const [loading, setLoading] = useState(null)
  const [error, setError] = useState(null)

  const qs = timeWindow ? `?window=${timeWindow}` : ''

  async function handle(key, url, filename) {
    setLoading(key)
    setError(null)
    try {
      await triggerDownload(url, filename)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="export-panel">
      <button
        className="export-btn"
        disabled={loading !== null}
        onClick={() => handle('stix', `/api/export/stix${qs}`, 'stix_bundle.json')}
      >
        {loading === 'stix' ? 'EXPORTING...' : '[EXPORT_STIX]'}
      </button>
      <button
        className="export-btn"
        disabled={loading !== null}
        onClick={() => handle('csv', `/api/export/csv${qs}`, 'ssh_events.csv')}
      >
        {loading === 'csv' ? 'EXPORTING...' : '[EXPORT_CSV]'}
      </button>
      <button
        className="export-btn"
        disabled={loading !== null}
        onClick={() => handle('report', `/api/export/report${qs}`, 'threat_report.json')}
      >
        {loading === 'report' ? 'GENERATING...' : '[THREAT_REPORT]'}
      </button>
      {error && <span className="export-error">ERR: {error}</span>}
    </div>
  )
}
