import React, { useMemo } from 'react'

const FILTERS = [
  { key: 'all',    label: 'ALL' },
  { key: 'ssh',    label: 'SSH \u26A1' },
  { key: 'http',   label: 'HTTP \uD83D\uDEE1' },
  { key: 'visits', label: 'VISITS \uD83D\uDC41' },
]

function getSourceFilter(event) {
  if (event.source === 'ssh') return 'ssh'
  if (event.event_type?.startsWith('visit_')) return 'visits'
  if (event.source === 'http') return 'http'
  return 'ssh'
}

function formatTime(ts) {
  if (!ts) return '??:??:??'
  try { return new Date(ts).toLocaleTimeString('en-US', { hour12: false }) }
  catch { return ts.slice(11, 19) }
}

export default function FeedFilters({ events, activeFilter, onChange }) {
  const counts = useMemo(() => {
    const c = { all: events.length, ssh: 0, http: 0, visits: 0 }
    events.forEach((e) => {
      const src = getSourceFilter(e)
      c[src] = (c[src] || 0) + 1
    })
    return c
  }, [events])

  const streamed = useMemo(() => {
    const list = activeFilter === 'all'
      ? events
      : events.filter((e) => getSourceFilter(e) === activeFilter)
    return list.slice(0, 80)
  }, [events, activeFilter])

  return (
    <div className="hack-console">
      <div className="hack-console-header">
        <span className="hack-dot hack-dot-red" />
        <span className="hack-dot hack-dot-yellow" />
        <span className="hack-dot hack-dot-green" />
        <span className="hack-console-title">root@honeypot:~#</span>
        <div className="feed-filters feed-filters-panel">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              className={`feed-filter-btn ${activeFilter === f.key ? 'active' : ''}`}
              onClick={() => onChange(f.key)}
            >
              <span className="filter-label">{f.label}</span>
              <span className="filter-count">{counts[f.key] || 0}</span>
            </button>
          ))}
        </div>
      </div>
        {streamed.length === 0 ? (
          <div className="hack-line empty">
            <span className="hack-prompt">$</span>
            <span className="hack-cursor">_</span>
          </div>
        ) : (
          streamed.map((e) => (
            <div key={e.id} className="hack-line">
              <span className="hack-ts">{formatTime(e.timestamp)}</span>
              <span className="hack-prompt">$</span>
              <span className="hack-src">{e.source || '--'}</span>
              <span className="hack-type">[{e.event_type}]</span>
              <span className="hack-ip">{e.ip}</span>
              <span className="hack-sep">&rarr;</span>
              <span className="hack-user">{e.username || '-'}</span>
              {e.geo?.country_code && e.geo.country_code !== 'XX' && (
                <span className="hack-geo">{e.geo.country_code}</span>
              )}
            </div>
          ))
      )}
    </div>
  )
}

export { getSourceFilter }
