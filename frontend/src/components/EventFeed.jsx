import React, { useMemo } from 'react'
import MitreBadge from './MitreBadge'

const EVENT_LABELS = {
  // SSH
  failed_password:    'FAIL_PASS',
  invalid_user:       'INVL_USER',
  connection_closed:  'CONN_CLOS',
  disconnected:       'DISCONN',
  max_auth_exceeded:  'MAX_AUTH',
  received_disconnect:'RECV_DC',
  bad_protocol:       'BAD_PROTO',
  // HTTP threats
  git_exposure:       'GIT_PROBE',
  secret_probe:       'SEC_PROBE',
  cms_scan:           'CMS_SCAN',
  php_probe:          'PHP_PROBE',
  path_traversal:     'PATH_TRAV',
  exploit_attempt:    'EXPLOIT',
  scanner:            'SCANNER',
  post_probe:         'POST_PROBE',
  // HTTP noise
  crawler:            'CRAWLER',
  auto_tool:          'AUTO_TOOL',
  http_error:         'HTTP_ERR',
  // Real traffic
  visit_desktop:      'VISIT',
  visit_mobile:       'VISIT',
  visit_tablet:       'VISIT',
}

const EVENT_COLORS = {
  // SSH — red spectrum
  failed_password:    '#ff0040',
  invalid_user:       '#ff6600',
  connection_closed:  '#ffb000',
  disconnected:       '#cc00ff',
  max_auth_exceeded:  '#ff0020',
  received_disconnect:'#00d4ff',
  bad_protocol:       '#ff00aa',
  // HTTP threats — orange/amber spectrum
  git_exposure:       '#ff8c00',
  secret_probe:       '#ffd700',
  cms_scan:           '#ff6347',
  php_probe:          '#ff4500',
  path_traversal:     '#dc143c',
  exploit_attempt:    '#ff1493',
  scanner:            '#39ff14',
  post_probe:         '#ff9800',
  // HTTP noise — purple/gray spectrum
  crawler:            '#b388ff',
  auto_tool:          '#78909c',
  http_error:         '#ef5350',
  // Real traffic — cyan spectrum
  visit_desktop:      '#00bfff',
  visit_mobile:       '#00e5ff',
  visit_tablet:       '#40e0d0',
}

const DEVICE_ICONS = {
  visit_desktop: '\uD83D\uDDA5',
  visit_mobile:  '\uD83D\uDCF1',
  visit_tablet:  '\u2B1C',
}

const SOURCE_ICONS = {
  ssh: '\u26A1',
  http: '\uD83C\uDF10',
}

function getSourceFilter(event) {
  if (event.source === 'ssh') return 'ssh'
  if (event.event_type?.startsWith('visit_')) return 'visits'
  if (event.source === 'http') return 'http'
  return 'ssh'
}

function formatTime(ts) {
  if (!ts) return '??:??:??'
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false })
  } catch {
    return ts.slice(11, 19)
  }
}

function HttpStatusBadge({ status }) {
  if (!status) return null
  const success = status >= 200 && status < 300
  return (
    <span
      className="event-http-status"
      style={{
        color: success ? '#00ff41' : '#555',
        fontWeight: success ? 'bold' : 'normal',
        textShadow: success ? '0 0 6px #00ff4166' : 'none',
      }}
    >
      {success ? `\u2713${status}` : status}
    </span>
  )
}

export default function EventFeed({ events, onIpClick, activeFilter = 'all' }) {
  const filtered = useMemo(() => {
    return activeFilter === 'all'
      ? events
      : events.filter((e) => getSourceFilter(e) === activeFilter)
  }, [events, activeFilter])

  return (
    <div className="event-feed">
      <div className="event-feed-header">
        <span className="feed-title">LIVE_TERMINAL</span>
        <span className="event-cursor" />
      </div>

      <div className="event-list">
        {filtered.slice(0, 60).map((e) => {
          const isVisit = e.event_type?.startsWith('visit_')
          const isHttpAttack = e.source === 'http' && !isVisit
          const sourceIcon = isVisit
            ? (DEVICE_ICONS[e.event_type] || '\uD83D\uDC41')
            : (SOURCE_ICONS[e.source] || '\u26A1')

          return (
            <div
              key={e.id}
              className={`event-item ${isVisit ? 'event-visit' : ''} ${isHttpAttack ? 'event-http-attack' : ''}`}
            >
              <span className="event-time">{formatTime(e.timestamp)}</span>
              <span className="event-source-icon" title={e.source}>{sourceIcon}</span>
              <span
                className="event-badge"
                style={{ backgroundColor: EVENT_COLORS[e.event_type] || '#00ff41' }}
              >
                {EVENT_LABELS[e.event_type] || e.event_type}
              </span>
              {e.source === 'http' && <HttpStatusBadge status={e.http_status} />}
              <div className="event-details">
                <span
                  className="event-ip ip-clickable"
                  onClick={() => onIpClick?.(e.ip)}
                  title={`View profile for ${e.ip}`}
                >
                  {e.ip}
                </span>
                <span className="event-arrow">{'>>'}</span>
                <span className={`event-user ${isVisit ? 'event-user-visit' : ''}`}>
                  {e.username}
                </span>
              </div>
              {e.geo && e.geo.country_code !== 'XX' && (
                <span className="event-geo">{e.geo.country_code}</span>
              )}
              {e.mitre_ttps?.length > 0 && (
                <span className="event-ttp-inline">
                  {e.mitre_ttps.filter((t) => t !== 'T1021.004').map((t) => (
                    <MitreBadge key={t} ttp={t} />
                  ))}
                </span>
              )}
            </div>
          )
        })}
        {filtered.length === 0 && (
          <div className="event-empty">
            {activeFilter === 'all' ? 'AWAITING_EVENTS...' : `NO_${activeFilter.toUpperCase()}_EVENTS`}
          </div>
        )}
      </div>
    </div>
  )
}
