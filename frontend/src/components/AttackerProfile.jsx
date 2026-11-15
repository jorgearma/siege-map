import React, { useEffect, useState } from 'react'
import MitreBadge from './MitreBadge'
import { isKnownRoute } from '../config/knownRoutes'
import { PATTERNS, SEVERITY_COLOR, CONFIDENCE_COLOR } from '../lib/severity'

function StatusBadge({ status }) {
  if (!status) return null
  const color = status >= 200 && status < 300 ? '#00ff41'
              : status >= 300 && status < 400 ? '#00bfff'
              : status >= 400 && status < 500 ? '#ffd700'
              : '#ff2020'
  return (
    <span className="drawer-status-badge" style={{ color, borderColor: color + '55', background: color + '11' }}>
      {status}
    </span>
  )
}

function flag(code) {
  if (!code || code === 'XX') return '\uD83C\uDF10'
  return String.fromCodePoint(
    ...code
      .toUpperCase()
      .split('')
      .map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)
  )
}

const PATTERN_COLORS = PATTERNS

const STEP_COLOR = {
  contact: '#00d4ff', ssh: '#ff0040', http: '#ffd700', rate: '#ffb000', multi: '#ff7a1a',
  campaign: '#ff7a1a', persistence: '#9085e9', reputation: '#ffb000', alert: '#ff0040',
}

/** Where each point of the score comes from. */
function ScoreBreakdown({ parts }) {
  if (!parts?.length) return null
  return (
    <ul className="fo-score-parts">
      {parts.map((p) => (
        <li key={p.factor} title={`${p.factor}: ${p.points} of ${p.max} points`}>
          <span className="fo-score-factor">{p.factor.toUpperCase()}</span>
          <span className="fo-score-track">
            <span className="fo-score-fill" style={{ width: `${(p.points / p.max) * 100}%` }} />
          </span>
          <span className="fo-score-points">{p.points}/{p.max}</span>
          <span className="fo-score-detail">{p.detail}</span>
        </li>
      ))}
    </ul>
  )
}

const SPEED_COLORS = {
  BRUTE_FORCE: '#ff0040',
  MODERATE:    '#ffb000',
  SLOW_SCAN:   '#00d4ff',
}

function PipBoyMeter({ value, max = 100, color, label }) {
  const pct = Math.min((value / max) * 100, 100)
  const segments = 20
  const filledSegments = Math.round((pct / 100) * segments)
  return (
    <div className="pipboy-meter">
      <div className="pipboy-meter-header">
        <span className="pipboy-meter-label">{label}</span>
        <span className="pipboy-meter-value" style={{ color }}>{value}/{max}</span>
      </div>
      <div className="pipboy-meter-track">
        {Array.from({ length: segments }, (_, i) => (
          <div
            key={i}
            className={`pipboy-segment ${i < filledSegments ? 'pipboy-segment--filled' : ''}`}
            style={i < filledSegments ? { background: color, boxShadow: `0 0 4px ${color}66` } : {}}
          />
        ))}
      </div>
    </div>
  )
}

function VaultStatCard({ value, label, icon, color = 'var(--pip-green)' }) {
  return (
    <div className="vault-stat-card">
      <div className="vault-stat-icon">{icon}</div>
      <div className="vault-stat-data">
        <span className="vault-stat-number" style={{ color }}>{value}</span>
        <span className="vault-stat-name">{label}</span>
      </div>
      <div className="vault-stat-corner vault-stat-corner--tl" />
      <div className="vault-stat-corner vault-stat-corner--tr" />
      <div className="vault-stat-corner vault-stat-corner--bl" />
      <div className="vault-stat-corner vault-stat-corner--br" />
    </div>
  )
}

export default function AttackerProfile({ ip, onClose }) {
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    if (!ip) return
    setLoading(true)
    setError(null)
    setProfile(null)

    fetch(`/api/attacker/${ip}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then((data) => {
        setProfile(data)
        setActiveTab('overview')
        setLoading(false)
      })
      .catch((e) => {
        setError(e.message)
        setLoading(false)
      })
  }, [ip])

  const sshUsernames = (profile?.usernames_attempted || []).filter((u) => !u.startsWith('/') && !u.startsWith('POST ') && !u.startsWith('('))
  const httpRoutes = profile?.http_routes || []
  const hasSsh = sshUsernames.length > 0
  const hasHttp = httpRoutes.length > 0

  const patternMeta = PATTERN_COLORS[profile?.attack_pattern] || { color: '#00ff41', label: profile?.attack_pattern || '' }
  const speedColor = SPEED_COLORS[profile?.attack_speed] || '#00ff41'

  const sourceType = hasSsh && hasHttp ? 'mixed' : hasSsh ? 'ssh' : 'http'
  const accentColor = sourceType === 'ssh' ? '#ff0040' : sourceType === 'http' ? '#ffd700' : '#00d4ff'

  const threatColor = SEVERITY_COLOR[profile?.severity] || '#00ff41'

  return (
    <>
      <div className="attacker-drawer-backdrop" onClick={onClose} />
      <div className="attacker-drawer fo-drawer">
        <div className="fo-scanlines" />

        {/* ── HEADER ── */}
        <div className="fo-header">
          <div className="fo-header-left">
            <span className="fo-header-bracket">[</span>
            <span className="fo-title">THREAT DOSSIER</span>
            <span className="fo-header-bracket">]</span>
            <span className="fo-source-tag" style={{ color: accentColor, borderColor: `${accentColor}80` }}>
              {sourceType === 'mixed' ? 'SSH+HTTP' : sourceType === 'ssh' ? 'SSH' : 'HTTP'}
            </span>
          </div>
          <button className="fo-close" onClick={onClose}>
            <span className="fo-close-x">X</span>
          </button>
        </div>

        {loading && (
          <div className="fo-loading">
            <div className="fo-loading-bar" />
            <span>ACCESSING VAULT-TEC RECORDS...</span>
          </div>
        )}
        {error && (
          <div className="fo-error">
            <span className="fo-error-icon">[!]</span> TERMINAL ERROR: {error}
          </div>
        )}

        {profile && (
          <div className="drawer-body fo-body">

            {/* ── SUBJECT IDENTIFICATION ── */}
            <div className="fo-frame">
              <div className="fo-frame-label">SUBJECT IDENTIFICATION</div>
              <div className="fo-id-content">
                <div className="fo-ip-display">
                  <span className="fo-ip-prefix">IP:</span>
                  <span className="fo-ip-addr" style={{ color: accentColor }}>
                    {profile.ip}
                  </span>
                </div>
                {profile.ip.includes('xxx') ? (
                  /* IP anonimizada (visitante HTTP): sin enlaces externos */
                  <div className="fo-ext-links">
                    <span className="fo-link-btn">ANONYMIZED /24</span>
                  </div>
                ) : (
                  <div className="fo-ext-links">
                    <a className="fo-link-btn" href={`https://www.shodan.io/host/${profile.ip}`} target="_blank" rel="noopener noreferrer">
                      SHODAN
                    </a>
                    <a className="fo-link-btn" href={`https://www.abuseipdb.com/check/${profile.ip}`} target="_blank" rel="noopener noreferrer">
                      ABUSE DB
                    </a>
                  </div>
                )}
              </div>
              {profile.geo && (
                <div className="fo-geo-row">
                  <span className="fo-geo-flag">{flag(profile.geo.country_code)}</span>
                  <span className="fo-geo-loc">
                    {profile.geo.country}
                    {profile.geo.city && profile.geo.city !== 'Unknown' && ` // ${profile.geo.city}`}
                  </span>
                </div>
              )}
              {profile.geo?.org && (
                <div className="fo-org">ORG: {profile.geo.org}</div>
              )}
            </div>

            {/* ── THREAT LEVEL ── */}
            <div className="fo-frame">
              <div className="fo-frame-label">THREAT ASSESSMENT</div>
              <PipBoyMeter
                value={profile.threat_score}
                max={100}
                color={threatColor}
                label="DANGER LEVEL"
              />
              {profile.severity && (
                <div className="fo-badges">
                  <span className="fo-badge" style={{ borderColor: threatColor, color: threatColor }}>
                    SEVERITY: {profile.severity}
                  </span>
                </div>
              )}
              <ScoreBreakdown parts={profile.score_breakdown} />
            </div>

            {/* ── COMBAT STATS ── */}
            <div className="fo-frame">
              <div className="fo-frame-label">S.T.A.T.S.</div>
              <div className="vault-stats-grid">
                <VaultStatCard value={profile.total_attempts} label="TOTAL HITS" icon="+" color={accentColor} />
                <VaultStatCard value={sshUsernames.length} label="SSH USERS" icon=">" color="#ff0040" />
                <VaultStatCard value={httpRoutes.length} label="HTTP PATHS" icon="~" color="#ffd700" />
                <VaultStatCard value={profile.requests_per_minute} label="REQ / MIN" icon="#" color="var(--pip-green)" />
              </div>
            </div>

            {/* ── ABUSEIPDB ── */}
            {profile.abuse_confidence > 0 && (
              <div className="fo-frame">
                <div className="fo-frame-label">
                  ABUSEIPDB INTEL
                  <span className="fo-frame-sub">
                    {' '}// {profile.abuse_total_reports?.toLocaleString() || 0} reports
                  </span>
                </div>
                <PipBoyMeter
                  value={profile.abuse_confidence}
                  max={100}
                  color={profile.abuse_confidence > 50 ? '#ff0040' : '#ffb000'}
                  label="MALICIOUS CONFIDENCE"
                />
              </div>
            )}

            {/* ── CLASSIFICATION ── */}
            <div className="fo-frame">
              <div className="fo-frame-label">CLASSIFICATION</div>
              <div className="fo-badges">
                {patternMeta.label && (
                  <span className="fo-badge" style={{ borderColor: patternMeta.color, color: patternMeta.color }}>
                    {patternMeta.label}
                  </span>
                )}
                <span className="fo-badge" style={{ borderColor: speedColor, color: speedColor }}>
                  {profile.attack_speed?.replace('_', ' ')}
                </span>
                {profile.abuse_confidence > 50 && (
                  <span className="fo-badge fo-badge--danger">KNOWN THREAT</span>
                )}
              </div>
            </div>

            {/* ── LONG-TERM RECORD (SQLite) ── */}
            {(profile.days_active > 0 || profile.tags?.length > 0 || profile.greynoise) && (
              <div className="fo-frame">
                <div className="fo-frame-label">LONG-TERM RECORD</div>
                <div className="fo-record">
                  {profile.days_active > 0 && (
                    <div><span>ACTIVE DAYS</span><b>{profile.days_active}</b></div>
                  )}
                  {profile.first_seen_ever && (
                    <div><span>FIRST SEEN</span><b>{profile.first_seen_ever.slice(0, 10)}</b></div>
                  )}
                  {profile.auth_attempts > 0 && (
                    <div><span>LOGIN ATTEMPTS</span><b>{profile.auth_attempts.toLocaleString()}</b></div>
                  )}
                  {profile.net_type && profile.net_type !== 'unknown' && (
                    <div><span>NETWORK</span><b>{profile.net_type.toUpperCase()}</b></div>
                  )}
                </div>
                {profile.tags?.length > 0 && (
                  <div className="fo-badges">
                    {profile.tags.map((t) => (
                      <span key={t} className={`fo-badge${t === 'tor-exit' ? ' fo-badge--danger' : ''}`}>
                        {t.toUpperCase()}
                      </span>
                    ))}
                  </div>
                )}
                {profile.campaign_size > 1 && (
                  <p className="fo-record-note">
                    Shares its wordlist ({profile.campaign_usernames}…) with{' '}
                    <b>{profile.campaign_size - 1}</b> other address(es)
                    {profile.campaign_label && (
                      <>
                        {' — '}
                        <b style={{ color: CONFIDENCE_COLOR[profile.campaign_level] }}>
                          {profile.campaign_label}
                        </b>
                        , confidence {profile.campaign_confidence}/100
                      </>
                    )}
                  </p>
                )}
                {profile.greynoise && (
                  <p className="fo-record-note">
                    GreyNoise: <b>{profile.greynoise.classification || 'unknown'}</b>
                    {profile.greynoise.name && profile.greynoise.name !== 'unknown' ? ` · ${profile.greynoise.name}` : ''}
                    {profile.greynoise.noise ? ' · mass internet scanner' : ''}
                    {profile.greynoise.riot ? ' · known benign service' : ''}
                  </p>
                )}
              </div>
            )}

            {/* ── MITRE ATT&CK ── */}
            {profile.mitre_ttps?.length > 0 && (
              <div className="fo-frame">
                <div className="fo-frame-label">MITRE ATT&CK</div>
                <div className="fo-mitre-list">
                  {profile.mitre_ttps.map((ttp) => (
                    <MitreBadge key={ttp} ttp={ttp} />
                  ))}
                </div>
              </div>
            )}

            {/* ── TABS ── */}
            <div className="fo-tabs">
              <button
                className={`fo-tab ${activeTab === 'overview' ? 'fo-tab--active' : ''}`}
                onClick={() => setActiveTab('overview')}
              >
                OVERVIEW
              </button>
              {hasSsh && (
                <button
                  className={`fo-tab ${activeTab === 'ssh' ? 'fo-tab--active' : ''}`}
                  onClick={() => setActiveTab('ssh')}
                  style={activeTab === 'ssh' ? { '--tab-color': '#ff0040' } : {}}
                >
                  SSH [{sshUsernames.length}]
                </button>
              )}
              {hasHttp && (
                <button
                  className={`fo-tab ${activeTab === 'http' ? 'fo-tab--active' : ''}`}
                  onClick={() => setActiveTab('http')}
                  style={activeTab === 'http' ? { '--tab-color': '#ffd700' } : {}}
                >
                  HTTP [{httpRoutes.length}]
                </button>
              )}
            </div>

            {/* ── OVERVIEW TAB ── */}
            {activeTab === 'overview' && (
              <div className="fo-tab-content">
                <div className="fo-list-header">ATTACK NARRATIVE</div>
                <div className="fo-timeline">
                  {(profile.narrative || []).map((step, i) => (
                    <div className="fo-tl-entry" key={i}>
                      <span className="fo-tl-dot" style={{ background: STEP_COLOR[step.kind] }} />
                      <div className="fo-tl-data">
                        <span className="fo-tl-key">
                          {step.kind.toUpperCase()}
                          {step.ts ? ` · ${step.ts.slice(0, 16).replace('T', ' ')}` : ''}
                        </span>
                        <span className="fo-tl-val fo-tl-val--text">{step.text}</span>
                      </div>
                    </div>
                  ))}
                </div>
                {hasSsh && (
                  <div className="fo-summary-row">
                    <span className="fo-summary-icon" style={{ color: '#ff0040' }}>></span>
                    <span className="fo-summary-text">
                      Attempted <strong>{sshUsernames.length}</strong> SSH credentials
                    </span>
                  </div>
                )}
                {hasHttp && (
                  <div className="fo-summary-row">
                    <span className="fo-summary-icon" style={{ color: '#ffd700' }}>~</span>
                    <span className="fo-summary-text">
                      Probed <strong>{httpRoutes.length}</strong> HTTP endpoints
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* ── SSH TAB ── */}
            {activeTab === 'ssh' && hasSsh && (
              <div className="fo-tab-content">
                <div className="fo-list-header">USERNAMES ATTEMPTED ({sshUsernames.length})</div>
                <div className="fo-username-grid">
                  {sshUsernames.map((u) => (
                    <span key={u} className="fo-username">{u}</span>
                  ))}
                </div>
              </div>
            )}

            {/* ── HTTP TAB ── */}
            {activeTab === 'http' && hasHttp && (
              <div className="fo-tab-content">
                <div className="fo-list-header">ROUTES PROBED ({httpRoutes.length})</div>
                <div className="fo-routes-list">
                  {httpRoutes.map((r) => {
                    const known = isKnownRoute(r.path)
                    return (
                      <div key={r.path} className={`fo-route-row ${known ? 'fo-route-row--real' : ''}`}>
                        <span className={`fo-route-path ${known ? 'fo-route-path--real' : ''}`}>
                          {r.path}
                        </span>
                        <StatusBadge status={r.status} />
                        <span className="fo-route-count">x{r.count}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  )
}
