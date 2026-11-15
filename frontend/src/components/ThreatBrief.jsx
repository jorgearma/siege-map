import React, { useState } from 'react'
import useApi from '../hooks/useApi'
import { CONFIDENCE_COLOR } from '../lib/severity'

const TACTIC_COLOR = {
  'Credential Access': '#ff0040',
  'Initial Access': '#ff7a1a',
  Reconnaissance: '#00d4ff',
}

function openCampaigns() {
  window.dispatchEvent(new CustomEvent('siege:intel-tab', { detail: 'campaigns' }))
}

function Campaigns() {
  const d = useApi('/api/intel/campaigns?limit=5', 30000)
  if (!d) return <div className="brief-empty">LOADING…</div>
  if (!d.campaigns.length) {
    return <div className="brief-empty">NO GROUPS YET — addresses acting together will show up here</div>
  }
  return (
    <ul className="brief-list">
      {d.campaigns.map((c) => {
        const color = CONFIDENCE_COLOR[c.level]
        return (
          <li key={c.fingerprint} className="brief-row brief-row--link" onClick={openCampaigns} title={c.evidence.join('\n')}>
            <span className="brief-conf">
              <span className="brief-track"><span className="brief-fill" style={{ width: `${c.confidence}%`, background: color }} /></span>
              <span className="brief-num">{c.confidence}</span>
            </span>
            <span className="brief-main">
              <span className="brief-label" style={{ color }}>{c.label.toUpperCase()}</span>
              {c.active && <span className="alert-live"> ● ACTIVE</span>}
              <span className="brief-sub">{c.usernames.slice(0, 4).join(' · ')}</span>
            </span>
            <span className="brief-count"><b>{c.ips}</b> IPs</span>
          </li>
        )
      })}
    </ul>
  )
}

function Mitre({ window: timeWindow }) {
  const d = useApi(`/api/stats/mitre${timeWindow ? `?window=${timeWindow}` : ''}`, 15000)
  if (!d) return <div className="brief-empty">LOADING…</div>
  if (!d.techniques.length) return <div className="brief-empty">NO ACTIVITY IN THIS WINDOW</div>
  const max = Math.max(...d.techniques.map((t) => t.count))
  return (
    <ul className="brief-list">
      {d.techniques.map((t) => (
        <li key={t.id} className="brief-row" title={`${t.tactic}: ${t.name}`}>
          <span className="brief-ttp">{t.id}</span>
          <span className="brief-main">
            <span className="brief-label">{t.name}</span>
            <span className="brief-track brief-track--wide">
              <span className="brief-fill" style={{ width: `${(t.count / max) * 100}%`, background: TACTIC_COLOR[t.tactic] || '#00ff41' }} />
            </span>
          </span>
          <span className="brief-count"><b>{t.count.toLocaleString()}</b> IPs</span>
        </li>
      ))}
    </ul>
  )
}

/** Who is coordinated, and which techniques are in use. */
export default function ThreatBrief({ window: timeWindow }) {
  const [view, setView] = useState('campaigns')
  return (
    <div className="chart-card brief-card">
      <div className="brief-head">
        <h4>{view === 'campaigns' ? 'TOP_CAMPAIGNS' : 'MITRE_ATT&CK'}</h4>
        <div className="brief-switch" role="group" aria-label="Panel content">
          <button className={view === 'campaigns' ? 'active' : ''} onClick={() => setView('campaigns')}>[CAMPAIGNS]</button>
          <button className={view === 'mitre' ? 'active' : ''} onClick={() => setView('mitre')}>[MITRE]</button>
        </div>
      </div>
      <div className="brief-body">
        {view === 'campaigns' ? <Campaigns /> : <Mitre window={timeWindow} />}
      </div>
    </div>
  )
}
