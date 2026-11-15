import React from 'react'
import useApi from '../hooks/useApi'

function flag(code) {
  if (!code || code === 'XX' || code.length !== 2) return ''
  return String.fromCodePoint(...code.toUpperCase().split('').map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

/** The most insistent SSH address of today, with what it has been trying. */
export default function BotOfTheDay({ onIpClick }) {
  const summary = useApi('/api/summary', 30000)
  const bot = summary?.bot_of_the_day
  if (!bot) return null
  return (
    <div className="stat-card botd">
      <div className="stat-card-header">BOT OF THE DAY</div>
      <div className="botd-main">
        <span className="botd-ip mono ip-clickable" onClick={() => onIpClick?.(bot.ip)}>{bot.ip}</span>
        <span className="botd-origin">{flag(bot.country_code)} {bot.country}</span>
      </div>
      <div className="botd-org">{bot.org}</div>
      <div className="botd-stats">
        <span><b>{(bot.attempts || bot.lines).toLocaleString()}</b> attempts today</span>
        <span><b>{bot.usernames}</b> usernames</span>
        {bot.days_active > 1 && <span><b>{bot.days_active}</b> days active</span>}
        {bot.campaign_size > 1 && <span>botnet of <b>{bot.campaign_size}</b></span>}
      </div>
      {bot.top_usernames?.length > 0 && (
        <div className="botd-users">
          {bot.top_usernames.map((u) => <span key={u} className="intel-chip">{u}</span>)}
        </div>
      )}
      {bot.tags?.length > 0 && (
        <div className="botd-users">
          {bot.tags.map((t) => <span key={t} className="intel-chip intel-chip--tag">{t}</span>)}
        </div>
      )}
    </div>
  )
}
