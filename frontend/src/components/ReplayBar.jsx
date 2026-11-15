import React from 'react'

/** Progress HUD of the time-lapse: clock, counter and a volume strip. */
export default function ReplayBar({ replay }) {
  if (!replay.active) return null
  const totals = replay.totals || []
  const max = Math.max(1, ...totals)
  const clock = replay.clock
    ? replay.clock.toLocaleString('en-GB', { weekday: 'short', hour: '2-digit', minute: '2-digit' })
    : '—'
  return (
    <div className="replay-bar" role="status">
      <div className="replay-head">
        <span className="replay-title">
          {replay.loading ? 'LOADING HISTORY…' : replay.done ? `LAST ${replay.hours}H · COMPLETE` : `REPLAY · LAST ${replay.hours}H`}
        </span>
        <span className="replay-clock">{clock}</span>
        <span className="replay-count">
          {(replay.shown || 0).toLocaleString()} / {(replay.total || 0).toLocaleString()} events
        </span>
        {replay.done && (
          <button className="replay-btn" onClick={replay.start}>[AGAIN]</button>
        )}
        <button className="replay-btn" onClick={replay.stop}>[BACK TO LIVE]</button>
      </div>
      <div className="replay-strip" aria-hidden="true">
        {totals.map((n, i) => (
          <span
            key={i}
            className={i / totals.length <= (replay.progress || 0) ? 'on' : ''}
            style={{ height: `${Math.max(6, (n / max) * 100)}%` }}
          />
        ))}
      </div>
    </div>
  )
}
