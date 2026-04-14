import React, { useEffect, useState, useRef } from 'react'

const DAYS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN']
const HOURS = Array.from({ length: 24 }, (_, i) => i)

export default function HeatmapChart({ window: timeWindow }) {
  const [grid, setGrid] = useState(null)
  const intervalRef = useRef(null)

  useEffect(() => {
    const qs = timeWindow ? `?window=${timeWindow}` : ''
    let active = true

    async function load() {
      try {
        const res = await fetch(`/api/stats/heatmap${qs}`)
        if (res.ok && active) {
          const data = await res.json()
          setGrid(data.heatmap)
        }
      } catch {
        // retry next cycle
      }
    }

    load()
    intervalRef.current = setInterval(load, 30000)
    return () => {
      active = false
      clearInterval(intervalRef.current)
    }
  }, [timeWindow])

  if (!grid) {
    return (
      <div className="heatmap-loading">LOADING_ATTACK_MATRIX...</div>
    )
  }

  const maxVal = Math.max(1, ...grid.flatMap((row) => row))
  const now = new Date()
  const currentHour = now.getHours()
  const currentDay = (now.getDay() + 6) % 7 // convert Sun=0 to Mon=0

  return (
    <>
      {/* Hour labels */}
      <div className="heatmap-hour-labels">
        <div className="heatmap-day-spacer" />
        {HOURS.map((h) => (
          <div
            key={h}
            className={`heatmap-hour-label ${h === currentHour ? 'current' : ''}`}
          >
            {h % 6 === 0 ? String(h).padStart(2, '0') : ''}
          </div>
        ))}
      </div>

      {/* Grid rows */}
      {DAYS.map((day, dayIdx) => (
        <div key={day} className="heatmap-row">
          <div className={`heatmap-day-label ${dayIdx === currentDay ? 'current' : ''}`}>
            {day}
          </div>
          {HOURS.map((hour) => {
            const count = grid[dayIdx][hour]
            const intensity = count / maxVal
            const isCurrent = dayIdx === currentDay && hour === currentHour
            return (
              <div
                key={hour}
                className={`heatmap-cell ${isCurrent ? 'current-cell' : ''}`}
                style={{ '--intensity': intensity }}
                title={`${day} ${String(hour).padStart(2, '0')}:00 — ${count} events`}
              />
            )
          })}
        </div>
      ))}
    </>
  )
}
