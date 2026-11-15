import React, { useEffect, useState } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

import ThreatBrief from './ThreatBrief'

const GRID_COLOR = '#00ff4112'
const AXIS_COLOR = '#00ff4140'
const TOOLTIP_BG = '#0a110a'
const TOOLTIP_BORDER = '#00ff4130'

export default function Charts({ window: timeWindow }) {
  const [timeline, setTimeline] = useState([])

  useEffect(() => {
    const qs = timeWindow ? `?window=${timeWindow}` : ''
    let active = true

    async function load() {
      try {
        const tRes = await fetch(`/api/stats/timeline${qs}`)
        if (active) {
          if (tRes.ok) {
            const tData = await tRes.json()
            setTimeline(
              tData.timeline.map((t) => ({
                time: t.minute.slice(11),
                count: t.count,
              }))
            )
          }
        }
      } catch {
        // retry next cycle
      }
    }

    load()
    const id = setInterval(load, 10000)
    return () => {
      active = false
      clearInterval(id)
    }
  }, [timeWindow])

  return (
    <div className="charts-grid">
      <div className="chart-card">
        <h4>EVENTS_PER_MINUTE</h4>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timeline}>
            <defs>
              <linearGradient id="greenGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#00ff41" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#00ff41" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={GRID_COLOR}
              vertical={false}
            />
            <XAxis
              dataKey="time"
              stroke={AXIS_COLOR}
              fontSize={10}
              fontFamily="Share Tech Mono, monospace"
              tickLine={false}
            />
            <YAxis
              stroke={AXIS_COLOR}
              fontSize={10}
              fontFamily="Share Tech Mono, monospace"
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                background: TOOLTIP_BG,
                border: `1px solid ${TOOLTIP_BORDER}`,
                borderRadius: 2,
                fontFamily: 'Share Tech Mono, monospace',
                fontSize: 11,
                color: '#00ff41',
              }}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#00ff41"
              fill="url(#greenGrad)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <ThreatBrief window={timeWindow} />
    </div>
  )
}
