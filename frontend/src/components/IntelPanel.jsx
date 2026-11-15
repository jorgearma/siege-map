import React, { useEffect, useRef, useState } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Sankey,
} from 'recharts'
import useApi from '../hooks/useApi'
import HeatmapChart from './HeatmapChart'

/* ── Colour by job ────────────────────────────────────────────
   Categorical slots (validated for the dark surface, colour-blind safe in
   this order). Every entity keeps its colour whatever the filter shows. */
const SLOT = {
  blue: '#3987e5', orange: '#d95926', aqua: '#199e70', yellow: '#c98500',
  magenta: '#d55181', green: '#0ca30c', violet: '#9085e9', neutral: '#5d6f62',
}
const CATEGORY_COLOR = {
  default: SLOT.blue, service: SLOT.orange, iot: SLOT.aqua, devops: SLOT.yellow,
  crypto: SLOT.magenta, gaming: SLOT.green, other: SLOT.neutral,
}
const CATEGORY_LABEL = {
  default: 'Default accounts', service: 'Services / DBs', iot: 'IoT / routers',
  devops: 'DevOps', crypto: 'Crypto nodes', gaming: 'Game servers', other: 'Other',
}
const DEVICE_COLOR = { desktop: SLOT.blue, mobile: SLOT.orange, tablet: SLOT.aqua }
const CLASS_COLOR = {
  browser_verified: SLOT.blue, browser: SLOT.aqua, crawler: SLOT.yellow,
  tool: SLOT.violet, fake_browser: SLOT.magenta, scanner: SLOT.orange,
}
const CLASS_LABEL = {
  browser_verified: 'Browser (verified)', browser: 'Browser', crawler: 'Crawler',
  tool: 'Script / tool', fake_browser: 'Fake browser', scanner: 'Scanner',
}
const NET_LABEL = {
  hosting: 'Datacenter / hosting', residential: 'Residential ISP', mobile: 'Mobile network',
  proxy: 'Proxy / VPN', unknown: 'Unknown',
}
// Same meaning as on the map
const SOURCE_COLOR = { ssh: '#ff2020', http: '#ffd700', visit: '#1e90ff' }
const KIND_LABEL = { exploit: 'EXPLOIT', exposure: 'EXPOSURE', recon: 'RECON', c2: 'C2' }

const RANGES = [
  { value: 'today', label: 'TODAY' },
  { value: '7d', label: '7D' },
  { value: '30d', label: '30D' },
  { value: 'all', label: 'ALL' },
]
const TABS = [
  { key: 'visitors', label: 'VISITORS' },
  { key: 'ssh', label: 'SSH BOTS' },
  { key: 'campaigns', label: 'CAMPAIGNS' },
  { key: 'persistence', label: 'PERSISTENCE' },
  { key: 'cve', label: 'HTTP PROBES' },
  { key: 'flow', label: 'FLOW' },
  { key: 'activity', label: 'ACTIVITY' },
]

const fmt = (n) => (n == null ? '—' : typeof n === 'number' ? n.toLocaleString() : String(n))
const day = (ts) => (ts ? ts.slice(0, 10) : '—')

function flag(code) {
  if (!code || code === 'XX' || code.length !== 2) return ''
  return String.fromCodePoint(...code.toUpperCase().split('').map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

/* ── Building blocks ─────────────────────────────────────────── */

function Tile({ label, value, sub }) {
  return (
    <div className="intel-tile">
      <span className="intel-tile-value">{fmt(value)}</span>
      <span className="intel-tile-label">{label}</span>
      {sub && <span className="intel-tile-sub">{sub}</span>}
    </div>
  )
}

function Card({ title, note, children, wide }) {
  return (
    <section className={`intel-card${wide ? ' intel-card--wide' : ''}`}>
      <h4 className="intel-card-title">{title}</h4>
      {children}
      {note && <p className="intel-note">{note}</p>}
    </section>
  )
}

function Empty({ children = 'NO DATA YET' }) {
  return <div className="intel-empty">{children}</div>
}

/** Ranking: one series, so one colour; the label carries the identity. */
function BarList({ items, label = (i) => i.name, color, colorOf, limit = 10, onPick }) {
  const rows = (items || []).slice(0, limit)
  if (!rows.length) return <Empty />
  const max = Math.max(1, ...rows.map((r) => r.count))
  return (
    <ul className="intel-bars">
      {rows.map((r, i) => {
        const c = colorOf ? colorOf(r) : color
        return (
          <li key={i} title={`${label(r)}: ${fmt(r.count)}`}>
            <span
              className={`intel-bar-label${onPick ? ' ip-clickable' : ''}`}
              onClick={onPick ? () => onPick(r) : undefined}
            >
              {colorOf && <i className="intel-dot" style={{ background: c }} />}
              {label(r)}
            </span>
            <span className="intel-bar-track">
              <span className="intel-bar-fill" style={{ width: `${(r.count / max) * 100}%`, background: c }} />
            </span>
            <span className="intel-bar-value">{fmt(r.count)}</span>
          </li>
        )
      })}
    </ul>
  )
}

/** Part-to-whole: one bar split in segments, every segment named in the legend. */
function SplitBar({ items, colors, labels = {} }) {
  const rows = (items || []).filter((r) => r.count > 0)
  const total = rows.reduce((a, r) => a + r.count, 0)
  if (!total) return <Empty />
  return (
    <div className="intel-split">
      <div className="intel-split-bar">
        {rows.map((r) => (
          <span
            key={r.name}
            style={{ flexGrow: r.count, background: colors[r.name] || SLOT.neutral }}
            title={`${labels[r.name] || r.name}: ${fmt(r.count)} (${Math.round((r.count / total) * 100)}%)`}
          />
        ))}
      </div>
      <ul className="intel-legend">
        {rows.map((r) => (
          <li key={r.name}>
            <i className="intel-dot" style={{ background: colors[r.name] || SLOT.neutral }} />
            <span className="intel-legend-name">{labels[r.name] || r.name}</span>
            <span className="intel-legend-value">
              {fmt(r.count)} · {Math.round((r.count / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/* ── Tabs ────────────────────────────────────────────────────── */

function Visitors({ range }) {
  const d = useApi(`/api/intel/visitors?range=${range}`)
  if (!d) return <Empty>LOADING…</Empty>
  const classes = Object.entries(d.classes || {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
  return (
    <>
      <div className="intel-tiles">
        <Tile label="PEOPLE" value={d.people} sub="unique browsers per day" />
        <Tile label="VERIFIED" value={d.verified} sub="also loaded css / js / images" />
        <Tile label="AUTOMATED" value={d.automated} sub="crawlers, scripts, scanners" />
      </div>
      <div className="intel-grid">
        <Card title="DEVICES" note="Counted once per visitor and day, from the browser family only.">
          <SplitBar items={d.devices} colors={DEVICE_COLOR} />
        </Card>
        <Card title="WHO IS ON THE OTHER SIDE" note="“Browser” without assets is not proof of a bot: a CDN can serve the cached files.">
          <SplitBar items={classes} colors={CLASS_COLOR} labels={CLASS_LABEL} />
        </Card>
        <Card title="DEVICE · SYSTEM"><BarList items={d.device_os} color={SLOT.blue} /></Card>
        <Card title="BROWSER"><BarList items={d.browsers} color={SLOT.blue} /></Card>
        <Card title="ARRIVED FROM" note="Only the site is kept, never the full URL.">
          <BarList items={d.referrers} color={SLOT.blue} />
        </Card>
        <Card title="LANGUAGE" note="Needs the JSON log format (docs/nginx-log-format.md).">
          <BarList items={d.languages} color={SLOT.blue} label={(i) => i.name.toUpperCase()} />
        </Card>
        <Card title="COUNTRY"><BarList items={d.countries} color={SLOT.blue} /></Card>
        <Card title="NETWORK">
          <BarList items={d.networks} color={SLOT.blue} label={(i) => NET_LABEL[i.name] || i.name} />
        </Card>
      </div>
    </>
  )
}

function Ssh({ range }) {
  const d = useApi(`/api/intel/ssh?range=${range}&limit=20`)
  if (!d) return <Empty>LOADING…</Empty>
  return (
    <>
      <div className="intel-tiles">
        <Tile label="LOGIN ATTEMPTS" value={d.attempts} sub="real tries, not log lines" />
        <Tile label="DIFFERENT USERNAMES" value={d.distinct_usernames} />
        <Tile label="MOST TRIED" value={d.usernames?.[0]?.username || '—'}
              sub={d.usernames?.[0] ? `${fmt(d.usernames[0].count)} attempts` : ''} />
      </div>
      <div className="intel-grid">
        <Card title="MOST ATTEMPTED USERNAMES" wide>
          <BarList
            items={d.usernames} limit={20}
            label={(i) => i.username}
            colorOf={(i) => CATEGORY_COLOR[i.category] || SLOT.neutral}
          />
        </Card>
        <Card title="WHAT THEY HOPE TO FIND" note="Usernames grouped by the kind of machine they belong to.">
          <SplitBar
            items={(d.categories || []).map((c) => ({ ...c }))}
            colors={CATEGORY_COLOR} labels={CATEGORY_LABEL}
          />
        </Card>
        <Card title="NETWORK TYPE">
          <BarList items={d.net_types} color={SLOT.blue} label={(i) => NET_LABEL[i.name] || i.name} />
        </Card>
        <Card title="TOP NETWORKS (ASN)"><BarList items={d.networks} color={SLOT.blue} /></Card>
        <Card title="CLOUD PROVIDERS ABUSED"><BarList items={d.clouds} color={SLOT.blue} /></Card>
        <Card title="TOP COUNTRIES"><BarList items={d.countries} color={SLOT.blue} /></Card>
        <Card title="NOT EVEN SSH" note="What clients sent to port 22 instead of an SSH banner.">
          <BarList items={d.banners} color={SLOT.blue} />
        </Card>
      </div>
    </>
  )
}

const LEVEL_COLOR = { HIGH: '#ff0040', MEDIUM: '#ffb000', LOW: '#5d6f62' }

function Confidence({ c }) {
  const color = LEVEL_COLOR[c.level]
  return (
    <div className="intel-conf" title={c.evidence.join('\n')}>
      <span className="intel-conf-track">
        <span className="intel-conf-fill" style={{ width: `${c.confidence}%`, background: color }} />
      </span>
      <span className="intel-conf-num">{c.confidence}</span>
      <span className="intel-kind" style={{ color }}>{c.level}</span>
    </div>
  )
}

function Campaigns({ onIpClick }) {
  const d = useApi('/api/intel/campaigns?limit=25', 60000)
  const [open, setOpen] = useState(null)
  if (!d) return <Empty>LOADING…</Empty>
  if (!d.campaigns.length) {
    return (
      <Empty>
        NO GROUPS YET — one appears when two or more addresses try the same first{' '}
        {d.prefix_len} usernames in the same order, or many addresses hit one account at once
      </Empty>
    )
  }
  const confident = d.campaigns.filter((c) => c.level !== 'LOW').length
  return (
    <Card
      title="CAMPAIGNS" wide
      note={`Sharing a wordlist only proves the same tool, not the same operator. Each group is scored on independent evidence — how rare its wordlist is, whether its addresses arrived together, whether they share a network — and is called a coordinated campaign only when at least two agree. ${confident} of ${d.campaigns.length} groups pass MEDIUM. Click a row for its evidence.`}
    >
      <div className="intel-table-wrap">
        <table className="intel-table">
          <thead>
            <tr>
              <th>CONFIDENCE</th><th>VERDICT</th><th>TARGETS</th><th className="num">IPS</th>
              <th className="num">COUNTRIES</th><th className="num">ATTEMPTS</th>
              <th>SEEN</th><th>MEMBERS</th>
            </tr>
          </thead>
          <tbody>
            {d.campaigns.map((c) => (
              <React.Fragment key={c.fingerprint}>
                <tr className="intel-row-link" onClick={() => setOpen(open === c.fingerprint ? null : c.fingerprint)}>
                  <td><Confidence c={c} /></td>
                  <td>
                    <span className="strong">{c.label}</span>
                    {c.active && <span className="alert-live"> ● ACTIVE</span>}
                    <div className="mono dim">{c.fingerprint}</div>
                  </td>
                  <td>{c.usernames.map((u, i) => <span key={i} className="intel-chip">{u}</span>)}</td>
                  <td className="num strong">{fmt(c.ips)}</td>
                  <td className="num">
                    {c.countries}{' '}
                    <span className="dim">{c.top_countries.map((t) => flag(t.country_code)).join(' ')}</span>
                  </td>
                  <td className="num">{fmt(c.attempts)}</td>
                  <td className="dim">{day(c.first_seen)} → {day(c.last_seen)}</td>
                  <td>
                    {c.sample_ips.slice(0, 3).map((ip) => (
                      <span
                        key={ip} className="mono ip-clickable intel-ip"
                        onClick={(ev) => { ev.stopPropagation(); onIpClick?.(ip) }}
                      >
                        {ip}
                      </span>
                    ))}
                  </td>
                </tr>
                {open === c.fingerprint && (
                  <tr className="intel-evidence">
                    <td colSpan={8}>
                      <ul>
                        {c.evidence.map((line, i) => <li key={i}>{line}</li>)}
                      </ul>
                      <div className="intel-signals">
                        {Object.entries(c.signals).map(([name, value]) => (
                          <span key={name}>{name.toUpperCase()} <b>{Math.round(value * 100)}%</b></span>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function Persistence({ range, onIpClick }) {
  const d = useApi(`/api/intel/persistence?range=${range}`, 60000)
  if (!d) return <Empty>LOADING…</Empty>
  return (
    <>
      <div className="intel-tiles">
        <Tile label="NEW ADDRESSES" value={d.new} sub="never seen before" />
        <Tile label="CAME BACK" value={d.returning} sub="seen on an earlier day" />
        <Tile label="KNOWN SSH ADDRESSES" value={d.totals?.ssh} sub="since the sensor started" />
      </div>
      <div className="intel-grid">
        <Card title="MOST PERSISTENT" wide note="Ranked by the number of different days each address attacked.">
          {d.persistent.length ? (
            <div className="intel-table-wrap">
              <table className="intel-table">
                <thead>
                  <tr>
                    <th>ADDRESS</th><th className="num">DAYS</th><th className="num">ATTEMPTS</th>
                    <th className="num">USERS</th><th>ORIGIN</th><th>NETWORK</th><th>FIRST SEEN</th>
                  </tr>
                </thead>
                <tbody>
                  {d.persistent.map((p) => (
                    <tr key={p.ip}>
                      <td><span className="mono ip-clickable" onClick={() => onIpClick?.(p.ip)}>{p.ip}</span></td>
                      <td className="num strong">{p.days_active}</td>
                      <td className="num">{fmt(p.attempts)}</td>
                      <td className="num">{p.user_count}</td>
                      <td>{flag(p.country_code)} {p.country}</td>
                      <td className="dim">
                        {p.org}
                        {(p.tags || '').split(',').filter(Boolean).map((t) => (
                          <span key={t} className="intel-chip intel-chip--tag">{t}</span>
                        ))}
                      </td>
                      <td className="dim">{day(p.first_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <Empty />}
        </Card>
        <Card
          title="SAME NETWORK ON SSH AND HTTP" wide
          note="Visitor addresses are stored truncated, so this match is by /24 network, not by host."
        >
          {d.dual_vector.length ? (
            <div className="intel-table-wrap">
              <table className="intel-table">
                <thead>
                  <tr>
                    <th>NETWORK</th><th className="num">SSH ADDRESSES</th>
                    <th className="num">SSH ATTEMPTS</th><th className="num">HTTP HITS</th><th>ORIGIN</th>
                  </tr>
                </thead>
                <tbody>
                  {d.dual_vector.map((n) => (
                    <tr key={n.network}>
                      <td className="mono">{n.network}</td>
                      <td className="num">{n.ssh_ips}</td>
                      <td className="num">{fmt(n.ssh_attempts)}</td>
                      <td className="num">{fmt(n.http_hits)}</td>
                      <td>{flag(n.country_code)} {n.country} <span className="dim">· {n.org}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <Empty />}
        </Card>
      </div>
    </>
  )
}

function Probes({ range }) {
  const d = useApi(`/api/intel/signatures?range=${range}&limit=25`)
  if (!d) return <Empty>LOADING…</Empty>
  const max = Math.max(1, ...d.signatures.map((s) => s.count))
  return (
    <div className="intel-grid">
      <Card
        title="WHAT THE HTTP BOTS ARE LOOKING FOR" wide
        note="A match means the request has the shape of a known probe — not that this server is vulnerable."
      >
        {d.signatures.length ? (
          <div className="intel-table-wrap">
            <table className="intel-table">
              <thead>
                <tr><th>ID</th><th>WHAT</th><th>PRODUCT</th><th>KIND</th><th className="num">HITS</th><th /></tr>
              </thead>
              <tbody>
                {d.signatures.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">
                      {s.cve ? (
                        <a href={`https://nvd.nist.gov/vuln/detail/${s.id}`} target="_blank" rel="noopener noreferrer">
                          {s.id}
                        </a>
                      ) : <span className="dim">{s.id}</span>}
                    </td>
                    <td>{s.name}</td>
                    <td className="dim">{s.product}</td>
                    <td><span className={`intel-kind intel-kind--${s.kind}`}>{KIND_LABEL[s.kind] || s.kind}</span></td>
                    <td className="num strong">{fmt(s.count)}</td>
                    <td className="bar-cell">
                      <span className="intel-bar-track">
                        <span className="intel-bar-fill" style={{ width: `${(s.count / max) * 100}%`, background: SLOT.orange }} />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty />}
      </Card>
      <Card title="MOST PROBED PATHS">
        <BarList items={d.probes} color={SLOT.orange} label={(i) => i.path} limit={12} />
      </Card>
      <Card title="EVENT TYPES">
        <BarList items={d.event_types} color={SLOT.blue} limit={12} />
      </Card>
    </div>
  )
}

function SankeyNode({ x, y, width, height, payload, containerWidth }) {
  const right = x > containerWidth / 2
  return (
    <g>
      <rect x={x} y={y} width={width} height={Math.max(2, height)} fill="#3987e5" rx={1} />
      <text
        x={right ? x - 6 : x + width + 6} y={y + height / 2}
        textAnchor={right ? 'end' : 'start'} dominantBaseline="middle"
        className="intel-sankey-label"
      >
        {payload.name}
      </text>
    </g>
  )
}

function Flow() {
  const [hours, setHours] = useState(24)
  const d = useApi(`/api/intel/sankey?hours=${hours}`, 60000)
  const [box, setBox] = useState(900)
  const ready = d && d.links?.length > 0
  return (
    <Card
      title="COUNTRY → NETWORK → USERNAME" wide
      note="Width = SSH login attempts. Read left to right: where they come from, whose network they use, which account they go for."
    >
      <div className="intel-inline-filter">
        {[1, 24, 168].map((h) => (
          <button key={h} className={hours === h ? 'active' : ''} onClick={() => setHours(h)}>
            [{h === 1 ? '1H' : h === 24 ? '24H' : '7D'}]
          </button>
        ))}
      </div>
      {!d ? <Empty>LOADING…</Empty> : !ready ? <Empty /> : (
        <div className="intel-sankey" ref={(el) => el && el.clientWidth !== box && setBox(el.clientWidth)}>
          <ResponsiveContainer width="100%" height="100%">
            <Sankey
              data={d} nodePadding={14} nodeWidth={8} iterations={32}
              margin={{ top: 8, right: 8, bottom: 8, left: 8 }}
              link={{ stroke: '#3987e5', strokeOpacity: 0.28 }}
              node={<SankeyNode containerWidth={box} />}
            >
              <Tooltip
                contentStyle={{ background: '#0a110a', border: '1px solid #00ff4130', borderRadius: 2, fontSize: 11 }}
                itemStyle={{ color: '#c8e6cf' }}
              />
            </Sankey>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  )
}

function Activity({ range }) {
  const d = useApi('/api/intel/trend?days=30', 60000)
  const rows = (d?.days || []).map((r) => ({
    day: r.day.slice(5), ssh: r.ssh || 0, http: r.http || 0, visit: r.visit || 0,
  }))
  return (
    <div className="intel-grid">
      <Card title="EVENTS PER DAY · LAST 30 DAYS" wide>
        <ul className="intel-legend intel-legend--row">
          <li><i className="intel-dot" style={{ background: SOURCE_COLOR.ssh }} />SSH</li>
          <li><i className="intel-dot" style={{ background: SOURCE_COLOR.http }} />HTTP probes</li>
          <li><i className="intel-dot" style={{ background: SOURCE_COLOR.visit }} />Visits</li>
        </ul>
        <div className="intel-chart">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={rows} margin={{ top: 6, right: 12, bottom: 0, left: -8 }}>
              <CartesianGrid stroke="#00ff4112" vertical={false} />
              <XAxis dataKey="day" stroke="#00ff4140" fontSize={10} tickLine={false} minTickGap={24} />
              <YAxis stroke="#00ff4140" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#0a110a', border: '1px solid #00ff4130', borderRadius: 2, fontSize: 11 }}
                labelStyle={{ color: '#8fb89a' }} itemStyle={{ color: '#c8e6cf' }}
              />
              <Line type="monotone" dataKey="ssh" name="SSH" stroke={SOURCE_COLOR.ssh} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="http" name="HTTP probes" stroke={SOURCE_COLOR.http} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="visit" name="Visits" stroke={SOURCE_COLOR.visit} strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>
      <Card title="WHEN THEY ATTACK · DAY × HOUR" wide note="Server local time. Darker = more events.">
        <div className="intel-heatmap"><HeatmapChart range={range} /></div>
      </Card>
    </div>
  )
}

/* ── Panel ───────────────────────────────────────────────────── */

export default function IntelPanel({ onIpClick }) {
  // ?tab=ssh opens a tab directly (shareable link)
  const [tab, setTab] = useState(() => {
    const wanted = new URLSearchParams(window.location.search).get('tab')
    return TABS.some((t) => t.key === wanted) ? wanted : 'visitors'
  })
  const [range, setRange] = useState('7d')
  const ranged = !['campaigns', 'flow'].includes(tab)
  const rootRef = useRef(null)

  // Other panels can ask for a tab (e.g. the campaigns summary next to the chart)
  useEffect(() => {
    function onAsk(ev) {
      if (TABS.some((t) => t.key === ev.detail)) {
        setTab(ev.detail)
        rootRef.current?.scrollIntoView({ behavior: 'smooth' })
      }
    }
    window.addEventListener('siege:intel-tab', onAsk)
    return () => window.removeEventListener('siege:intel-tab', onAsk)
  }, [])

  // The panel does not exist yet when the browser resolves "#intel"
  useEffect(() => {
    if (window.location.hash === '#intel') rootRef.current?.scrollIntoView()
  }, [])

  return (
    <section className="intel-panel" id="intel" ref={rootRef}>
      <div className="intel-head">
        <h3 className="intel-heading">
          <span className="label-bracket">[</span>INTEL<span className="label-bracket">]</span>
          <span className="intel-heading-sub">long-term telemetry · stored in SQLite</span>
        </h3>
        <div className={`intel-range${ranged ? '' : ' intel-range--off'}`}>
          <span className="selector-label">RANGE:</span>
          {RANGES.map((r) => (
            <button
              key={r.value} disabled={!ranged}
              className={range === r.value ? 'active' : ''}
              onClick={() => setRange(r.value)}
            >
              [{r.label}]
            </button>
          ))}
        </div>
      </div>

      <div className="intel-tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.key} role="tab" aria-selected={tab === t.key}
            className={tab === t.key ? 'active' : ''}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="intel-body">
        {tab === 'visitors' && <Visitors range={range} />}
        {tab === 'ssh' && <Ssh range={range} />}
        {tab === 'campaigns' && <Campaigns onIpClick={onIpClick} />}
        {tab === 'persistence' && <Persistence range={range} onIpClick={onIpClick} />}
        {tab === 'cve' && <Probes range={range} />}
        {tab === 'flow' && <Flow />}
        {tab === 'activity' && <Activity range={range} />}
      </div>
    </section>
  )
}
