import React, { useEffect, useState } from 'react'
import useApi from '../hooks/useApi'

/**
 * First screen for someone who lands here without context (a recruiter
 * following a portfolio link): what this is, three live numbers, and where
 * the code is. One click and it gets out of the way.
 */

const COPY = {
  es: {
    kicker: 'SENSOR EN VIVO',
    title: 'Esto es lo que recibe un servidor por estar conectado a internet.',
    body: 'siege-map lee en tiempo real los logs de SSH y de nginx de mi VPS, geolocaliza cada intento, lo clasifica (MITRE ATT&CK, CVE) y lo dibuja. Nadie ha invitado a estos bots: es el ruido de fondo de internet.',
    attempts: 'intentos de login por SSH',
    ips: 'direcciones distintas',
    countries: 'países',
    since: 'desde',
    top: 'Usuario más probado',
    today: 'hoy',
    enter: 'VER EL PANEL',
    code: 'CÓDIGO EN GITHUB',
    how: 'Cómo funciona',
    steps: [
      'Un backend en FastAPI sigue los logs con tail -F y los parsea con regex.',
      'Cada evento se geolocaliza, se clasifica y se guarda agregado en SQLite.',
      'El navegador lo recibe por WebSocket y lo pinta en un globo dibujado en canvas.',
    ],
    privacy: 'Las IPs de los visitantes de la web se truncan antes de guardarse. Las de los bots de SSH se muestran completas.',
    lang: 'EN',
  },
  en: {
    kicker: 'LIVE SENSOR',
    title: 'This is what a server gets just for being on the internet.',
    body: 'siege-map reads the SSH and nginx logs of my VPS in real time, geolocates every attempt, classifies it (MITRE ATT&CK, CVE) and draws it. Nobody invited these bots: this is the background noise of the internet.',
    attempts: 'SSH login attempts',
    ips: 'different addresses',
    countries: 'countries',
    since: 'since',
    top: 'Most tried username',
    today: 'today',
    enter: 'OPEN THE DASHBOARD',
    code: 'SOURCE ON GITHUB',
    how: 'How it works',
    steps: [
      'A FastAPI backend follows the logs with tail -F and parses them with regex.',
      'Every event is geolocated, classified and stored as aggregates in SQLite.',
      'The browser receives it over a WebSocket and paints it on a canvas-drawn globe.',
    ],
    privacy: 'Website visitor IPs are truncated before being stored. SSH bot IPs are shown in full.',
    lang: 'ES',
  },
}

function CountUp({ value }) {
  const [shown, setShown] = useState(0)
  useEffect(() => {
    if (value == null) return undefined
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setShown(value)
      return undefined
    }
    const from = shown
    const t0 = performance.now()
    let raf
    const step = (now) => {
      const k = Math.min(1, (now - t0) / 900)
      setShown(Math.round(from + (value - from) * (1 - Math.pow(1 - k, 3))))
      if (k < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value])
  return <>{value == null ? '—' : shown.toLocaleString()}</>
}

export default function Landing({ onEnter }) {
  const summary = useApi('/api/summary', 15000)
  const [lang, setLang] = useState(() => (navigator.language || 'es').toLowerCase().startsWith('es') ? 'es' : 'en')
  const t = COPY[lang]
  const all = summary?.all_time

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' || e.key === 'Enter') onEnter() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onEnter])

  return (
    <div className="landing" role="dialog" aria-modal="true" aria-label="siege-map">
      <div className="landing-box">
        <div className="landing-top">
          <span className="landing-kicker"><i className="status-dot" /> {t.kicker}</span>
          <button className="landing-lang" onClick={() => setLang(lang === 'es' ? 'en' : 'es')}>[{t.lang}]</button>
        </div>

        <h2 className="landing-title">{t.title}</h2>
        <p className="landing-body">{t.body}</p>

        <div className="landing-stats">
          <div>
            <strong><CountUp value={all?.ssh_attempts} /></strong>
            <span>{t.attempts}</span>
          </div>
          <div>
            <strong><CountUp value={all?.unique_ssh_ips} /></strong>
            <span>{t.ips}</span>
          </div>
          <div>
            <strong><CountUp value={all?.countries} /></strong>
            <span>{t.countries}</span>
          </div>
        </div>

        <p className="landing-meta">
          {summary?.since && <>{t.since} {summary.since} · </>}
          {summary?.today && <>{summary.today.ssh_attempts.toLocaleString()} {t.today}</>}
          {summary?.top_username && (
            <> · {t.top}: <b>{summary.top_username.key}</b> ({summary.top_username.count.toLocaleString()})</>
          )}
        </p>

        <div className="landing-actions">
          <button className="landing-enter" onClick={onEnter} autoFocus>{t.enter} →</button>
          {summary?.repo_url && (
            <a className="landing-link" href={summary.repo_url} target="_blank" rel="noopener noreferrer">
              {t.code}
            </a>
          )}
        </div>

        <details className="landing-how">
          <summary>{t.how}</summary>
          <ol>{t.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
          <p>{t.privacy}</p>
        </details>
      </div>
    </div>
  )
}
