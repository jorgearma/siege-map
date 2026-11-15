/* One place for what a severity / attack pattern looks like. Colour never
   carries the meaning alone: every use also prints the label. */
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const SEVERITY_COLOR = {
  CRITICAL: '#ff0040',
  HIGH: '#ff7a1a',
  MEDIUM: '#ffb000',
  LOW: '#00d4ff',
}

export const PATTERNS = {
  DICTIONARY_ATTACK: { color: '#ff0040', label: 'DICTIONARY ATTACK', short: 'DICT ATTACK' },
  PASSWORD_SPRAYING: { color: '#ff7a1a', label: 'PASSWORD SPRAYING', short: 'PASS SPRAY' },
  PASSWORD_GUESSING: { color: '#ffb000', label: 'PASSWORD GUESSING', short: 'PASS GUESS' },
  WEB_SCANNING: { color: '#ffd700', label: 'WEB SCANNING', short: 'WEB SCAN' },
  SSH_SCANNING: { color: '#9085e9', label: 'SSH SCANNING', short: 'SSH SCAN' },
  SINGLE_PROBE: { color: '#00d4ff', label: 'SINGLE PROBE', short: 'SINGLE PROBE' },
}

export const CONFIDENCE_COLOR = { HIGH: '#ff0040', MEDIUM: '#ffb000', LOW: '#5d6f62' }

export function clock(ts) {
  return ts ? ts.slice(11, 16) : ''
}

export function ago(ts) {
  if (!ts) return ''
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000)
  if (s < 90) return 'now'
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}
