import React from 'react'

const MITRE_INFO = {
  'T1110':     { name: 'Brute Force',         tactic: 'Credential Access' },
  'T1110.001': { name: 'Password Guessing',   tactic: 'Credential Access' },
  'T1110.003': { name: 'Password Spraying',   tactic: 'Credential Access' },
  'T1595':     { name: 'Active Scanning',     tactic: 'Reconnaissance'    },
  'T1595.002': { name: 'Vulnerability Scanning', tactic: 'Reconnaissance' },
  'T1190':     { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  'T1078':     { name: 'Valid Accounts',      tactic: 'Initial Access'    },
}

export default function MitreBadge({ ttp }) {
  const info = MITRE_INFO[ttp]
  if (!info) return null
  return (
    <span className="mitre-badge" title={`${info.tactic}: ${info.name}`}>
      <span className="mitre-badge-id">{ttp}</span>
      <span className="mitre-badge-name">{info.name}</span>
    </span>
  )
}
