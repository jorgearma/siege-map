import React from 'react'

const MITRE_INFO = {
  'T1110.001': { name: 'Password Guessing',  tactic: 'Credential Access' },
  'T1110.003': { name: 'Password Spraying',  tactic: 'Credential Access' },
  'T1110.004': { name: 'Credential Stuffing', tactic: 'Credential Access' },
  'T1078':     { name: 'Valid Accounts',      tactic: 'Initial Access'    },
  'T1021.004': { name: 'Remote Services: SSH', tactic: 'Lateral Movement' },
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
