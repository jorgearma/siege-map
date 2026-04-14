import React, { useEffect, useRef } from 'react'

export default function Console({ events = [] }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [events])

  return (
    <div className="console-panel">
      <div className="console-header">
        <span className="console-title">&gt;_ LIVE_CONSOLE</span>
      </div>
      <div className="console-body" ref={scrollRef}>
        {events.length === 0 ? (
          <div className="console-line empty">
            <span className="console-prompt">&gt;</span>
            <span className="console-text text-dim">waiting for events...</span>
          </div>
        ) : (
          events.slice(-50).map((evt, idx) => (
            <div key={idx} className="console-line">
              <span className="console-prompt">&gt;</span>
              <span className="console-text">
                <span className="text-primary">[{evt.event_type}]</span>
                {' '}
                <span className="text-bright">{evt.ip}</span>
                {' '}
                <span className="text-secondary">{evt.username || '-'}</span>
                {' '}
                <span className="text-dim">{new Date(evt.timestamp).toLocaleTimeString()}</span>
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
