import { useEffect, useState } from 'react'

/** Poll a JSON endpoint. `url = null` pauses it. */
export default function useApi(url, interval = 30000) {
  const [data, setData] = useState(null)
  useEffect(() => {
    if (!url) return undefined
    let active = true
    async function load() {
      try {
        const res = await fetch(url)
        if (res.ok && active) setData(await res.json())
      } catch {
        // retry next cycle
      }
    }
    load()
    const id = setInterval(load, interval)
    return () => { active = false; clearInterval(id) }
  }, [url, interval])
  return data
}
