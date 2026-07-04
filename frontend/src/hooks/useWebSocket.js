import { useState, useEffect, useRef, useCallback } from 'react'

export function useWebSocket(path = '/ws') {
  const [messages, setMessages] = useState([])
  const [isConnected, setIsConnected] = useState(false)
  const pollRef = useRef(null)

  const poll = useCallback(async () => {
    try {
      const API_BASE = import.meta.env.VITE_API_URL || ''
      const res = await fetch(`${API_BASE}/api/alerts?limit=5`)
      if (res.ok) {
        const data = await res.json()
        setMessages(prev => {
          const newAlerts = data.filter(a => !prev.find(p => p.id === a.id))
          return [...newAlerts, ...prev].slice(0, 50)
        })
        setIsConnected(true)
      }
    } catch (e) {
      setIsConnected(false)
    }
  }, [])

  useEffect(() => {
    poll()
    pollRef.current = setInterval(poll, 3000)
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [poll])

  return { messages, isConnected }
}
