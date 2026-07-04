import { useState, useEffect, useRef, useCallback } from 'react'

const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://127.0.0.1:8001'

export function useWebSocket(path = '/ws') {
  const [messages, setMessages] = useState([])
  const [isConnected, setIsConnected] = useState(false)
  const ws = useRef(null)
  const reconnectTimer = useRef(null)

  const connect = useCallback(() => {
    try {
      ws.current = new WebSocket(`${WS_BASE}${path}`)

      ws.current.onopen = () => {
        setIsConnected(true)
      }

      ws.current.onclose = () => {
        setIsConnected(false)
        reconnectTimer.current = setTimeout(connect, 3000)
      }

      ws.current.onerror = () => {
        setIsConnected(false)
      }

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setMessages((prev) => [data, ...prev.slice(0, 99)])
        } catch (e) {
          console.error('WebSocket parse error:', e)
        }
      }
    } catch (e) {
      console.error('WebSocket connection error:', e)
      reconnectTimer.current = setTimeout(connect, 3000)
    }
  }, [url])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (ws.current) ws.current.close()
    }
  }, [connect])

  return { messages, isConnected }
}
