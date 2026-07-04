import React, { useEffect, useState } from 'react'
import { api } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'
import ThreatGauge from '../components/ThreatGauge'
import WatcherStatus from '../components/WatcherStatus'
import ThreatCard from '../components/ThreatCard'
import LiveChart from '../components/LiveChart'
import { Shield, Wifi, WifiOff } from 'lucide-react'

export default function Dashboard() {
  const [status, setStatus] = useState(null)
  const [alerts, setAlerts] = useState([])
  const { messages, isConnected } = useWebSocket('/ws/events')

  useEffect(() => {
    api.getStatus().then(setStatus).catch(console.error)
    api.getAlerts(10).then(setAlerts).catch(console.error)
  }, [])

  useEffect(() => {
    if (messages.length > 0) {
      setAlerts(prev => {
        const existing = new Set(prev.map(a => a.id))
        const newAlerts = messages.filter(a => !existing.has(a.id))
        return [...newAlerts, ...prev].slice(0, 10)
      })
    }
  }, [messages])

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">GUARDIAN Dashboard</h1>
        <div className="flex items-center gap-2">
          {isConnected ? (
            <span className="flex items-center gap-1 text-guardian-400 text-sm">
              <Wifi size={16} /> Live
            </span>
          ) : (
            <span className="flex items-center gap-1 text-red-400 text-sm">
              <WifiOff size={16} /> Disconnected
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Threat Level</h2>
          <ThreatGauge level={status?.threat_level || 'SAFE'} />
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Watcher Status</h2>
          <WatcherStatus watchers={status?.watchers || {}} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Recent Alerts</h2>
          <div className="space-y-3 max-h-80 overflow-y-auto">
            {alerts.length === 0 ? (
              <p className="text-gray-500 text-sm">No alerts yet</p>
            ) : (
              alerts.map((alert, i) => (
                <ThreatCard key={alert.id || i} alert={alert} compact />
              ))
            )}
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Event Timeline</h2>
          <LiveChart messages={messages} />
        </div>
      </div>
    </div>
  )
}
