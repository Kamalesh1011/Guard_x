import React, { useEffect, useState } from 'react'
import { api } from '../utils/api'
import ThreatCard from '../components/ThreatCard'
import { Filter } from 'lucide-react'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function AlertFeed() {
  const [alerts, setAlerts] = useState([])
  const [filter, setFilter] = useState('ALL')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    const severity = filter === 'ALL' ? null : filter
    api.getAlerts(100, 0, severity)
      .then(setAlerts)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [filter])

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Alert Feed</h1>
        <div className="flex items-center gap-2">
          <Filter size={16} className="text-gray-400" />
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                filter === s
                  ? 'bg-guardian-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {loading && (
        <div className="text-center text-gray-500 py-8">Loading...</div>
      )}

      <div className="space-y-4">
        {alerts.map((alert) => (
          <ThreatCard
            key={alert.id}
            alert={alert}
            onDismiss={() => {
              api.dismissAlert(alert.id)
              setAlerts((prev) => prev.filter((a) => a.id !== alert.id))
            }}
            onWhitelist={() => {
              api.addWhitelist(alert.process_name)
            }}
            onKill={() => {
              if (alert.pid) api.killProcess(alert.pid)
            }}
          />
        ))}
        {!loading && alerts.length === 0 && (
          <div className="text-center text-gray-500 py-8">No alerts found</div>
        )}
      </div>
    </div>
  )
}
