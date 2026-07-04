import React from 'react'
import SHAPBar from './SHAPBar'
import { Shield, Trash2, Ban } from 'lucide-react'

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  SAFE: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
}

export default function ThreatCard({ alert, compact = false, onDismiss, onWhitelist, onKill }) {
  const severity = alert.severity || 'SAFE'
  const shapValues = typeof alert.shap_values === 'string'
    ? JSON.parse(alert.shap_values || '{}')
    : alert.shap_values || {}

  const topFeatures = Object.entries(shapValues)
    .sort(([, a], [, b]) => Math.abs(b) - Math.abs(a))
    .slice(0, 3)

  if (compact) {
    return (
      <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
        <div className="flex items-center gap-2 mb-1">
          <span className={`px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_STYLES[severity]}`}>
            {severity}
          </span>
          <span className="text-xs text-gray-500">{alert.type}</span>
        </div>
        <p className="text-sm text-gray-300 line-clamp-2">{alert.summary}</p>
      </div>
    )
  }

  return (
    <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className={`px-2.5 py-1 rounded text-xs font-bold ${SEVERITY_STYLES[severity]}`}>
            {severity}
          </span>
          <span className="text-white font-medium">{alert.type}</span>
        </div>
        <span className="text-xs text-gray-500">
          {alert.created_at ? new Date(alert.created_at).toLocaleString() : ''}
        </span>
      </div>

      <p className="text-gray-300 text-sm mb-4">{alert.summary}</p>

      {topFeatures.length > 0 && (
        <div className="mb-4">
          <p className="text-xs text-gray-500 mb-2">WHY THIS IS SUSPICIOUS:</p>
          <div className="space-y-2">
            {topFeatures.map(([feature, value]) => (
              <SHAPBar key={feature} feature={feature} value={value} />
            ))}
          </div>
        </div>
      )}

      {alert.recommendation && (
        <div className="bg-gray-800/50 rounded-lg p-3 mb-4">
          <p className="text-xs text-gray-500 mb-1">RECOMMENDATION:</p>
          <p className="text-sm text-gray-300">{alert.recommendation}</p>
        </div>
      )}

      <div className="flex items-center gap-2 text-xs text-gray-500">
        {alert.process_name && <span>Process: {alert.process_name}</span>}
        {alert.pid && <span>PID: {alert.pid}</span>}
      </div>

      {(onDismiss || onWhitelist || onKill) && (
        <div className="flex gap-2 mt-4 pt-3 border-t border-gray-800">
          {onWhitelist && (
            <button
              onClick={onWhitelist}
              className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-xs text-gray-300"
            >
              <Shield size={12} /> Whitelist
            </button>
          )}
          {onKill && alert.pid && (
            <button
              onClick={onKill}
              className="flex items-center gap-1 px-3 py-1.5 bg-red-900/50 hover:bg-red-800/50 rounded text-xs text-red-300"
            >
              <Ban size={12} /> Kill Process
            </button>
          )}
          {onDismiss && (
            <button
              onClick={onDismiss}
              className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-xs text-gray-400"
            >
              <Trash2 size={12} /> Dismiss
            </button>
          )}
        </div>
      )}
    </div>
  )
}
