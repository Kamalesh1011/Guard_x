import React from 'react'
import SHAPBar from './SHAPBar'
import { Shield, Trash2, Ban, AlertTriangle, ExternalLink } from 'lucide-react'

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  SAFE: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
}

const RISK_STYLES = {
  CRITICAL: 'bg-red-500/10 border-red-500/20 text-red-300',
  HIGH: 'bg-orange-500/10 border-orange-500/20 text-orange-300',
  MEDIUM: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-300',
}

export default function ThreatCard({ alert, compact = false, onDismiss, onWhitelist, onKill }) {
  const severity = alert.severity || 'SAFE'
  const shapValues = typeof alert.shap_values === 'string'
    ? JSON.parse(alert.shap_values || '{}')
    : alert.shap_values || {}
  const riskFactors = typeof alert.risk_factors === 'string'
    ? JSON.parse(alert.risk_factors || '[]')
    : alert.risk_factors || []
  const mitreTtps = typeof alert.mitre_ttps === 'string'
    ? JSON.parse(alert.mitre_ttps || '[]')
    : alert.mitre_ttps || []

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
          {alert.total_risk_score > 0 && (
            <span className="text-xs text-gray-500">
              Risk Score: {alert.total_risk_score}
            </span>
          )}
        </div>
        <span className="text-xs text-gray-500">
          {alert.created_at ? new Date(alert.created_at).toLocaleString() : ''}
        </span>
      </div>

      <p className="text-gray-300 text-sm mb-4">{alert.summary}</p>

      {riskFactors.length > 0 && (
        <div className="mb-4">
          <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
            <AlertTriangle size={12} /> RISK FACTORS ({riskFactors.length}):
          </p>
          <div className="space-y-2">
            {riskFactors.map((rf, i) => (
              <div key={i} className={`rounded-lg p-3 border ${RISK_STYLES[rf.risk_level] || RISK_STYLES.MEDIUM}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold">{rf.factor}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/20">{rf.risk_level}</span>
                </div>
                <p className="text-xs opacity-80">{rf.detail}</p>
                {rf.ttp && (
                  <p className="text-[10px] mt-1 opacity-60">MITRE: {rf.ttp}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {mitreTtps.length > 0 && (
        <div className="mb-4">
          <p className="text-xs text-gray-500 mb-2">MITRE ATT&CK TECHNIQUES:</p>
          <div className="flex flex-wrap gap-1">
            {mitreTtps.map((ttp, i) => (
              <span key={i} className="px-2 py-0.5 bg-purple-500/10 border border-purple-500/20 rounded text-[10px] text-purple-300">
                {ttp}
              </span>
            ))}
          </div>
        </div>
      )}

      {topFeatures.length > 0 && (
        <div className="mb-4">
          <p className="text-xs text-gray-500 mb-2">FEATURE CONTRIBUTIONS:</p>
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

      <div className="flex items-center gap-3 text-xs text-gray-500">
        {alert.process_name && <span>Process: {alert.process_name}</span>}
        {alert.pid && <span>PID: {alert.pid}</span>}
        {alert.threat_context && (
          <span className="text-red-400/70 italic">{alert.threat_context.substring(0, 80)}...</span>
        )}
      </div>

      {(onDismiss || onWhitelist || onKill) && (
        <div className="flex gap-2 mt-4 pt-3 border-t border-gray-800">
          {onWhitelist && (
            <button onClick={onWhitelist} className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-xs text-gray-300">
              <Shield size={12} /> Whitelist
            </button>
          )}
          {onKill && alert.pid && (
            <button onClick={onKill} className="flex items-center gap-1 px-3 py-1.5 bg-red-900/50 hover:bg-red-800/50 rounded text-xs text-red-300">
              <Ban size={12} /> Kill Process
            </button>
          )}
          {onDismiss && (
            <button onClick={onDismiss} className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-xs text-gray-400">
              <Trash2 size={12} /> Dismiss
            </button>
          )}
        </div>
      )}
    </div>
  )
}
