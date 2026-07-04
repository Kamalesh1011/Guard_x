import React from 'react'

export default function SHAPBar({ feature, value }) {
  const absValue = Math.abs(value)
  const width = Math.min(100, absValue * 100)
  const isSuspicious = value > 0
  const label = feature.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())

  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-400 w-32 text-right truncate">{label}</span>
      <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${
            isSuspicious ? 'bg-red-500' : 'bg-guardian-500'
          }`}
          style={{ width: `${width}%` }}
        />
      </div>
      <span className={`text-xs w-12 ${isSuspicious ? 'text-red-400' : 'text-guardian-400'}`}>
        {value > 0 ? '+' : ''}{(value * 100).toFixed(0)}%
      </span>
    </div>
  )
}
