import React from 'react'

const LEVEL_CONFIG = {
  SAFE: { color: '#22c55e', label: 'SAFE', percent: 10 },
  LOW: { color: '#3b82f6', label: 'LOW', percent: 30 },
  MEDIUM: { color: '#eab308', label: 'MEDIUM', percent: 55 },
  HIGH: { color: '#f97316', label: 'HIGH', percent: 75 },
  CRITICAL: { color: '#ef4444', label: 'CRITICAL', percent: 95 },
}

export default function ThreatGauge({ level = 'SAFE' }) {
  const config = LEVEL_CONFIG[level] || LEVEL_CONFIG.SAFE

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-48 h-24 mb-4">
        <svg viewBox="0 0 200 100" className="w-full h-full">
          <defs>
            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#22c55e" />
              <stop offset="33%" stopColor="#eab308" />
              <stop offset="66%" stopColor="#f97316" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
          </defs>

          <path
            d="M 20 90 A 80 80 0 0 1 180 90"
            fill="none"
            stroke="#1f2937"
            strokeWidth="12"
            strokeLinecap="round"
          />

          <path
            d="M 20 90 A 80 80 0 0 1 180 90"
            fill="none"
            stroke="url(#gaugeGradient)"
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${config.percent * 2.5} 250`}
          />

          <circle
            cx={100 + 80 * Math.cos(Math.PI - (config.percent / 100) * Math.PI)}
            cy={90 - 80 * Math.sin((config.percent / 100) * Math.PI)}
            r="6"
            fill={config.color}
          />
        </svg>
      </div>

      <div
        className="text-2xl font-bold"
        style={{ color: config.color }}
      >
        {config.label}
      </div>
    </div>
  )
}
