import React, { useState, useEffect } from 'react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

export default function LiveChart({ messages = [] }) {
  const [data, setData] = useState([])

  useEffect(() => {
    const now = Date.now()
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }

    messages.forEach((msg) => {
      if (msg.type === 'alert' && msg.data?.severity) {
        severityCounts[msg.data.severity] = (severityCounts[msg.data.severity] || 0) + 1
      }
    })

    const newPoint = {
      time: new Date(now).toLocaleTimeString(),
      critical: severityCounts.CRITICAL,
      high: severityCounts.HIGH,
      medium: severityCounts.MEDIUM,
      low: severityCounts.LOW,
    }

    setData((prev) => [...prev.slice(-29), newPoint])
  }, [messages])

  return (
    <div className="h-48">
      {data.length < 2 ? (
        <div className="h-full flex items-center justify-center text-gray-500 text-sm">
          Collecting data...
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#6b7280' }} />
            <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1f2937',
                border: '1px solid #374151',
                borderRadius: '8px',
                fontSize: '12px',
              }}
            />
            <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="low" stroke="#3b82f6" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
