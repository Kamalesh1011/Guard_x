import React from 'react'
import { Camera, Wifi, Cpu, HardDrive, Moon } from 'lucide-react'

const WATCHER_CONFIG = {
  process: { icon: Cpu, label: 'Process' },
  network: { icon: Wifi, label: 'Network' },
  hardware: { icon: Camera, label: 'Hardware' },
  filesystem: { icon: HardDrive, label: 'Filesystem' },
  idle: { icon: Moon, label: 'Idle' },
}

export default function WatcherStatus({ watchers = {} }) {
  return (
    <div className="space-y-3">
      {Object.entries(WATCHER_CONFIG).map(([key, { icon: Icon, label }]) => {
        const active = watchers[key] === true || watchers[key] === 'true'
        return (
          <div key={key} className="flex items-center gap-3">
            <div
              className={`w-3 h-3 rounded-full ${
                active ? 'bg-guardian-500 animate-pulse' : 'bg-gray-600'
              }`}
            />
            <Icon size={16} className="text-gray-400" />
            <span className="text-sm text-gray-300 flex-1">{label}</span>
            <span className={`text-xs ${active ? 'text-guardian-400' : 'text-gray-500'}`}>
              {active ? 'Active' : 'Disabled'}
            </span>
          </div>
        )
      })}
    </div>
  )
}
