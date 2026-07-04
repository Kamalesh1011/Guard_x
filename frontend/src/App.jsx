import React from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import AlertFeed from './pages/AlertFeed'
import ProcessTree from './pages/ProcessTree'
import HardwareStatus from './pages/HardwareStatus'
import Settings from './pages/Settings'
import { Shield, AlertTriangle, Activity, Cpu, Settings as SettingsIcon } from 'lucide-react'

const navItems = [
  { to: '/', icon: Shield, label: 'Dashboard' },
  { to: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { to: '/processes', icon: Activity, label: 'Processes' },
  { to: '/hardware', icon: Cpu, label: 'Hardware' },
  { to: '/settings', icon: SettingsIcon, label: 'Settings' },
]

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-950">
        <nav className="w-16 bg-gray-900 border-r border-gray-800 flex flex-col items-center py-4 gap-2">
          <div className="mb-4 p-2 bg-guardian-600 rounded-lg">
            <Shield size={24} className="text-white" />
          </div>
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `p-3 rounded-lg transition-colors ${
                  isActive
                    ? 'bg-guardian-600 text-white'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`
              }
              title={label}
            >
              <Icon size={20} />
            </NavLink>
          ))}
        </nav>

        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<AlertFeed />} />
            <Route path="/processes" element={<ProcessTree />} />
            <Route path="/hardware" element={<HardwareStatus />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
