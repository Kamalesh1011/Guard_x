import React, { useEffect, useState } from 'react'
import { api } from '../utils/api'
import { Camera, Mic, Bluetooth, Usb, Shield, ShieldOff, AlertTriangle, Lock, Unlock, RefreshCw, History, Settings } from 'lucide-react'

export default function HardwareStatus() {
  const [hardware, setHardware] = useState({})
  const [alerts, setAlerts] = useState([])
  const [cameraEnabled, setCameraEnabled] = useState(true)
  const [micEnabled, setMicEnabled] = useState(true)
  const [btEnabled, setBtEnabled] = useState(true)
  const [usbEnabled, setUsbEnabled] = useState(true)
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [history, setHistory] = useState([])

  useEffect(() => {
    api.getHardware().then(setHardware).catch(console.error)
    api.getAlerts(20).then((data) => {
      const hwAlerts = data.filter(a =>
        ['CAMERA_ACCESS', 'MIC_ACCESS', 'BLUETOOTH_CONNECT', 'USB_INSERT'].includes(a.type)
      )
      setAlerts(hwAlerts)
    }).catch(console.error)

    const interval = setInterval(() => {
      api.getHardware().then(setHardware).catch(console.error)
    }, 2000)
    return () => clearInterval(interval)
  }, [])

  const cameraActive = hardware.camera?.active || false
  const micActive = hardware.microphone?.active || false
  const cameraApps = hardware.camera?.apps || []
  const micApps = hardware.microphone?.apps || []

  const toggleCamera = () => {
    setCameraEnabled(!cameraEnabled)
    api.updateSettings({ hardware_camera: (!cameraEnabled).toString() })
  }

  const toggleMic = () => {
    setMicEnabled(!micEnabled)
    api.updateSettings({ hardware_mic: (!micEnabled).toString() })
  }

  const toggleBluetooth = () => {
    setBtEnabled(!btEnabled)
    api.updateSettings({ hardware_bluetooth: (!btEnabled).toString() })
  }

  const toggleUsb = () => {
    setUsbEnabled(!usbEnabled)
    api.updateSettings({ hardware_usb: (!usbEnabled).toString() })
  }

  const blockApp = (appName) => {
    api.addWhitelist(appName)
    setHistory(prev => [...prev, { action: 'blocked', app: appName, time: new Date().toLocaleTimeString() }])
  }

  const trustApp = (appName) => {
    setHistory(prev => [...prev, { action: 'trusted', app: appName, time: new Date().toLocaleTimeString() }])
  }

  const HardwareCard = ({ icon: Icon, color, name, status, active, enabled, onToggle, apps, onBlock, onTrust }) => (
    <div className={`bg-gray-900 rounded-xl p-5 border transition-all ${active && enabled ? 'border-red-500/50 shadow-lg shadow-red-500/10' : 'border-gray-800'}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`p-3 rounded-full ${active && enabled ? `bg-${color}-500/20 animate-pulse-fast` : `bg-${color}-500/10`}`}>
            <Icon size={24} className={active && enabled ? `text-${color}-400` : 'text-gray-500'} />
          </div>
          <div>
            <h3 className="text-white font-medium">{name}</h3>
            <p className={`text-sm ${active && enabled ? 'text-red-400' : 'text-guardian-400'}`}>
              {active && enabled ? 'ACTIVE' : enabled ? 'Inactive' : 'Disabled'}
            </p>
          </div>
        </div>
        <button
          onClick={onToggle}
          className={`relative w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-guardian-600' : 'bg-gray-700'}`}
        >
          <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${enabled ? 'left-7' : 'left-1'}`} />
        </button>
      </div>

      {apps && apps.length > 0 && enabled && (
        <div className="mt-3 space-y-2">
          <p className="text-xs text-gray-500 uppercase tracking-wide">Active Applications</p>
          {apps.map((app, i) => (
            <div key={i} className="flex items-center justify-between bg-gray-800/80 rounded-lg px-3 py-2">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                <span className="text-sm text-gray-300">{app}</span>
              </div>
              <div className="flex gap-1">
                <button
                  onClick={() => onTrust(app)}
                  className="p-1 hover:bg-gray-700 rounded text-gray-400 hover:text-guardian-400"
                  title="Trust this app"
                >
                  <Shield size={14} />
                </button>
                <button
                  onClick={() => onBlock(app)}
                  className="p-1 hover:bg-gray-700 rounded text-gray-400 hover:text-red-400"
                  title="Block this app"
                >
                  <ShieldOff size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {!enabled && (
        <div className="mt-3 flex items-center gap-2 text-gray-500">
          <Lock size={14} />
          <span className="text-sm">Monitoring disabled</span>
        </div>
      )}

      {enabled && !active && apps && apps.length === 0 && (
        <div className="mt-3 flex items-center gap-2 text-gray-500">
          <Unlock size={14} />
          <span className="text-sm">No active applications</span>
        </div>
      )}
    </div>
  )

  const btAlerts = alerts.filter(a => a.type === 'BLUETOOTH_CONNECT')
  const usbAlerts = alerts.filter(a => a.type === 'USB_INSERT')

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Hardware Status</h1>
        <div className="flex items-center gap-3">
          <button
            onClick={() => api.getHardware().then(setHardware)}
            className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300"
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <HardwareCard
          icon={Camera}
          color="green"
          name="Camera"
          status={cameraActive}
          active={cameraActive}
          enabled={cameraEnabled}
          onToggle={toggleCamera}
          apps={cameraApps}
          onBlock={blockApp}
          onTrust={trustApp}
        />
        <HardwareCard
          icon={Mic}
          color="red"
          name="Microphone"
          status={micActive}
          active={micActive}
          enabled={micEnabled}
          onToggle={toggleMic}
          apps={micApps}
          onBlock={blockApp}
          onTrust={trustApp}
        />
        <HardwareCard
          icon={Bluetooth}
          color="blue"
          name="Bluetooth"
          status={false}
          active={false}
          enabled={btEnabled}
          onToggle={toggleBluetooth}
          apps={[]}
          onBlock={blockApp}
          onTrust={trustApp}
        />
        <HardwareCard
          icon={Usb}
          color="purple"
          name="USB"
          status={false}
          active={false}
          enabled={usbEnabled}
          onToggle={toggleUsb}
          apps={[]}
          onBlock={blockApp}
          onTrust={trustApp}
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
          <h2 className="text-white font-medium mb-3 flex items-center gap-2">
            <History size={16} className="text-gray-400" /> Recent Activity
          </h2>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {history.length === 0 && alerts.length === 0 ? (
              <p className="text-gray-500 text-sm">No recent activity</p>
            ) : (
              <>
                {history.map((h, i) => (
                  <div key={`h-${i}`} className="flex items-center gap-2 text-sm">
                    <div className={`w-1.5 h-1.5 rounded-full ${h.action === 'blocked' ? 'bg-red-500' : 'bg-guardian-500'}`} />
                    <span className="text-gray-400">{h.time}</span>
                    <span className="text-gray-300">{h.action} {h.app}</span>
                  </div>
                ))}
                {alerts.slice(0, 5).map((a, i) => (
                  <div key={`a-${i}`} className="flex items-center gap-2 text-sm">
                    <div className="w-1.5 h-1.5 rounded-full bg-yellow-500" />
                    <span className="text-gray-400">{new Date(a.created_at).toLocaleTimeString()}</span>
                    <span className="text-gray-300">{a.type}: {a.process_name}</span>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl p-5 border border-gray-800">
          <h2 className="text-white font-medium mb-3 flex items-center gap-2">
            <AlertTriangle size={16} className="text-yellow-400" /> Hardware Alerts
          </h2>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {alerts.length === 0 ? (
              <p className="text-gray-500 text-sm">No hardware alerts</p>
            ) : (
              alerts.slice(0, 8).map((alert, i) => (
                <div key={i} className="bg-gray-800/50 rounded-lg p-2">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                      alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                      alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {alert.severity}
                    </span>
                    <span className="text-xs text-gray-500">{alert.type}</span>
                  </div>
                  <p className="text-xs text-gray-400 truncate">{alert.summary}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
