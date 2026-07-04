import React, { useEffect, useState } from 'react'
import { api } from '../utils/api'
import { Settings as SettingsIcon, Save, Trash2, Download } from 'lucide-react'

export default function Settings() {
  const [settings, setSettings] = useState({})
  const [whitelist, setWhitelist] = useState([])
  const [newWhitelist, setNewWhitelist] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    api.getSettings().then(setSettings).catch(console.error)
    api.getWhitelist().then(setWhitelist).catch(console.error)
  }, [])

  const handleSave = () => {
    api.updateSettings(settings).then(() => {
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    })
  }

  const handleAddWhitelist = () => {
    if (!newWhitelist.trim()) return
    api.addWhitelist(newWhitelist.trim()).then(() => {
      setNewWhitelist('')
      api.getWhitelist().then(setWhitelist)
    })
  }

  const handleRemoveWhitelist = (name) => {
    api.removeWhitelist(name).then(() => {
      api.getWhitelist().then(setWhitelist)
    })
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-white mb-6">Settings</h1>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h2 className="text-white font-medium mb-4 flex items-center gap-2">
            <SettingsIcon size={18} /> Detection Settings
          </h2>

          <div className="space-y-4">
            <div>
              <label className="text-sm text-gray-400 block mb-1">
                Poll Interval (seconds)
              </label>
              <input
                type="number"
                value={settings.poll_interval || 3}
                onChange={(e) =>
                  setSettings({ ...settings, poll_interval: e.target.value })
                }
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm"
              />
            </div>

            <div>
              <label className="text-sm text-gray-400 block mb-1">
                Sensitivity ({settings.contamination || 0.05})
              </label>
              <input
                type="range"
                min="0.01"
                max="0.3"
                step="0.01"
                value={settings.contamination || 0.05}
                onChange={(e) =>
                  setSettings({ ...settings, contamination: e.target.value })
                }
                className="w-full"
              />
              <div className="flex justify-between text-xs text-gray-500">
                <span>Less sensitive</span>
                <span>More sensitive</span>
              </div>
            </div>

            <div>
              <label className="text-sm text-gray-400 block mb-2">
                Watchers
              </label>
              {['process', 'network', 'hardware', 'filesystem', 'idle'].map(
                (pillar) => (
                  <label key={pillar} className="flex items-center gap-2 mb-2">
                    <input
                      type="checkbox"
                      checked={
                        settings[`watcher_${pillar}`] === 'true' ||
                        settings[`watcher_${pillar}`] === true
                      }
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          [`watcher_${pillar}`]: e.target.checked ? 'true' : 'false',
                        })
                      }
                      className="rounded border-gray-600"
                    />
                    <span className="text-sm text-gray-300 capitalize">
                      {pillar} Watcher
                    </span>
                  </label>
                )
              )}
            </div>

            <button
              onClick={handleSave}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                saved
                  ? 'bg-guardian-600 text-white'
                  : 'bg-guardian-600 hover:bg-guardian-700 text-white'
              }`}
            >
              <Save size={16} />
              {saved ? 'Saved!' : 'Save Settings'}
            </button>
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h2 className="text-white font-medium mb-4">Whitelist</h2>

          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={newWhitelist}
              onChange={(e) => setNewWhitelist(e.target.value)}
              placeholder="Process name (e.g., chrome.exe)"
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm"
              onKeyDown={(e) => e.key === 'Enter' && handleAddWhitelist()}
            />
            <button
              onClick={handleAddWhitelist}
              className="bg-guardian-600 hover:bg-guardian-700 px-4 py-2 rounded text-sm text-white"
            >
              Add
            </button>
          </div>

          <div className="space-y-2 max-h-60 overflow-y-auto">
            {whitelist.length === 0 ? (
              <p className="text-gray-500 text-sm">No whitelisted processes</p>
            ) : (
              whitelist.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between bg-gray-800 rounded px-3 py-2"
                >
                  <span className="text-sm text-gray-300">{item.process_name}</span>
                  <button
                    onClick={() => handleRemoveWhitelist(item.process_name)}
                    className="text-gray-500 hover:text-red-400"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              ))
            )}
          </div>

          <div className="mt-6 pt-4 border-t border-gray-800">
            <a
              href={api.exportCsv()}
              className="flex items-center gap-2 text-sm text-guardian-400 hover:text-guardian-300"
            >
              <Download size={16} />
              Export Alerts as CSV
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}
