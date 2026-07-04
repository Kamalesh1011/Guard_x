const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8001'

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}

export const api = {
  getStatus: () => request('/api/status'),
  getAlerts: (limit = 50, offset = 0, severity = null) => {
    const params = new URLSearchParams({ limit, offset })
    if (severity) params.set('severity', severity)
    return request(`/api/alerts?${params}`)
  },
  getAlert: (id) => request(`/api/alerts/${id}`),
  getHardware: () => request('/api/hardware'),
  getProcesses: () => request('/api/processes'),
  getNetwork: () => request('/api/network'),
  getSettings: () => request('/api/settings'),
  updateSettings: (data) => request('/api/settings', { method: 'POST', body: JSON.stringify(data) }),
  addWhitelist: (name) => request('/api/actions/whitelist', { method: 'POST', body: JSON.stringify({ process_name: name }) }),
  removeWhitelist: (name) => request(`/api/actions/whitelist/${name}`, { method: 'DELETE' }),
  getWhitelist: () => request('/api/whitelist'),
  killProcess: (pid) => request('/api/actions/kill', { method: 'POST', body: JSON.stringify({ pid }) }),
  dismissAlert: (id) => request('/api/actions/dismiss', { method: 'POST', body: JSON.stringify({ alert_id: id }) }),
  getStats: () => request('/api/stats'),
  exportCsv: () => `${API_BASE}/api/export/csv`,
}
