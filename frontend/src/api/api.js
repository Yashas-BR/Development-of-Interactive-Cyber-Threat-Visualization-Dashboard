import axios from 'axios'

const BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const buildParams = (filters = {}) => {
  const params = {}
  if (filters.country && filters.country !== 'All') params.country = filters.country
  if (filters.severity && filters.severity !== 'All') params.severity = filters.severity
  if (filters.attack_type && filters.attack_type !== 'All') params.attack_type = filters.attack_type
  if (filters.days && filters.days !== 'All') params.days = filters.days
  return params
}

export const api = {
  getThreats: (filters) => axios.get(`${BASE}/api/threats`, { params: buildParams(filters) }),
  getStats: (filters) => axios.get(`${BASE}/api/stats`, { params: buildParams(filters) }),
  getTrends: (filters) => axios.get(`${BASE}/api/trends`, { params: buildParams(filters) }),
  getTypes: (filters) => axios.get(`${BASE}/api/types`, { params: buildParams(filters) }),
  getDevices: (filters) => axios.get(`${BASE}/api/devices`, { params: buildParams(filters) }),
  getCountries: (filters) => axios.get(`${BASE}/api/countries`, { params: buildParams(filters) }),
  getSeverity: (filters) => axios.get(`${BASE}/api/severity`, { params: buildParams(filters) }),
  getMeta: () => axios.get(`${BASE}/api/meta`),
  simulate: (count = 250) => axios.post(`${BASE}/api/simulate?count=${count}`),
}
