import axios, { AxiosInstance } from 'axios'

const USE_MOCK = false // Toggle for mock mode

const apiClient: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Mock data store
const mockStore = {
  iocs: [
    {
      id: 'ioc-001',
      type: 'ipv4',
      value: '192.168.1.100',
      threat_level: 'high',
      confidence: 85,
      source: 'manual',
      first_seen: '2026-04-25T10:00:00Z',
      last_seen: '2026-04-27T10:00:00Z',
      active: true,
      metadata: {},
      stix_id: 'indicator--abc123',
    },
    {
      id: 'ioc-002',
      type: 'domain',
      value: 'malicious-site.example.com',
      threat_level: 'critical',
      confidence: 95,
      source: 'virustotal',
      first_seen: '2026-04-20T08:00:00Z',
      last_seen: '2026-04-27T09:00:00Z',
      active: true,
      metadata: { tags: ['malware', 'c2'] },
      stix_id: 'indicator--def456',
    },
    {
      id: 'ioc-003',
      type: 'hash-sha256',
      value: 'a1b2c3d4e5f6...',
      threat_level: 'medium',
      confidence: 70,
      source: 'alienvault_otx',
      first_seen: '2026-04-22T12:00:00Z',
      last_seen: '2026-04-26T15:00:00Z',
      active: true,
      metadata: { malware_family: 'Emotet' },
      stix_id: 'indicator--ghi789',
    },
  ],
  users: [
    { username: 'admin', email: 'admin@threatintel.local', role: 'admin', is_active: true },
  ],
}

// Mock API implementation
const mockAPI = {
  async get(url: string, config?: any) {
    if (url.includes('/iocs')) {
      const page = config?.params?.page || 1
      const pageSize = config?.params?.page_size || 20
      return {
        data: {
          success: true,
          data: mockStore.iocs,
          total: mockStore.iocs.length,
          page,
          page_size: pageSize,
          total_pages: 1,
        }
      }
    }
    if (url.includes('/actors')) {
      return { data: { data: [], total: 0 } }
    }
    if (url.includes('/auth/me')) {
      return { data: mockStore.users[0] }
    }
    return { data: { success: true } }
  },

  async post(url: string, data?: any) {
    if (url.includes('/auth/login')) {
      if (data.username === 'admin' && data.password === 'admin123') {
        return {
          data: {
            access_token: 'mock-jwt-token-admin',
            token_type: 'bearer',
          }
        }
      }
      throw { response: { status: 401, data: { detail: 'Invalid credentials' } } }
    }
    if (url.includes('/auth/register')) {
      return { data: { message: 'User created successfully', username: data.username } }
    }
    if (url.includes('/iocs') && !url.includes('bulk')) {
      const newIOC = {
        id: `ioc-${Date.now()}`,
        ...data,
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        active: true,
      }
      mockStore.iocs.push(newIOC)
      return { data: { success: true, message: 'IOC created', data: newIOC } }
    }
    return { data: { success: true } }
  },

  async put(url: string, data?: any) {
    return { data: { success: true, message: 'Updated' } }
  },

  async delete(url: string) {
    return { data: { success: true, message: 'Deleted' } }
  },
}

// Conditionally use mock or real API
const api = USE_MOCK ? mockAPI : apiClient

// Auth API
export const authAPI = {
  login: (username: string, password: string) => api.post('/auth/login', { username, password }),
  register: (username: string, email: string, password: string) =>
    api.post('/auth/register', { username, email, password, role: 'viewer' }),
  me: () => api.get('/auth/me'),
  users: () => api.get('/auth/users'),
}

// IOC API
export const iocAPI = {
  list: (params?: any) => api.get('/iocs', { params }),
  create: (data: any) => api.post('/iocs', data),
  get: (id: string) => api.get(`/iocs/${id}`),
  update: (id: string, data: any) => api.put(`/iocs/${id}`, data),
  delete: (id: string) => api.delete(`/iocs/${id}`),
  bulkCreate: (iocs: any[]) => api.post('/iocs/bulk', iocs),
  enrich: (id: string) => api.post(`/iocs/${id}/enrich`),
}

// Threat Actors API
export const actorAPI = {
  list: (params?: any) => api.get('/actors', { params }),
  create: (data: any) => api.post('/actors', data),
  get: (id: string) => api.get(`/actors/${id}`),
  getGraph: (id: string, depth?: number) =>
    api.get(`/actors/${id}/graph`, { params: { depth } }),
}

// Malware API
export const malwareAPI = {
  list: (params?: any) => api.get('/malware', { params }),
  create: (data: any) => api.post('/malware', data),
  get: (id: string) => api.get(`/malware/${id}`),
}

// Campaigns API
export const campaignAPI = {
  list: (params?: any) => api.get('/campaigns', { params }),
  create: (data: any) => api.post('/campaigns', data),
  get: (id: string) => api.get(`/campaigns/${id}`),
}

// Feeds API
export const feedAPI = {
  list: () => api.get('/feeds/status'),
  register: (data: any) => api.post('/feeds/register', data),
  ingest: (feedId: string, force?: boolean) =>
    api.post('/feeds/ingest', { feed_id: feedId, force }),
}

// Search API
export const searchAPI = {
  textSearch: (query: string, filters?: any) =>
    api.post('/search/text', { query, filters }),
  semanticSearch: (query: string, collection?: string, limit?: number) =>
    api.post('/search/semantic', { query, collection, limit }),
}

// Analysis API
export const analysisAPI = {
  analyzeText: (text: string, type?: string) =>
    api.post('/analysis/analyze-text', { text, analysis_type: type }),
  extractIOCs: (text: string, minConfidence?: number) =>
    api.post('/analysis/extract-iocs', { text, min_confidence: minConfidence }),
  generateReport: (iocIds: string[]) =>
    api.post('/analysis/generate-report', { ioc_ids: iocIds }),
  mapToATTACK: (text: string, useLLM?: boolean) =>
    api.post('/analysis/map-attack', { text, use_llm: useLLM }),
  uploadReport: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/analysis/upload-report', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
  },
}

// TAXII API
export const taxiiAPI = {
  listCollections: () => api.get('/taxii/collections'),
  push: (bundle: any, collectionId?: string) =>
    api.post('/taxii/push', { bundle, collection_id: collectionId }),
  ingest: (url: string, apiKey?: string) =>
    api.post('/taxii/ingest', { collection_url: url, api_key: apiKey }),
}

// STIX API
export const stixAPI = {
  importBundle: (bundle: any) => api.post('/stix/import', { bundle }),
  exportBundle: (iocIds?: string[], format?: string) =>
    api.get('/stix/export', { params: { ioc_ids: iocIds, format } }),
  convertToPattern: (type: string, value: string) =>
    api.post('/stix/convert', { ioc_type: type, value }),
}

export default apiClient
