import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000',
  timeout: 15000,
})

export function queryVulnerabilities(params) {
  return api.get('/vulnerabilities', { params })
}

export function queryPatches(cveId) {
  return api.get(`/vulnerabilities/${encodeURIComponent(cveId)}/related_patches`)
}

export function ingestDocument(payload) {
  return api.post('/vulnerabilities/ingest', payload)
}

export function ingestFromUrl(payload) {
  return api.post('/vulnerabilities/ingest/url', payload)
}

export function ingestFromFile(formData) {
  return api.post('/vulnerabilities/ingest/file', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
}

export function crawlAdvisories(payload) {
  return api.post('/vulnerabilities/crawl', payload)
}
