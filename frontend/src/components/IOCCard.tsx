import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { iocAPI } from '@/services/api'

interface IOCFormProps {
  ioc?: any
  onSubmit: (data: any) => void
  onCancel: () => void
  isLoading: boolean
}

export default function IOCForm({ ioc, onSubmit, onCancel, isLoading }: IOCFormProps) {
  const [formData, setFormData] = useState({
    type: ioc?.type || 'ipv4',
    value: ioc?.value || '',
    threat_level: ioc?.threat_level || 'medium',
    confidence: ioc?.confidence || 75,
    source: ioc?.source || 'manual',
    metadata: ioc?.metadata ? JSON.stringify(ioc.metadata, null, 2) : '{}',
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      ...formData,
      metadata: JSON.parse(formData.metadata || '{}'),
    })
  }

  const iocTypes = [
    { value: 'ipv4', label: 'IPv4 Address' },
    { value: 'ipv6', label: 'IPv6 Address' },
    { value: 'domain', label: 'Domain' },
    { value: 'url', label: 'URL' },
    { value: 'hash-md5', label: 'MD5 Hash' },
    { value: 'hash-sha1', label: 'SHA1 Hash' },
    { value: 'hash-sha256', label: 'SHA256 Hash' },
    { value: 'email', label: 'Email Address' },
  ]

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
        <h2 className="text-xl font-bold mb-4">
          {ioc ? 'Edit IOC' : 'Add New IOC'}
        </h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Type *
            </label>
            <select 
              value={formData.type}
              onChange={(e) => setFormData({ ...formData, type: e.target.value })}
              className="input-field"
              required
            >
              {iocTypes.map(type => (
                <option key={type.value} value={type.value}>{type.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Value *
            </label>
            <input 
              type="text" 
              value={formData.value}
              onChange={(e) => setFormData({ ...formData, value: e.target.value })}
              placeholder={
                formData.type === 'ipv4' ? '192.168.1.1' :
                formData.type === 'domain' ? 'example.com' :
                formData.type === 'url' ? 'https://example.com/path' :
                formData.type.includes('hash') ? 'abc123...' :
                formData.type === 'email' ? 'user@example.com' :
                'Enter value...'
              }
              className="input-field font-mono"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Threat Level
            </label>
            <select 
              value={formData.threat_level}
              onChange={(e) => setFormData({ ...formData, threat_level: e.target.value })}
              className="input-field"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Confidence ({formData.confidence}%)
            </label>
            <input 
              type="range" 
              min="0"
              max="100"
              value={formData.confidence}
              onChange={(e) => setFormData({ ...formData, confidence: parseInt(e.target.value) })}
              className="w-full"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Source
            </label>
            <input 
              type="text" 
              value={formData.source}
              onChange={(e) => setFormData({ ...formData, source: e.target.value })}
              placeholder="manual, alienvault_otx, abuse_ch..."
              className="input-field"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Metadata (JSON)
            </label>
            <textarea 
              value={formData.metadata}
              onChange={(e) => setFormData({ ...formData, metadata: e.target.value })}
              placeholder='{"description": "..."}'
              className="input-field h-24 font-mono text-sm"
            />
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button 
              type="button"
              onClick={onCancel}
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button 
              type="submit"
              disabled={isLoading}
              className="btn btn-primary"
            >
              {isLoading ? 'Saving...' : (ioc ? 'Update' : 'Create')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
