import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { feedAPI } from '@/services/api'

interface SettingsProps {}

export default function Settings({}: SettingsProps) {
  const [activeTab, setActiveTab] = useState('general')
  const [apiKeys, setApiKeys] = useState({
    virustotal: '',
    shodan: '',
    otx: '',
  })
  const [selectedFeed, setSelectedFeed] = useState<any>(null)
  const queryClient = useQueryClient()

  const { data: feedsData, isLoading } = useQuery({
    queryKey: ['feeds'],
    queryFn: () => feedAPI.list(),
  })

  const registerFeedMutation = useMutation({
    mutationFn: (data: any) => feedAPI.register(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] })
      setSelectedFeed(null)
      alert('Feed registered successfully!')
    },
  })

  const ingestFeedMutation = useMutation({
    mutationFn: ({ feedId, force }: { feedId: string; force?: boolean }) => 
      feedAPI.ingest(feedId, force),
    onSuccess: () => {
      alert('Feed ingestion started!')
    },
  })

  const tabs = [
    { id: 'general', label: 'General' },
    { id: 'feeds', label: 'Threat Feeds' },
    { id: 'api', label: 'API Keys' },
    { id: 'users', label: 'Users' },
  ]

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-600 mt-1">Configure your threat intelligence platform</p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-48 flex-shrink-0">
          <nav className="space-y-1">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full text-left px-3 py-2 rounded-md text-sm font-medium ${
                  activeTab === tab.id
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 bg-gray-50 p-6 rounded-lg">
          {activeTab === 'general' && (
            <div>
              <h3 className="text-lg font-semibold mb-4">General Settings</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Platform Name
                  </label>
                  <input 
                    type="text" 
                    defaultValue="ThreatIntel Platform"
                    className="input-field"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Default Threat Level
                  </label>
                  <select className="input-field">
                    <option value="low">Low</option>
                    <option value="medium" selected>Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="flex items-center">
                    <input type="checkbox" className="mr-2" defaultChecked />
                    Enable automatic enrichment
                  </label>
                </div>
                <div>
                  <label className="flex items-center">
                    <input type="checkbox" className="mr-2" defaultChecked />
                    Enable LLM analysis
                  </label>
                </div>
                <button className="btn btn-primary">Save Settings</button>
              </div>
            </div>
          )}

          {activeTab === 'feeds' && (
            <div>
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-semibold">Threat Feeds</h3>
                <button 
                  onClick={() => setSelectedFeed({})}
                  className="btn btn-primary btn-sm"
                >
                  + Register Feed
                </button>
              </div>

          {isLoading ? (
            <div className="text-center py-8">Loading feeds...</div>
          ) : (
            <div className="space-y-3">
              {(feedsData?.data || []).map((feed: any) => (
                <div key={feed.id || Math.random()} className="bg-white p-4 rounded border">
                  <div className="flex justify-between items-start">
                    <div>
                      <h4 className="font-medium">{feed.name}</h4>
                      <p className="text-sm text-gray-600">{feed.url}</p>
                      <div className="flex gap-4 mt-2 text-xs text-gray-500">
                        <span>Type: {feed.type}</span>
                        <span>Status: {feed.status}</span>
                        <span>Last Ingest: {feed.last_ingest || 'Never'}</span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button 
                        onClick={() => ingestFeedMutation.mutate({ feedId: feed.id })}
                        className="btn btn-secondary btn-sm"
                        disabled={ingestFeedMutation.isPending}
                      >
                        Ingest Now
                      </button>
                      <button className="btn btn-secondary btn-sm">
                        Edit
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
            </div>
          )}

          {activeTab === 'api' && (
            <div>
              <h3 className="text-lg font-semibold mb-4">API Keys</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    VirusTotal API Key
                  </label>
                  <input 
                    type="password" 
                    value={apiKeys.virustotal}
                    onChange={(e) => setApiKeys({...apiKeys, virustotal: e.target.value})}
                    placeholder="Enter VirusTotal API key"
                    className="input-field"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Get your key at <a href="https://www.virustotal.com" className="text-blue-600">virustotal.com</a>
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Shodan API Key
                  </label>
                  <input 
                    type="password" 
                    value={apiKeys.shodan}
                    onChange={(e) => setApiKeys({...apiKeys, shodan: e.target.value})}
                    placeholder="Enter Shodan API key"
                    className="input-field"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    AlienVault OTX API Key
                  </label>
                  <input 
                    type="password" 
                    value={apiKeys.otx}
                    onChange={(e) => setApiKeys({...apiKeys, otx: e.target.value})}
                    placeholder="Enter OTX API key"
                    className="input-field"
                  />
                </div>
                <button className="btn btn-primary">Save API Keys</button>
              </div>
            </div>
          )}

          {activeTab === 'users' && (
            <div>
              <h3 className="text-lg font-semibold mb-4">User Management</h3>
              <p className="text-gray-600">User management interface would be implemented here.</p>
            </div>
          )}
        </div>
      </div>

      {/* Feed Registration Modal */}
      {selectedFeed !== null && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-bold mb-4">
              {selectedFeed.id ? 'Edit Feed' : 'Register New Feed'}
            </h3>
            <form onSubmit={(e) => {
              e.preventDefault()
              const formData = new FormData(e.target as HTMLFormElement)
              registerFeedMutation.mutate(Object.fromEntries(formData))
            }}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Feed Name</label>
                  <input name="name" required className="input-field" />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Feed URL</label>
                  <input name="url" type="url" required className="input-field" />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Feed Type</label>
                  <select name="type" className="input-field">
                    <option value="misp">MISP Feed</option>
                    <option value="taxii">TAXII Feed</option>
                    <option value="otx">AlienVault OTX</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div className="flex justify-end gap-3">
                  <button 
                    type="button"
                    onClick={() => setSelectedFeed(null)}
                    className="btn btn-secondary"
                  >
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary">
                    Register
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
