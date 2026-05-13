import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { feedAPI, authAPI } from '@/services/api'

interface SettingsProps {}

export default function Settings({}: SettingsProps) {
  const [activeTab, setActiveTab] = useState('general')
  const [apiKeys, setApiKeys] = useState({
    virustotal: '',
    shodan: '',
    otx: '',
  })
  const [selectedFeed, setSelectedFeed] = useState<any>(null)
  const [mfaEnabled, setMfaEnabled] = useState(false)
  const [totpCode, setTotpCode] = useState('')
  const [passwordForMfa, setPasswordForMfa] = useState('')
  const [mfaError, setMfaError] = useState('')
  const [mfaSuccess, setMfaSuccess] = useState('')
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

  const handleEnableMFA = async () => {
    setMfaError('')
    setMfaSuccess('')
    try {
      // First, enable TOTP on the backend
      const enableRes = await authAPI.enableMFA(passwordForMfa)
      setMfaEnabled(true)
      setMfaSuccess('MFA enabled. Scan the QR code with your authenticator app.')
      // TODO: Display QR code from enableRes.provisioning_uri
    } catch (err: any) {
      setMfaError(err.response?.data?.detail || 'Failed to enable MFA')
    }
  }

  const handleDisableMFA = async () => {
    setMfaError('')
    try {
      await authAPI.disableMFA(passwordForMfa)
      setMfaEnabled(false)
      setMfaSuccess('MFA disabled successfully')
    } catch (err: any) {
      setMfaError(err.response?.data?.detail || 'Failed to disable MFA')
    }
  }

  const tabs = [
    { id: 'general', label: 'General' },
    { id: 'security', label: 'Security' },
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

          {activeTab === 'security' && (
            <div>
              <h3 className="text-lg font-semibold mb-4">Security & Two-Factor Authentication</h3>
              <div className="space-y-6">
                <div className="bg-white p-4 rounded border">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h4 className="font-medium text-gray-900">Multi-Factor Authentication (TOTP)</h4>
                      <p className="text-sm text-gray-600">
                        Add an extra layer of security using an authenticator app (Google Authenticator, Authy, etc.)
                      </p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={mfaEnabled}
                        onChange={(e) => {
                          if (e.target.checked) {
                            handleEnableMFA()
                          } else {
                            handleDisableMFA()
                          }
                        }}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 peer-checked:bg-blue-600"></div>
                    </label>
                  </div>

                  {mfaEnabled && (
                    <div className="mt-4 space-y-3">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Password (to modify MFA settings)
                        </label>
                        <input
                          type="password"
                          value={passwordForMfa}
                          onChange={(e) => setPasswordForMfa(e.target.value)}
                          placeholder="Your current password"
                          className="input-field"
                        />
                      </div>
                      <p className="text-xs text-gray-500">
                        After enabling MFA, you will be prompted for a verification code on each login.
                        Save your recovery codes in a secure location.
                      </p>
                    </div>
                  )}

                  {mfaError && (
                    <div className="mt-3 text-sm text-red-600 bg-red-50 p-2 rounded">
                      {mfaError}
                    </div>
                  )}
                  {mfaSuccess && (
                    <div className="mt-3 text-sm text-green-600 bg-green-50 p-2 rounded">
                      {mfaSuccess}
                    </div>
                  )}
                </div>

                <div className="bg-white p-4 rounded border">
                  <h4 className="font-medium text-gray-900 mb-2">Session Management</h4>
                  <p className="text-sm text-gray-600 mb-3">
                    Current session tokens expire after 30 minutes (12 hours with MFA verified).
                  </p>
                  <button
                    onClick={() => {
                      localStorage.removeItem('access_token')
                      localStorage.removeItem('user')
                      window.location.href = '/login'
                    }}
                    className="btn btn-secondary btn-sm"
                  >
                    Sign Out Everywhere
                  </button>
                </div>
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
                          <button className="btn btn-secondary btn-sm">Edit</button>
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
                    onChange={(e) => setApiKeys({ ...apiKeys, virustotal: e.target.value })}
                    placeholder="Enter VirusTotal API key"
                    className="input-field"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Get your key at{' '}
                    <a href="https://www.virustotal.com" className="text-blue-600">
                      virustotal.com
                    </a>
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Shodan API Key
                  </label>
                  <input
                    type="password"
                    value={apiKeys.shodan}
                    onChange={(e) => setApiKeys({ ...apiKeys, shodan: e.target.value })}
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
                    onChange={(e) => setApiKeys({ ...apiKeys, otx: e.target.value })}
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
    </div>
  )
}