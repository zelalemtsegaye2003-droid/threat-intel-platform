import { useState, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { iocAPI, actorAPI } from '@/services/api'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, AreaChart, Area, RadarChart,
  PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
} from 'recharts'
import { format, subDays, parseISO } from 'date-fns'

// Color palette for charts
const COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#8b5cf6',
}

const THREAT_COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6']

// Mock data for demonstration (surpassing MISP's static view)
const MOCK_TIME_SERIES = Array.from({ length: 30 }, (_, i) => ({
  date: format(subDays(new Date(), 29 - i), 'MM/dd'),
  iocs: Math.floor(Math.random() * 50) + 10,
  threats: Math.floor(Math.random() * 20) + 5,
  critical: Math.floor(Math.random() * 8),
}))

const MOCK_GEO_DATA = [
  { country: 'Russia', lat: 61.5, lng: 105.3, count: 145, flag: '🇷🇺' },
  { country: 'China', lat: 35.86, lng: 104.19, count: 132, flag: '🇨🇳' },
  { country: 'USA', lat: 37.09, lng: -95.71, count: 98, flag: '🇺🇸' },
  { country: 'North Korea', lat: 40.33, lng: 127.51, count: 87, flag: '🇰🇵' },
  { country: 'Iran', lat: 32.42, lng: 53.68, count: 76, flag: '🇮🇷' },
  { country: 'Brazil', lat: -14.23, lng: -51.92, count: 45, flag: '🇧🇷' },
]

const MOCK_ATTACK_DATA = [
  { technique: 'Phishing', value: 95 },
  { technique: 'Malware', value: 88 },
  { technique: 'Exploit', value: 72 },
  { technique: 'Credential Stuffing', value: 65 },
  { technique: 'DDoS', value: 45 },
  { technique: 'Ransomware', value: 82 },
]

interface DashboardProps {}

export default function Dashboard({}: DashboardProps) {
  const [timeRange, setTimeRange] = useState('30d')
  const [darkMode, setDarkMode] = useState(false)
  const [selectedMetric, setSelectedMetric] = useState<'iocs' | 'threats' | 'critical'>('iocs')
  
  // Mock mode - replace with real API when backend is up
  const isMock = true

  const { data: iocsData, isLoading: iocsLoading } = useQuery({
    queryKey: ['iocs', 'dashboard'],
    queryFn: () => iocAPI.list({ page: 1, page_size: 100 }),
    enabled: !isMock,
  })

  const { data: actorsData, isLoading: actorsLoading } = useQuery({
    queryKey: ['actors', 'dashboard'],
    queryFn: () => actorAPI.list({ page: 1, page_size: 10 }),
    enabled: !isMock,
  })

  // Enhanced mock stats
  const stats = {
    totalIOCs: isMock ? 2483 : (iocsData?.data?.total || 0),
    critical: isMock ? 87 : 0,
    high: isMock ? 342 : 0,
    medium: isMock ? 856 : 0,
    low: isMock ? 1198 : 0,
    activeActors: isMock ? 23 : 0,
    newToday: isMock ? 34 : 0,
    trend: isMock ? '+12.5%' : '',
  }

  const threatLevelData = [
    { name: 'Critical', value: stats.critical, color: COLORS.critical },
    { name: 'High', value: stats.high, color: COLORS.high },
    { name: 'Medium', value: stats.medium, color: COLORS.medium },
    { name: 'Low', value: stats.low, color: COLORS.low },
  ]

  const isLoading = iocsLoading || actorsLoading

  return (
    <div className={`min-h-screen ${darkMode ? 'bg-gray-900 text-white' : 'bg-gray-100'}`}>
      <div className="max-w-7xl mx-auto px-4 py-6">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className={`text-3xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              Threat Intelligence Dashboard
            </h1>
            <p className={`mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Real-time threat monitoring and analysis
            </p>
          </div>
          <div className="flex items-center gap-4">
            <select 
              value={timeRange} 
              onChange={(e) => setTimeRange(e.target.value)}
              className={`input-field w-auto ${darkMode ? 'bg-gray-800 text-white border-gray-700' : ''}`}
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="90d">Last 90 Days</option>
            </select>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`p-2 rounded-lg ${darkMode ? 'bg-gray-800 text-yellow-400' : 'bg-white text-gray-600'}`}
            >
              {darkMode ? '☀️' : '🌙'}
            </button>
            <button className="btn btn-primary">
              📥 Export Report
            </button>
          </div>
        </div>

        {isLoading ? (
          <LoadingSpinner />
        ) : (
          <>
            {/* Enhanced Stats Cards with Trends */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              <EnhancedStatCard
                title="Total IOCs"
                value={stats.totalIOCs}
                trend="+12.5%"
                trendUp={true}
                icon="🎯"
                color="blue"
                darkMode={darkMode}
              />
              <EnhancedStatCard
                title="Critical Threats"
                value={stats.critical}
                trend="+8.3%"
                trendUp={false}
                icon="🚨"
                color="red"
                darkMode={darkMode}
              />
              <EnhancedStatCard
                title="Active Actors"
                value={stats.activeActors}
                trend="+2"
                trendUp={true}
                icon="👤"
                color="purple"
                darkMode={darkMode}
              />
              <EnhancedStatCard
                title="New Today"
                value={stats.newToday}
                trend="vs yesterday"
                trendUp={true}
                icon="📈"
                color="green"
                darkMode={darkMode}
              />
            </div>

            {/* Main Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              {/* Time Series Chart - Better than MISP's static view */}
              <div className={`p-6 rounded-lg shadow ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <div className="flex justify-between items-center mb-4">
                  <h3 className={`text-lg font-semibold ${darkMode ? 'text-white' : ''}`}>
                    IOC Trends (30 Days)
                  </h3>
                  <div className="flex gap-2">
                    {['iocs', 'threats', 'critical'].map(metric => (
                      <button
                        key={metric}
                        onClick={() => setSelectedMetric(metric as any)}
                        className={`px-3 py-1 text-xs rounded ${
                          selectedMetric === metric
                            ? 'bg-blue-600 text-white'
                            : darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200'
                        }`}
                      >
                        {metric.charAt(0).toUpperCase() + metric.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={MOCK_TIME_SERIES}>
                    <defs>
                      <linearGradient id="colorIocs" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#374151' : '#e5e7eb'} />
                    <XAxis dataKey="date" stroke={darkMode ? '#9ca3af' : '#6b7280'} />
                    <YAxis stroke={darkMode ? '#9ca3af' : '#6b7280'} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: darkMode ? '#1f2937' : '#fff',
                        border: darkMode ? '1px solid #374151' : '1px solid #e5e7eb',
                        color: darkMode ? '#fff' : '#000',
                      }}
                    />
                    <Area 
                      type="monotone" 
                      dataKey={selectedMetric} 
                      stroke="#3b82f6" 
                      fillOpacity={1} 
                      fill="url(#colorIocs)" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Threat Level Distribution with Animation */}
              <div className={`p-6 rounded-lg shadow ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : ''}`}>
                  Threat Level Distribution
                </h3>
                <div className="flex gap-6">
                  <div className="flex-1">
                    <ResponsiveContainer width="100%" height={250}>
                      <PieChart>
                        <Pie
                          data={threatLevelData}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={false}
                          outerRadius={100}
                          fill="#8884d8"
                          dataKey="value"
                          animationBegin={0}
                          animationDuration={1500}
                        >
                          {threatLevelData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip 
                          contentStyle={{ 
                            backgroundColor: darkMode ? '#1f2937' : '#fff',
                            border: darkMode ? '1px solid #374151' : '1px solid #e5e7eb',
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex flex-col justify-center space-y-3">
                    {threatLevelData.map((level) => (
                      <div key={level.name} className="flex items-center gap-2">
                        <div 
                          className="w-3 h-3 rounded-full" 
                          style={{ backgroundColor: level.color }}
                        />
                        <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                          {level.name}: <strong>{level.value}</strong>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Second Row: Radar + Map Placeholder + Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
              {/* ATT&CK Techniques Radar Chart */}
              <div className={`p-6 rounded-lg shadow ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : ''}`}>
                  MITRE ATT&CK Coverage
                </h3>
                <ResponsiveContainer width="100%" height={250}>
                  <RadarChart data={MOCK_ATTACK_DATA}>
                    <PolarGrid stroke={darkMode ? '#374151' : '#e5e7eb'} />
                    <PolarAngleAxis dataKey="technique" stroke={darkMode ? '#9ca3af' : '#6b7280'} />
                    <PolarRadiusAxis 
                      angle={90} 
                      domain={[0, 100]} 
                      stroke={darkMode ? '#9ca3af' : '#6b7280'}
                    />
                    <Radar
                      name="Coverage"
                      dataKey="value"
                      stroke="#8b5cf6"
                      fill="#8b5cf6"
                      fillOpacity={0.6}
                      animationDuration={1500}
                    />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: darkMode ? '#1f2937' : '#fff',
                        border: darkMode ? '1px solid #374151' : '1px solid #e5e7eb',
                      }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              {/* Geographic Threat Map (Placeholder with enhanced stats) */}
              <div className={`p-6 rounded-lg shadow ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : ''}`}>
                  Global Threat Origins
                </h3>
                <div className="space-y-3">
                  {MOCK_GEO_DATA.map((country) => (
                    <div key={country.country} className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{country.flag}</span>
                        <span className={`text-sm font-medium ${darkMode ? 'text-gray-200' : ''}`}>
                          {country.country}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className={`w-32 h-2 rounded-full ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                          <div 
                            className="h-full rounded-full bg-red-500"
                            style={{ width: `${(country.count / 145) * 100}%` }}
                          />
                        </div>
                        <span className={`text-sm font-bold ${darkMode ? 'text-white' : ''}`}>
                          {country.count}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recent Activity Feed */}
              <div className={`p-6 rounded-lg shadow ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : ''}`}>
                  Recent Activity
                </h3>
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {[
                    { time: '2 min ago', action: 'New IOC added', detail: '192.168.1.100 (Critical)', type: 'critical' },
                    { time: '15 min ago', action: 'Actor updated', detail: 'APT29 - New campaign linked', type: 'info' },
                    { time: '1 hour ago', action: 'Feed ingested', detail: 'MISP feed: 34 new IOCs', type: 'success' },
                    { time: '2 hours ago', action: 'Analysis complete', detail: 'LLM report generated', type: 'info' },
                    { time: '3 hours ago', action: 'Correlation found', detail: '5 IOCs linked to APT29', type: 'warning' },
                    { time: '4 hours ago', action: 'IOC expired', detail: 'domain-old.example.com removed', type: 'neutral' },
                  ].map((activity, idx) => (
                    <div key={idx} className={`flex gap-3 p-2 rounded ${darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'}`}>
                      <div className={`w-2 h-2 mt-2 rounded-full flex-shrink-0 ${
                        activity.type === 'critical' ? 'bg-red-500' :
                        activity.type === 'success' ? 'bg-green-500' :
                        activity.type === 'warning' ? 'bg-yellow-500' :
                        activity.type === 'info' ? 'bg-blue-500' : 'bg-gray-400'
                      }`} />
                      <div className="flex-1">
                        <p className={`text-sm font-medium ${darkMode ? 'text-white' : ''}`}>
                          {activity.action}
                        </p>
                        <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {activity.detail}
                        </p>
                        <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                          {activity.time}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Quick Actions & Top IOCs */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className={`p-6 rounded-lg shadow ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : ''}`}>
                  Quick Actions
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  <Link to="/indicators" className="btn btn-primary text-center">
                    + Add New IOC
                  </Link>
                  <Link to="/reports" className="btn btn-secondary text-center">
                    📝 Generate Report
                  </Link>
                  <button className="btn btn-secondary">
                    🔍 Run Enrichment
                  </button>
                  <button className="btn btn-secondary">
                    📊 View Analytics
                  </button>
                </div>
              </div>

              <div className={`p-6 rounded-lg shadow ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : ''}`}>
                  Top Threat Indicators
                </h3>
                <div className="space-y-3">
                  {[
                    { value: '192.168.1.100', type: 'IP', threats: 15, level: 'critical' },
                    { value: 'malicious-site.com', type: 'Domain', threats: 12, level: 'high' },
                    { value: 'a1b2c3d4e5f6...', type: 'Hash', threats: 8, level: 'high' },
                    { value: 'evil-c2.example', type: 'Domain', threats: 7, level: 'medium' },
                  ].map((ioc, idx) => (
                    <div key={idx} className={`flex items-center justify-between p-2 rounded ${
                      darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                    }`}>
                      <div className="flex items-center gap-3">
                        <span className={`badge badge-${ioc.level}`}>
                          {ioc.level}
                        </span>
                        <div>
                          <p className={`text-sm font-mono ${darkMode ? 'text-gray-200' : ''}`}>
                            {ioc.value}
                          </p>
                          <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                            {ioc.type}
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className={`text-sm font-bold ${darkMode ? 'text-white' : ''}`}>
                          {ioc.threats}
                        </p>
                        <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          threats
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function EnhancedStatCard({ title, value, trend, trendUp, icon, color, darkMode }: any) {
  const colorClasses: Record<string, string> = {
    blue: darkMode ? 'border-blue-400 bg-blue-900/20' : 'border-blue-500 bg-blue-50',
    red: darkMode ? 'border-red-400 bg-red-900/20' : 'border-red-500 bg-red-50',
    green: darkMode ? 'border-green-400 bg-green-900/20' : 'border-green-500 bg-green-50',
    purple: darkMode ? 'border-purple-400 bg-purple-900/20' : 'border-purple-500 bg-purple-50',
  }
  
  return (
    <div className={`p-4 rounded-lg shadow border-l-4 ${colorClasses[color] || colorClasses.blue} ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
      <div className="flex justify-between items-start">
        <div>
          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{title}</p>
          <p className={`text-3xl font-bold mt-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            {value.toLocaleString()}
          </p>
          <p className={`text-xs mt-1 ${trendUp ? 'text-green-500' : 'text-red-500'}`}>
            {trendUp ? '↑' : '↓'} {trend}
          </p>
        </div>
        <span className="text-3xl">{icon}</span>
      </div>
    </div>
  )
}

function LoadingSpinner() {
  return (
    <div className="flex justify-center items-center h-64">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
    </div>
  )
}
