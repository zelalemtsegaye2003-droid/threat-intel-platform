import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { iocAPI, actorAPI } from '@/services/api'
import { useAuth } from '@/context/AuthContext'

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, isAuthenticated, logout } = useAuth()
  const [stats, setStats] = useState({
    totalIOCs: 0,
    activeThreats: 0,
    criticalAlerts: 0,
    sources: 0,
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchStats()
  }, [])

  const fetchStats = async () => {
    try {
      const [iocsRes, actorsRes] = await Promise.all([
        iocAPI.list({ page: 1, page_size: 1 }),
        actorAPI.list({ page: 1, page_size: 1 }),
      ])

      setStats({
        totalIOCs: iocsRes.data?.total || 0,
        activeThreats: iocsRes.data?.total || 0,
        criticalAlerts: 0,
        sources: actorsRes.data?.total || 0,
      })
    } catch (error) {
      console.error('Failed to fetch stats:', error)
    } finally {
      setLoading(false)
    }
  }

  const isActive = (path: string) => {
    return location.pathname === path || location.pathname.startsWith(path)
  }

  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: '📊' },
    { path: '/indicators', label: 'Indicators', icon: '🎯' },
    { path: '/graph', label: 'Graph View', icon: '🕸️' },
    { path: '/reports', label: 'Reports', icon: '📝' },
    { path: '/settings', label: 'Settings', icon: '⚙️' },
  ]

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link to="/dashboard" className="flex items-center space-x-2">
                <span className="text-2xl font-bold text-blue-600">🛡️</span>
                <span className="text-xl font-bold text-gray-900">ThreatIntel</span>
              </Link>

              <div className="hidden md:flex space-x-4">
                {navItems.map((item) => (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isActive(item.path)
                        ? 'bg-blue-100 text-blue-700'
                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                    }`}
                  >
                    <span className="mr-2">{item.icon}</span>
                    {item.label}
                  </Link>
                ))}
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <div className="hidden md:flex items-center space-x-2 text-sm text-gray-600">
                <span className="w-2 h-2 bg-green-500 rounded-full inline-block"></span>
                Services Online
              </div>

{isAuthenticated ? (
                 <div className="flex items-center space-x-3">
                   <span className="text-sm text-gray-600">
                     👤 {user?.username} ({user?.role})
                   </span>
                   {user?.mfa_enabled && (
                     <span className="text-xs text-green-600 bg-green-100 px-2 py-0.5 rounded-full">
                       🔒 2FA
                     </span>
                   )}
                   <button
                     onClick={() => logout()}
                     className="text-sm text-red-600 hover:text-red-800 font-medium"
                   >
                     Logout
                   </button>
                 </div>
               ) : (
                <Link
                  to="/login"
                  className="text-sm text-blue-600 hover:text-blue-800 font-medium"
                >
                  Login
                </Link>
              )}
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 py-6">
        {!loading && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <StatCard title="Total IOCs" value={stats.totalIOCs} color="blue" />
            <StatCard title="Active Threats" value={stats.activeThreats} color="green" />
            <StatCard title="Critical Alerts" value={stats.criticalAlerts} color="red" />
            <StatCard title="Sources" value={stats.sources} color="purple" />
          </div>
        )}

        <div className="bg-white rounded-lg shadow">
          {children}
        </div>
      </main>
    </div>
  )
}

function StatCard({ title, value, color }: { title: string; value: number; color: string }) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    red: 'bg-red-500',
    purple: 'bg-purple-500',
  }

  return (
    <div className="bg-white p-6 rounded-lg shadow border">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mt-2">
            {value}
          </p>
        </div>
        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${colorClasses[color] || colorClasses.blue}`}>
          <span className="text-white text-xl font-bold">{value > 999 ? '1K+' : value}</span>
        </div>
      </div>
    </div>
  )
}
