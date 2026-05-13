import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import apiClient from '@/services/api'

interface User {
  username: string
  email: string
  role: string
  is_active: boolean
  mfa_enabled: boolean
}

interface AuthContextType {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<{ requiresMFA: boolean }>
  verifyTOTP: (token: string) => Promise<void>
  useRecoveryCode: (code: string) => Promise<void>
  register: (username: string, email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [pendingAuthToken, setPendingAuthToken] = useState<string | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    // Check for existing session on load
    const storedToken = localStorage.getItem('access_token')
    const storedUser = localStorage.getItem('user')
    if (storedToken && storedUser) {
      setToken(storedToken)
      setUser(JSON.parse(storedUser))
    }
    setIsLoading(false)
  }, [])

  // Attach token to all API requests
  useEffect(() => {
    if (token) {
      apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`
      localStorage.setItem('access_token', token)
    } else {
      delete apiClient.defaults.headers.common['Authorization']
      localStorage.removeItem('access_token')
    }
  }, [token])

  const login = async (username: string, password: string): Promise<{ requiresMFA: boolean }> => {
    try {
      const response = await apiClient.post('/auth/login', { username, password })
      const data = response.data
      setToken(data.access_token)
      // Auto-fetch user info after login
      const userRes = await apiClient.get('/auth/me')
      setUser(userRes.data)
      localStorage.setItem('user', JSON.stringify(userRes.data))
      localStorage.setItem('access_token', data.access_token)
      navigate('/dashboard')
      return { requiresMFA: false }
    } catch (error: any) {
      if (error.response?.status === 403 && error.response?.data?.detail === 'Multi-factor authentication required') {
        // Extract pre-auth token from WWW-Authenticate header
        const authHeader = error.response.headers['www-authenticate']
        const match = authHeader?.match(/pre_auth_token="([^"]+)"/)
        if (match) {
          setPendingAuthToken(match[1])
          return { requiresMFA: true }
        }
      }
      throw error
    }
  }

  const verifyTOTP = async (totpToken: string) => {
    if (!pendingAuthToken) {
      throw new Error('No pending authentication')
    }
    const response = await apiClient.post(
      '/auth/totp/verify',
      { token: totpToken },
      { headers: { Authorization: `Bearer ${pendingAuthToken}` } }
    )
    const data = response.data
    setToken(data.access_token)
    setPendingAuthToken(null)
    // Fetch user info
    const userRes = await apiClient.get('/auth/me')
    setUser(userRes.data)
    localStorage.setItem('user', JSON.stringify(userRes.data))
    localStorage.setItem('access_token', data.access_token)
    navigate('/dashboard')
  }

  const useRecoveryCode = async (code: string) => {
    if (!pendingAuthToken) {
      throw new Error('No pending authentication')
    }
    const response = await apiClient.post(
      '/auth/totp/recovery',
      { recovery_code: code },
      { headers: { Authorization: `Bearer ${pendingAuthToken}` } }
    )
    const data = response.data
    setToken(data.access_token)
    setPendingAuthToken(null)
    const userRes = await apiClient.get('/auth/me')
    setUser(userRes.data)
    localStorage.setItem('user', JSON.stringify(userRes.data))
    localStorage.setItem('access_token', data.access_token)
    navigate('/dashboard')
  }

  const register = async (username: string, email: string, password: string) => {
    await apiClient.post('/auth/register', {
      username,
      email,
      password,
      role: 'viewer',
    })
    // Auto-login after registration
    await login(username, password)
  }

  const logout = () => {
    setToken(null)
    setUser(null)
    setPendingAuthToken(null)
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    navigate('/login')
  }

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!token, isLoading, login, verifyTOTP, useRecoveryCode, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}