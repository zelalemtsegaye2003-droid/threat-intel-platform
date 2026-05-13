import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import apiClient from '@/services/api'

interface User {
  username: string
  email: string
  role: string
  is_active: boolean
}

interface AuthContextType {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  register: (username: string, email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
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

  const login = async (username: string, password: string) => {
    const response = await apiClient.post('/auth/login', { username, password })
    const data = response.data
    setToken(data.access_token)
    // Fetch user info
    const userRes = await apiClient.get('/auth/me')
    setUser(userRes.data)
    localStorage.setItem('user', JSON.stringify(userRes.data))
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
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    navigate('/login')
  }

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!token, isLoading, login, register, logout }}>
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