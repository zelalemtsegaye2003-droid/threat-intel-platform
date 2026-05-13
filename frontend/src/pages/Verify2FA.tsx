import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'

export default function Verify2FAPage() {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { verifyTOTP, useRecoveryCode } = useAuth()
  const navigate = useNavigate()
  const [useRecovery, setUseRecovery] = useState(false)

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await verifyTOTP(token)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Invalid verification code')
    } finally {
      setLoading(false)
    }
  }

  const handleRecovery = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await useRecoveryCode(token)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Invalid recovery code')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            🔐 Two-Factor Authentication
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            {useRecovery
              ? 'Enter a one-time recovery code'
              : 'Enter the 6-digit code from your authenticator app'}
          </p>
        </div>

        <form className="mt-8 space-y-6" onSubmit={useRecovery ? handleRecovery : handleVerify}>
          {error && (
            <div className="rounded-md bg-red-50 p-4">
              <div className="flex">
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">{error}</h3>
                </div>
              </div>
            </div>
          )}

          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="token" className="sr-only">
                {useRecovery ? 'Recovery code' : 'Verification code'}
              </label>
              <input
                id="token"
                name="token"
                type="text"
                required
                maxLength={useRecovery ? 8 : 6}
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder={useRecovery ? 'ABC123DEF4' : '000000'}
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-lg text-center tracking-[0.5em]"
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading || token.length < (useRecovery ? 8 : 6)}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : useRecovery ? 'Verify Recovery Code' : 'Verify Code'}
            </button>
          </div>

          <div className="text-center">
            <button
              type="button"
              onClick={() => {
                setUseRecovery(!useRecovery)
                setToken('')
                setError('')
              }}
              className="text-sm text-blue-600 hover:text-blue-500 font-medium"
            >
              {useRecovery
                ? 'Use authenticator app code instead'
                : 'Use a recovery code instead'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}