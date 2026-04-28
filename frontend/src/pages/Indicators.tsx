import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { iocAPI } from '@/services/api'
import { useNavigate } from 'react-router-dom'
import IOCForm from '@/components/IOCCard'
import ConfirmDialog from '@/components/ConfirmDialog'

interface IndicatorsProps {}

export default function Indicators({}: IndicatorsProps) {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [page, setPage] = useState(1)
  const [showForm, setShowForm] = useState(false)
  const [editingIOC, setEditingIOC] = useState<any>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data, isLoading, error } = useQuery({
    queryKey: ['iocs', page, filter],
    queryFn: () => iocAPI.list({ page, page_size: 20, ioc_type: filter !== 'all' ? filter : undefined }),
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => iocAPI.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iocs'] })
      setShowForm(false)
      showToast('IOC created successfully', 'success')
    },
    onError: (error: any) => {
      showToast(error.response?.data?.message || 'Failed to create IOC', 'error')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => iocAPI.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iocs'] })
      setShowForm(false)
      setEditingIOC(null)
      showToast('IOC updated successfully', 'success')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => iocAPI.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iocs'] })
      setDeleteId(null)
      showToast('IOC deleted successfully', 'success')
    },
  })

  const handleDelete = (id: string) => {
    deleteMutation.mutate(id)
  }

  const handleEdit = (ioc: any) => {
    setEditingIOC(ioc)
    setShowForm(true)
  }

  const handleFormSubmit = (data: any) => {
    if (editingIOC) {
      updateMutation.mutate({ id: editingIOC.id, data })
    } else {
      createMutation.mutate(data)
    }
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          Failed to load IOCs. Please try again.
        </div>
      </div>
    )
  }

  // Extract iocs from response - handle both mock and real API
  const iocsList = data?.data ? (Array.isArray(data.data) ? data.data : (data.data.data || [])) : []
  const totalPages = data?.data?.total_pages || 1

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Indicators of Compromise</h1>
          <p className="text-gray-600 mt-1">
            {data?.data?.total || 0} total IOCs
          </p>
        </div>
        <button 
          onClick={() => { setEditingIOC(null); setShowForm(true) }}
          className="btn btn-primary"
        >
          + Add IOC
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-4 mb-6">
        <input 
          type="text" 
          placeholder="Search IOCs..." 
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field flex-1"
        />
        <select 
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="input-field w-auto"
        >
          <option value="all">All Types</option>
          <option value="ipv4">IPv4</option>
          <option value="ipv6">IPv6</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="hash">Hash</option>
        </select>
      </div>

      {/* IOC List */}
      {isLoading ? (
        <LoadingSpinner />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b text-left">
                  <th className="p-3 text-sm font-semibold text-gray-600">Type</th>
                  <th className="p-3 text-sm font-semibold text-gray-600">Value</th>
                  <th className="p-3 text-sm font-semibold text-gray-600">Threat Level</th>
                  <th className="p-3 text-sm font-semibold text-gray-600">Source</th>
                  <th className="p-3 text-sm font-semibold text-gray-600">Last Seen</th>
                  <th className="p-3 text-sm font-semibold text-gray-600">Actions</th>
                </tr>
              </thead>
              <tbody>
                {iocsList.map((ioc: any) => (
                  <tr key={ioc.id || Math.random()} className="border-b hover:bg-gray-50">
                    <td className="p-3">
                      <span className="badge bg-gray-100 text-gray-800">{ioc.type}</span>
                    </td>
                    <td className="p-3 font-mono text-sm">{ioc.value}</td>
                    <td className="p-3">
                      <span className={`badge badge-${ioc.threat_level}`}>
                        {ioc.threat_level}
                      </span>
                    </td>
                    <td className="p-3 text-sm text-gray-600">{ioc.source}</td>
                    <td className="p-3 text-sm text-gray-600">
                      {new Date(ioc.last_seen || Date.now()).toLocaleDateString()}
                    </td>
                    <td className="p-3">
                      <button 
                        onClick={() => handleEdit(ioc)}
                        className="text-blue-600 hover:underline mr-3 text-sm"
                      >
                        Edit
                      </button>
                      <button 
                        onClick={() => setDeleteId(ioc.id)}
                        className="text-red-600 hover:underline text-sm"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex justify-between items-center mt-4">
            <span className="text-sm text-gray-600">
              Page {page} of {totalPages}
            </span>
            <div className="space-x-2">
              <button 
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="btn btn-secondary"
              >
                Previous
              </button>
              <button 
                onClick={() => setPage(p => p + 1)}
                disabled={page >= totalPages}
                className="btn btn-secondary"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}

      {/* Forms & Dialogs */}
      {showForm && (
        <IOCForm 
          ioc={editingIOC}
          onSubmit={handleFormSubmit}
          onCancel={() => { setShowForm(false); setEditingIOC(null) }}
          isLoading={createMutation.isPending || updateMutation.isPending}
        />
      )}

      {deleteId && (
        <ConfirmDialog 
          title="Delete IOC"
          message="Are you sure you want to delete this IOC? This action cannot be undone."
          onConfirm={() => handleDelete(deleteId)}
          onCancel={() => setDeleteId(null)}
          isLoading={deleteMutation.isPending}
        />
      )}
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

// Toast notification helper
function showToast(message: string, type: 'success' | 'error') {
  alert(`${type.toUpperCase()}: ${message}`)
}
