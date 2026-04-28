interface ConfirmDialogProps {
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
  isLoading: boolean
}

export default function ConfirmDialog({ title, message, onConfirm, onCancel, isLoading }: ConfirmDialogProps) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-sm">
        <h2 className="text-xl font-bold mb-2">{title}</h2>
        <p className="text-gray-600 mb-6">{message}</p>
        
        <div className="flex justify-end space-x-3">
          <button 
            onClick={onCancel}
            className="btn btn-secondary"
            disabled={isLoading}
          >
            Cancel
          </button>
          <button 
            onClick={onConfirm}
            className="btn btn-danger"
            disabled={isLoading}
          >
            {isLoading ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  )
}
