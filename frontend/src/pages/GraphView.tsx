import { useState, useEffect, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { actorAPI, iocAPI } from '@/services/api'

// @ts-ignore - no type definitions available
import CytoscapeComponent from 'react-cytoscapejs'

interface GraphViewProps {}

export default function GraphView({}: GraphViewProps) {
  const { id } = useParams() as { id?: string }
  const [depth, setDepth] = useState(2)

  const { data: graphData, isLoading } = useQuery({
    queryKey: ['graph', id, depth],
    queryFn: () => id 
      ? actorAPI.getGraph(id, depth)
      : iocAPI.list({ page: 1, page_size: 50 }),
  })

  const elements = useCallback(() => {
    if (!graphData?.data) return []
    
    const nodes: any[] = []
    const edges: any[] = []
    
    const rawData: any = graphData.data
    const iocs = Array.isArray(rawData) ? rawData : (rawData?.data || [])
    
    if (id && rawData?.nodes) {
      (rawData.nodes || []).forEach((node: any) => {
        nodes.push({
          data: { id: node.id, label: node.label, type: node.type }
        })
      })
      (rawData.edges || []).forEach((edge: any) => {
        edges.push({
          data: { source: edge.source, target: edge.target, label: edge.label }
        })
      })
    } else if (Array.isArray(iocs)) {
      iocs.forEach((ioc: any) => {
        nodes.push({
          data: { 
            id: ioc.id, 
            label: (ioc.value || '').substring(0, 20), 
            type: ioc.type,
            threat: ioc.threat_level 
          }
        })
      })
    }
    
    return [...nodes, ...edges]
  }, [graphData, id])

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Graph Visualization</h1>
          <p className="text-gray-600 mt-1">
            {id ? `Viewing subgraph for node ${id}` : 'Full IOC relationship graph'}
          </p>
        </div>
        <div className="flex gap-4">
          <select 
            value={depth}
            onChange={(e) => setDepth(parseInt(e.target.value))}
            className="input-field w-auto"
          >
            <option value={1}>Depth 1</option>
            <option value={2}>Depth 2</option>
            <option value={3}>Depth 3</option>
          </select>
          {id && (
            <a href="/graph" className="btn btn-secondary">
              View All
            </a>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center h-96">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : (
        <div className="bg-gray-50 rounded-lg border" style={{ height: '600px' }}>
          <div className="flex items-center justify-center h-full text-gray-500">
            Graph visualization {id ? `for ${id}` : 'of all IOCs'} - Cytoscape.js integration ready
          </div>
        </div>
      )}

      <div className="mt-4 flex gap-4 text-sm text-gray-600">
        <span className="flex items-center">
          <span className="w-3 h-3 bg-blue-500 rounded-full mr-2"></span>
          General
        </span>
        <span className="flex items-center">
          <span className="w-3 h-3 bg-red-500 rounded-full mr-2"></span>
          IPv4
        </span>
        <span className="flex items-center">
          <span className="w-3 h-3 bg-orange-500 rounded-full mr-2"></span>
          Domain
        </span>
      </div>
    </div>
  )
}
