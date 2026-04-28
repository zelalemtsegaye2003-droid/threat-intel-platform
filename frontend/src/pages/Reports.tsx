import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { analysisAPI } from '@/services/api'

interface ReportsProps {}

export default function Reports({}: ReportsProps) {
  const [reportType, setReportType] = useState('ioc-summary')
  const [timeRange, setTimeRange] = useState('7d')
  const [generating, setGenerating] = useState(false)
  const [reportUrl, setReportUrl] = useState<string | null>(null)

  const { data: iocsData } = useQuery({
    queryKey: ['iocs', 'reports'],
    queryFn: () => analysisAPI.generateReport([]),
    enabled: false, // Only run when triggered
  })

  const reportTypes = [
    { value: 'ioc-summary', label: 'IOC Summary Report' },
    { value: 'threat-analysis', label: 'Threat Analysis Report' },
    { value: 'actor-profile', label: 'Threat Actor Profile' },
    { value: 'campaign-report', label: 'Campaign Analysis' },
  ]

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      // In production, this would call the API
      // const response = await analysisAPI.generateReport([])
      // setReportUrl(response.data.url)
      
      // Simulate generation
      await new Promise(resolve => setTimeout(resolve, 2000))
      setReportUrl('#generated-report')
    } catch (error) {
      console.error('Failed to generate report:', error)
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-gray-600 mt-1">Generate and download threat intelligence reports</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Report Configuration */}
        <div className="bg-gray-50 p-6 rounded-lg">
          <h3 className="text-lg font-semibold mb-4">Generate New Report</h3>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Report Type
              </label>
              <select 
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="input-field"
              >
                {reportTypes.map(type => (
                  <option key={type.value} value={type.value}>{type.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Time Range
              </label>
              <select 
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="input-field"
              >
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days</option>
                <option value="90d">Last 90 Days</option>
                <option value="all">All Time</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Format
              </label>
              <div className="flex gap-4">
                <label className="flex items-center">
                  <input type="radio" name="format" value="pdf" className="mr-2" defaultChecked />
                  PDF
                </label>
                <label className="flex items-center">
                  <input type="radio" name="format" value="json" className="mr-2" />
                  JSON (STIX)
                </label>
                <label className="flex items-center">
                  <input type="radio" name="format" value="csv" className="mr-2" />
                  CSV
                </label>
              </div>
            </div>

            <button 
              onClick={handleGenerate}
              disabled={generating}
              className="btn btn-primary w-full"
            >
              {generating ? (
                <>
                  <span className="animate-spin inline-block mr-2">⟳</span>
                  Generating...
                </>
              ) : (
                'Generate Report'
              )}
            </button>
          </div>
        </div>

        {/* Recent Reports */}
        <div className="bg-gray-50 p-6 rounded-lg">
          <h3 className="text-lg font-semibold mb-4">Recent Reports</h3>
          
          {reportUrl ? (
            <div className="bg-green-50 border border-green-200 rounded p-4 mb-4">
              <p className="text-green-800 font-medium">Report generated successfully!</p>
              <a href={reportUrl} download className="btn btn-primary mt-2 inline-block">
                Download Report
              </a>
            </div>
          ) : null}

          <div className="space-y-3">
            {[
              { name: 'IOC Summary - Apr 2026', date: '2026-04-20', type: 'PDF' },
              { name: 'Threat Actor Analysis Q1', date: '2026-04-15', type: 'JSON' },
              { name: 'Campaign Report - APT29', date: '2026-04-10', type: 'PDF' },
            ].map((report, idx) => (
              <div key={idx} className="flex justify-between items-center p-3 bg-white rounded border">
                <div>
                  <p className="font-medium text-sm">{report.name}</p>
                  <p className="text-xs text-gray-600">{report.date} • {report.type}</p>
                </div>
                <button className="text-blue-600 hover:underline text-sm">
                  Download
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Report Preview */}
      {reportUrl && (
        <div className="mt-6 bg-gray-50 p-6 rounded-lg">
          <h3 className="text-lg font-semibold mb-4">Report Preview</h3>
          <div className="bg-white p-4 rounded border font-mono text-sm">
            <pre>{`# Threat Intelligence Report
Generated: ${new Date().toISOString()}
Type: ${reportType}
Time Range: ${timeRange}

## Executive Summary
[Report content would be displayed here]

## Indicators of Compromise
[IOC list would be displayed here]

## Recommendations
[Security recommendations would be listed here]
`}</pre>
          </div>
        </div>
      )}
    </div>
  )
}
