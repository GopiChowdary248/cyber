import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Square, 
  Settings, 
  FileText, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Download,
  Eye,
  Code,
  Zap
} from 'lucide-react';

interface ScanConfig {
  languages: string[];
  rules: string[];
  severity: string[];
  exclude_patterns: string[];
  include_patterns: string[];
  timeout: number;
  max_issues: number;
  parallel_scans: boolean;
  incremental: boolean;
}

interface ScanResult {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  issues_found: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  start_time: string;
  end_time?: string;
  duration?: number;
  log: string[];
}

interface SASTScannerProps {
  projectId?: string;
  onScanComplete?: (result: ScanResult) => void;
}

const SASTScanner: React.FC<SASTScannerProps> = ({ projectId, onScanComplete }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [showConfig, setShowConfig] = useState(false);
  const [config, setConfig] = useState<ScanConfig>({
    languages: ['java', 'python', 'javascript'],
    rules: ['all'],
    severity: ['critical', 'high', 'medium', 'low'],
    exclude_patterns: ['**/node_modules/**', '**/vendor/**', '**/build/**'],
    include_patterns: ['**/*.java', '**/*.py', '**/*.js', '**/*.ts'],
    timeout: 3600,
    max_issues: 1000,
    parallel_scans: true,
    incremental: true
  });

  const supportedLanguages = [
    { value: 'java', label: 'Java', icon: '☕' },
    { value: 'python', label: 'Python', icon: '🐍' },
    { value: 'javascript', label: 'JavaScript', icon: '⚡' },
    { value: 'typescript', label: 'TypeScript', icon: '📘' },
    { value: 'php', label: 'PHP', icon: '🐘' },
    { value: 'go', label: 'Go', icon: '🐹' },
    { value: 'ruby', label: 'Ruby', icon: '💎' },
    { value: 'csharp', label: 'C#', icon: '🔷' },
    { value: 'cpp', label: 'C++', icon: '⚙️' },
    { value: 'c', label: 'C', icon: '🔧' }
  ];

  const ruleCategories = [
    { value: 'security', label: 'Security Rules', icon: '🔒' },
    { value: 'performance', label: 'Performance Rules', icon: '⚡' },
    { value: 'maintainability', label: 'Maintainability Rules', icon: '🔧' },
    { value: 'reliability', label: 'Reliability Rules', icon: '🛡️' },
    { value: 'accessibility', label: 'Accessibility Rules', icon: '♿' },
    { value: 'custom', label: 'Custom Rules', icon: '⚙️' }
  ];

  const startScan = async () => {
    try {
      setIsScanning(true);
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      
      const scanData = {
        project_id: projectId,
        scan_config: config,
        scan_type: 'static',
        priority: 'high'
      };

      const response = await fetch(`${API_URL}/api/v1/sast/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(scanData),
      });

      if (response.ok) {
        const result = await response.json();
        const newScan: ScanResult = {
          id: result.scan_id,
          status: 'running',
          progress: 0,
          issues_found: 0,
          critical_issues: 0,
          high_issues: 0,
          medium_issues: 0,
          low_issues: 0,
          start_time: new Date().toISOString(),
          log: ['Scan started...']
        };
        
        setCurrentScan(newScan);
        setScanHistory(prev => [newScan, ...prev]);
        
        // Start polling for progress
        pollScanProgress(result.scan_id);
      } else {
        throw new Error('Failed to start scan');
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      setIsScanning(false);
    }
  };

  const stopScan = async () => {
    if (!currentScan) return;
    
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
              await fetch(`${API_URL}/api/v1/sast/scans/${currentScan.id}/stop`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
        },
      });
      
      setCurrentScan(prev => prev ? { ...prev, status: 'failed' } : null);
      setIsScanning(false);
    } catch (error) {
      console.error('Error stopping scan:', error);
    }
  };

  const pollScanProgress = async (scanId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
        const response = await fetch(`${API_URL}/api/v1/sast/scans/${scanId}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          },
        });

        if (response.ok) {
          const result = await response.json();
          
          setCurrentScan(prev => {
            if (!prev) return null;
            
            const updatedScan = {
              ...prev,
              status: result.status,
              progress: result.progress || prev.progress,
              issues_found: result.issues_found || prev.issues_found,
              critical_issues: result.critical_issues || prev.critical_issues,
              high_issues: result.high_issues || prev.high_issues,
              medium_issues: result.medium_issues || prev.medium_issues,
              low_issues: result.low_issues || prev.low_issues,
              log: [...(prev.log || []), ...(result.log || [])]
            };

            if (result.status === 'completed' || result.status === 'failed') {
              updatedScan.end_time = new Date().toISOString();
              updatedScan.duration = new Date(updatedScan.end_time).getTime() - new Date(updatedScan.start_time).getTime();
              setIsScanning(false);
              clearInterval(pollInterval);
              
              if (onScanComplete && result.status === 'completed') {
                onScanComplete(updatedScan);
              }
            }

            return updatedScan;
          });

          setScanHistory(prev => 
            prev.map(scan => 
              scan.id === scanId 
                ? { ...scan, ...result }
                : scan
            )
          );
        }
      } catch (error) {
        console.error('Error polling scan progress:', error);
        clearInterval(pollInterval);
        setIsScanning(false);
      }
    }, 2000); // Poll every 2 seconds
  };

  const downloadReport = async (scanId: string, format: 'pdf' | 'csv' | 'json') => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_URL}/api/v1/sast/scans/${scanId}/report?format=${format}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
        },
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sast-report-${scanId}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Error downloading report:', error);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <Clock className="w-4 h-4 text-blue-500" />;
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-500" />;
      default: return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Code className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900">SAST Scanner</h2>
            <p className="text-sm text-gray-500">Static Application Security Testing</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
          >
            <Settings className="w-4 h-4" />
            <span>Configuration</span>
          </button>
          
          {!isScanning ? (
            <button
              onClick={startScan}
              disabled={!projectId}
              className="flex items-center space-x-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              <Play className="w-4 h-4" />
              <span>Start Scan</span>
            </button>
          ) : (
            <button
              onClick={stopScan}
              className="flex items-center space-x-2 px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700"
            >
              <Square className="w-4 h-4" />
              <span>Stop Scan</span>
            </button>
          )}
        </div>
      </div>

      {/* Configuration Panel */}
      {showConfig && (
        <div className="mb-6 p-4 bg-gray-50 rounded-lg">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Scan Configuration</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Languages */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Target Languages
              </label>
              <div className="space-y-2">
                {supportedLanguages.map(lang => (
                  <label key={lang.value} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={config.languages.includes(lang.value)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setConfig(prev => ({
                            ...prev,
                            languages: [...prev.languages, lang.value]
                          }));
                        } else {
                          setConfig(prev => ({
                            ...prev,
                            languages: prev.languages.filter(l => l !== lang.value)
                          }));
                        }
                      }}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">
                      {lang.icon} {lang.label}
                    </span>
                  </label>
                ))}
              </div>
            </div>

            {/* Rule Categories */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Rule Categories
              </label>
              <div className="space-y-2">
                {ruleCategories.map(category => (
                  <label key={category.value} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={config.rules.includes(category.value)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setConfig(prev => ({
                            ...prev,
                            rules: [...prev.rules, category.value]
                          }));
                        } else {
                          setConfig(prev => ({
                            ...prev,
                            rules: prev.rules.filter(r => r !== category.value)
                          }));
                        }
                      }}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">
                      {category.icon} {category.label}
                    </span>
                  </label>
                ))}
              </div>
            </div>

            {/* Advanced Settings */}
            <div className="md:col-span-2">
              <h4 className="text-sm font-medium text-gray-700 mb-3">Advanced Settings</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    value={config.timeout}
                    onChange={(e) => setConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Max Issues
                  </label>
                  <input
                    type="number"
                    value={config.max_issues}
                    onChange={(e) => setConfig(prev => ({ ...prev, max_issues: parseInt(e.target.value) }))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div className="flex items-center space-x-4">
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={config.parallel_scans}
                      onChange={(e) => setConfig(prev => ({ ...prev, parallel_scans: e.target.checked }))}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">Parallel Scans</span>
                  </label>
                  
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={config.incremental}
                      onChange={(e) => setConfig(prev => ({ ...prev, incremental: e.target.checked }))}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">Incremental</span>
                  </label>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Current Scan Progress */}
      {currentScan && (
        <div className="mb-6 p-4 bg-blue-50 rounded-lg">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-lg font-medium text-gray-900">Current Scan</h3>
            <div className="flex items-center space-x-2">
              {getStatusIcon(currentScan.status)}
              <span className="text-sm font-medium text-gray-700 capitalize">
                {currentScan.status}
              </span>
            </div>
          </div>
          
          {/* Progress Bar */}
          <div className="mb-4">
            <div className="flex justify-between text-sm text-gray-600 mb-1">
              <span>Progress</span>
              <span>{currentScan.progress}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${currentScan.progress}%` }}
              />
            </div>
          </div>
          
          {/* Issue Counts */}
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">{currentScan.critical_issues}</div>
              <div className="text-xs text-gray-500">Critical</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600">{currentScan.high_issues}</div>
              <div className="text-xs text-gray-500">High</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-600">{currentScan.medium_issues}</div>
              <div className="text-xs text-gray-500">Medium</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{currentScan.low_issues}</div>
              <div className="text-xs text-gray-500">Low</div>
            </div>
          </div>
          
          {/* Scan Log */}
          {currentScan.log && currentScan.log.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Scan Log</h4>
              <div className="bg-gray-900 text-green-400 p-3 rounded-md text-sm font-mono max-h-32 overflow-y-auto">
                {currentScan.log.map((log, index) => (
                  <div key={index} className="mb-1">
                    <span className="text-gray-500">[{new Date().toLocaleTimeString()}]</span> {log}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scan History */}
      <div>
        <h3 className="text-lg font-medium text-gray-900 mb-4">Scan History</h3>
        <div className="space-y-3">
          {scanHistory.map((scan) => (
            <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center space-x-4">
                {getStatusIcon(scan.status)}
                <div>
                  <div className="text-sm font-medium text-gray-900">
                    Scan #{scan.id.slice(-8)}
                  </div>
                  <div className="text-xs text-gray-500">
                    {new Date(scan.start_time).toLocaleString()}
                  </div>
                </div>
              </div>
              
              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <div className="text-sm font-medium text-gray-900">
                    {scan.issues_found} issues found
                  </div>
                  <div className="text-xs text-gray-500">
                    {scan.duration ? `${Math.round(scan.duration / 1000)}s` : 'In progress'}
                  </div>
                </div>
                
                {scan.status === 'completed' && (
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => downloadReport(scan.id, 'pdf')}
                      className="p-1 text-gray-400 hover:text-gray-600"
                      title="Download PDF Report"
                    >
                      <FileText className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => downloadReport(scan.id, 'csv')}
                      className="p-1 text-gray-400 hover:text-gray-600"
                      title="Download CSV Report"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => {/* Navigate to scan details */}}
                      className="p-1 text-gray-400 hover:text-gray-600"
                      title="View Details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
          
          {scanHistory.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
              <p>No scans performed yet</p>
              <p className="text-sm">Start your first scan to begin security analysis</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SASTScanner; 