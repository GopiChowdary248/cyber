import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { 
  Play, 
  Square, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  XCircle,
  Settings,
  Target,
  Shield,
  Activity,
  Zap,
  Eye,
  EyeOff
} from 'lucide-react';
import { 
  createScan, 
  startScan, 
  stopScan, 
  getScanDetails, 
  getScanIssues,
  getScanProfiles,
  createScanProfile
} from '../../../services/dastProjectToolsService';

interface ScanIssue {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'false_positive' | 'low' | 'medium' | 'high';
  url: string;
  method: string;
  evidence: any;
  cwe_id?: string;
  references?: string[];
  created_at: string;
}

interface ScanStatus {
  scan_id: string;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed';
  started_at: string;
  progress: number;
  total_requests: number;
  issues: ScanIssue[];
  error?: string;
}

interface DASTScannerProps {
  projectId: string;
}

const DASTScanner: React.FC<DASTScannerProps> = ({ projectId }) => {
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [targetUrls, setTargetUrls] = useState<string>('');
  const [scanConfig, setScanConfig] = useState({
    maxDepth: 3,
    rateLimit: 100,
    modules: ['sql_injection', 'xss', 'csrf', 'open_redirect', 'ssrf'],
    timeout: 30,
    followRedirects: true,
    verifySSL: false
  });
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [showAdvancedConfig, setShowAdvancedConfig] = useState(false);
  const [pollingInterval, setPollingInterval] = useState<NodeJS.Timeout | null>(null);

  const handleStartScan = useCallback(async () => {
    if (!targetUrls.trim()) return;
    
    setIsStarting(true);
    try {
      const urls = targetUrls.split('\n').filter(url => url.trim());
      
      // Create a scan first
      const scanData = {
        profile_id: 'default', // You can make this configurable
        name: `Scan ${new Date().toISOString()}`,
        target_urls: urls,
        scan_config: scanConfig
      };
      
      const scanResponse = await createScan(projectId, scanData);
      
      if (scanResponse && scanResponse.id) {
        // Start the scan
        await startScan(projectId, scanResponse.id);
        
        setScanStatus({
          scan_id: scanResponse.id,
          status: 'running',
          started_at: new Date().toISOString(),
          progress: 0,
          total_requests: urls.length * scanConfig.modules.length,
          issues: []
        });
        
        // Start polling for status updates
        startStatusPolling(scanResponse.id);
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
    } finally {
      setIsStarting(false);
    }
  }, [projectId, targetUrls, scanConfig]);

  const startStatusPolling = useCallback((scanId: string) => {
    const interval = setInterval(async () => {
      try {
        const status = await getScanDetails(projectId, scanId);
        if (status) {
          setScanStatus(prev => prev ? { ...prev, ...status } : null);
          
          if (status.status === 'completed' || status.status === 'failed') {
            clearInterval(interval);
            setPollingInterval(null);
          }
        }
      } catch (error) {
        console.error('Failed to get scan status:', error);
      }
    }, 2000);
    
    setPollingInterval(interval);
  }, [projectId]);

  const handleStopScan = useCallback(async () => {
    if (!scanStatus) return;
    
    setIsStopping(true);
    try {
      await stopScan(projectId, scanStatus.scan_id);
      
      if (scanStatus) {
        setScanStatus({ ...scanStatus, status: 'paused' });
      }
      
      if (pollingInterval) {
        clearInterval(pollingInterval);
        setPollingInterval(null);
      }
    } catch (error) {
      console.error('Failed to stop scan:', error);
    } finally {
      setIsStopping(false);
    }
  }, [projectId, scanStatus, pollingInterval]);

  const loadScanIssues = useCallback(async () => {
    if (!scanStatus?.scan_id) return;
    
    try {
      const issuesResponse = await getScanIssues(projectId, { 
        page: 1, 
        page_size: 1000, 
        scan_id: scanStatus.scan_id 
      });
      
      if (scanStatus && issuesResponse.issues) {
        setScanStatus(prev => prev ? { ...prev, issues: issuesResponse.issues } : null);
      }
    } catch (error) {
      console.error('Failed to load scan issues:', error);
    }
  }, [scanStatus, projectId]);

  useEffect(() => {
    if (scanStatus?.status === 'completed') {
      loadScanIssues();
    }
  }, [scanStatus?.status, loadScanIssues]);

  useEffect(() => {
    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, [pollingInterval]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'high': return 'text-green-600 bg-green-100';
      case 'medium': return 'text-blue-600 bg-blue-100';
      case 'low': return 'text-yellow-600 bg-yellow-100';
      case 'false_positive': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="space-y-6">
      {/* Configuration Panel */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white rounded-lg shadow-sm border border-gray-200 p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
            <Target className="w-5 h-5 text-blue-600" />
            Scanner Configuration
          </h3>
          <button
            onClick={() => setShowAdvancedConfig(!showAdvancedConfig)}
            className="flex items-center gap-2 text-sm text-gray-600 hover:text-gray-900"
          >
            {showAdvancedConfig ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {showAdvancedConfig ? 'Hide' : 'Show'} Advanced
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Target URLs (one per line)
            </label>
            <textarea
              value={targetUrls}
              onChange={(e) => setTargetUrls(e.target.value)}
              placeholder="https://example.com&#10;https://test.example.com"
              className="w-full h-24 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Max Depth
              </label>
              <input
                type="number"
                value={scanConfig.maxDepth}
                onChange={(e) => setScanConfig(prev => ({ ...prev, maxDepth: parseInt(e.target.value) }))}
                min="1"
                max="10"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Rate Limit (requests/sec)
              </label>
              <input
                type="number"
                value={scanConfig.rateLimit}
                onChange={(e) => setScanConfig(prev => ({ ...prev, rateLimit: parseInt(e.target.value) }))}
                min="1"
                max="1000"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </div>

        {showAdvancedConfig && (
          <motion.div 
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="mt-4 pt-4 border-t border-gray-200"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Timeout (seconds)
                </label>
                <input
                  type="number"
                  value={scanConfig.timeout}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
                  min="5"
                  max="300"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="followRedirects"
                  checked={scanConfig.followRedirects}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, followRedirects: e.target.checked }))}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <label htmlFor="followRedirects" className="text-sm text-gray-700">
                  Follow Redirects
                </label>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="verifySSL"
                  checked={scanConfig.verifySSL}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, verifySSL: e.target.checked }))}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <label htmlFor="verifySSL" className="text-sm text-gray-700">
                  Verify SSL
                </label>
              </div>
            </div>

            <div className="mt-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Security Modules
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {['sql_injection', 'xss', 'csrf', 'open_redirect', 'ssrf', 'file_inclusion', 'command_injection'].map(module => (
                  <label key={module} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={scanConfig.modules.includes(module)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setScanConfig(prev => ({ ...prev, modules: [...prev.modules, module] }));
                        } else {
                          setScanConfig(prev => ({ ...prev, modules: prev.modules.filter(m => m !== module) }));
                        }
                      }}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700 capitalize">{module.replace('_', ' ')}</span>
                  </label>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        <div className="mt-6 flex gap-3">
          <button
            onClick={handleStartScan}
            disabled={isStarting || !targetUrls.trim() || scanStatus?.status === 'running'}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play className="w-4 h-4" />
            {isStarting ? 'Starting...' : 'Start Scan'}
          </button>

          {scanStatus?.status === 'running' && (
            <button
              onClick={handleStopScan}
              disabled={isStopping}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
            >
              <Square className="w-4 h-4" />
              {isStopping ? 'Stopping...' : 'Stop Scan'}
            </button>
          )}
        </div>
      </motion.div>

      {/* Scan Status */}
      {scanStatus && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200 p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <Activity className="w-5 h-5 text-green-600" />
              Scan Status
            </h3>
            <div className="flex items-center gap-2">
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                scanStatus.status === 'running' ? 'bg-green-100 text-green-800' :
                scanStatus.status === 'completed' ? 'bg-blue-100 text-blue-800' :
                scanStatus.status === 'failed' ? 'bg-red-100 text-red-800' :
                'bg-gray-100 text-gray-800'
              }`}>
                {scanStatus.status.charAt(0).toUpperCase() + scanStatus.status.slice(1)}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{scanStatus.progress}%</div>
              <div className="text-sm text-gray-600">Progress</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{scanStatus.total_requests}</div>
              <div className="text-sm text-gray-600">Total Requests</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600">{scanStatus.issues.length}</div>
              <div className="text-sm text-gray-600">Issues Found</div>
            </div>
          </div>

          {scanStatus.status === 'running' && (
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${scanStatus.progress}%` }}
              />
            </div>
          )}

          {scanStatus.error && (
            <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
              <div className="flex items-center gap-2 text-red-800">
                <AlertTriangle className="w-4 h-4" />
                <span className="text-sm font-medium">Error: {scanStatus.error}</span>
              </div>
            </div>
          )}
        </motion.div>
      )}

      {/* Scan Issues */}
      {scanStatus?.issues.length > 0 && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200 p-6"
        >
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-red-600" />
            Security Issues Found
          </h3>

          <div className="space-y-4">
            {scanStatus.issues.map((issue) => (
              <div key={issue.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-medium text-gray-900">{issue.title}</h4>
                  <div className="flex gap-2">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(issue.severity)}`}>
                      {issue.severity.charAt(0).toUpperCase() + issue.severity.slice(1)}
                    </span>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getConfidenceColor(issue.confidence)}`}>
                      {issue.confidence.replace('_', ' ').charAt(0).toUpperCase() + issue.confidence.replace('_', ' ').slice(1)}
                    </span>
                  </div>
                </div>
                
                <p className="text-sm text-gray-600 mb-3">{issue.description}</p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-gray-700">URL:</span>
                    <span className="text-gray-600 ml-2 break-all">{issue.url}</span>
                  </div>
                  <div>
                    <span className="font-medium text-gray-700">Method:</span>
                    <span className="text-gray-600 ml-2">{issue.method}</span>
                  </div>
                  {issue.cwe_id && (
                    <div>
                      <span className="font-medium text-gray-700">CWE ID:</span>
                      <span className="text-gray-600 ml-2">{issue.cwe_id}</span>
                    </div>
                  )}
                  <div>
                    <span className="font-medium text-gray-700">Found:</span>
                    <span className="text-gray-600 ml-2">
                      {new Date(issue.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                {issue.references && issue.references.length > 0 && (
                  <div className="mt-3">
                    <span className="font-medium text-gray-700 text-sm">References:</span>
                    <ul className="mt-1 space-y-1">
                      {issue.references.map((ref, index) => (
                        <li key={index}>
                          <a 
                            href={ref} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-800 text-sm break-all"
                          >
                            {ref}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default DASTScanner;
