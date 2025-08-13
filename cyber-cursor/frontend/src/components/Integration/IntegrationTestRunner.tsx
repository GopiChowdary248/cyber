import React, { useState, useEffect } from 'react';
import {
  Play,
  Square,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Download,
  Copy,
  Eye,
  EyeOff,
  Settings,
  Zap,
  Target,
  Server,
  Database,
  Shield,
  Code,
  Cloud,
  Network,
  Monitor,
  BarChart3,
  AlertCircle,
  Lock,
  Info,
  ChevronDown,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import integrationVerificationService, {
  EndpointTestResult,
  ServiceIntegrationStatus
} from '../../services/integrationVerificationService';
import { API_ENDPOINTS, SERVICE_MAPPING } from '../../services/integrationService';

interface IntegrationTestRunnerProps {
  autoRun?: boolean;
  showAdvanced?: boolean;
}

interface TestSuite {
  name: string;
  description: string;
  endpoints: string[];
  icon: React.ReactNode;
}

const IntegrationTestRunner: React.FC<IntegrationTestRunnerProps> = ({
  autoRun = false,
  showAdvanced = false
}) => {
  const [isRunning, setIsRunning] = useState(false);
  const [currentTest, setCurrentTest] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, EndpointTestResult>>({});
  const [selectedService, setSelectedService] = useState<string>('all');
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>('all');
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(showAdvanced);
  const [timeout, setTimeout] = useState(10000);
  const [retryCount, setRetryCount] = useState(3);
  const [concurrentTests, setConcurrentTests] = useState(5);
  const [expandedServices, setExpandedServices] = useState<Set<string>>(new Set());
  const [expandedEndpoints, setExpandedEndpoints] = useState<Set<string>>(new Set());

  const testSuites: TestSuite[] = [
    {
      name: 'SAST Security',
      description: 'Static Application Security Testing endpoints',
      endpoints: ['/api/v1/sast/scan', '/api/v1/sast/reports', '/api/v1/sast/issues'],
      icon: <Code className="w-5 h-5" />
    },
    {
      name: 'DAST Security',
      description: 'Dynamic Application Security Testing endpoints',
      endpoints: ['/api/v1/dast/scan', '/api/v1/dast/reports', '/api/v1/dast/vulnerabilities'],
      icon: <Target className="w-5 h-5" />
    },
    {
      name: 'RASP Security',
      description: 'Runtime Application Self-Protection endpoints',
      endpoints: ['/api/v1/rasp/status', '/api/v1/rasp/events', '/api/v1/rasp/alerts'],
      icon: <Shield className="w-5 h-5" />
    },
    {
      name: 'Cloud Security',
      description: 'Cloud security and compliance endpoints',
      endpoints: ['/api/v1/cloud/security', '/api/v1/cloud/compliance', '/api/v1/cloud/scan'],
      icon: <Cloud className="w-5 h-5" />
    },
    {
      name: 'Network Security',
      description: 'Network security monitoring endpoints',
      endpoints: ['/api/v1/network/scan', '/api/v1/network/threats', '/api/v1/network/firewall'],
      icon: <Network className="w-5 h-5" />
    },
    {
      name: 'Endpoint Security',
      description: 'Endpoint protection and monitoring endpoints',
      endpoints: ['/api/v1/endpoint/status', '/api/v1/endpoint/threats', '/api/v1/endpoint/quarantine'],
      icon: <Monitor className="w-5 h-5" />
    },
    {
      name: 'Data Security',
      description: 'Data protection and encryption endpoints',
      endpoints: ['/api/v1/data/encrypt', '/api/v1/data/decrypt', '/api/v1/data/audit'],
      icon: <Database className="w-5 h-5" />
    },
    {
      name: 'SIEM/SOAR',
      description: 'Security Information and Event Management endpoints',
      endpoints: ['/api/v1/siem/events', '/api/v1/siem/alerts', '/api/v1/soar/incidents'],
      icon: <BarChart3 className="w-5 h-5" />
    },
    {
      name: 'Threat Intelligence',
      description: 'Threat intelligence and analysis endpoints',
      endpoints: ['/api/v1/threat/feed', '/api/v1/threat/analysis', '/api/v1/threat/indicators'],
      icon: <AlertCircle className="w-5 h-5" />
    },
    {
      name: 'Authentication',
      description: 'User authentication and authorization endpoints',
      endpoints: ['/api/v1/auth/login', '/api/v1/auth/register', '/api/v1/auth/verify'],
      icon: <Lock className="w-5 h-5" />
    }
  ];

  useEffect(() => {
    if (autoRun) {
      runAllTests();
    }
  }, [autoRun]);

  const runAllTests = async () => {
    if (isRunning) return;
    
    setIsRunning(true);
    setTestResults({});
    
    try {
      const report = await integrationVerificationService.verifyAllIntegrations();
      
      // Convert the report format to match the expected testResults format
      const results: Record<string, EndpointTestResult> = {};
      report.services.forEach(service => {
        service.endpoints.forEach(endpoint => {
          results[endpoint.endpoint] = endpoint;
        });
      });
      
      setTestResults(results);
    } catch (error) {
      console.error('Test execution failed:', error);
    } finally {
      setIsRunning(false);
      setCurrentTest(null);
    }
  };

  const runServiceTests = async (serviceName: string) => {
    if (isRunning) return;
    
    setIsRunning(true);
    setCurrentTest(`Testing ${serviceName}...`);
    
    try {
      const serviceStatus = await integrationVerificationService.verifyServiceIntegration(serviceName);
      
      // Convert the service status to match the expected testResults format
      const results: Record<string, EndpointTestResult> = {};
      serviceStatus.endpoints.forEach(endpoint => {
        results[endpoint.endpoint] = endpoint;
      });
      
      setTestResults(prev => ({ ...prev, ...results }));
    } catch (error) {
      console.error(`Service test execution failed for ${serviceName}:`, error);
    } finally {
      setIsRunning(false);
      setCurrentTest(null);
    }
  };

  const runEndpointTest = async (endpoint: string) => {
    if (isRunning) return;
    
    setIsRunning(true);
    setCurrentTest(`Testing ${endpoint}...`);
    
    try {
      // For single endpoint testing, we need to find which service it belongs to
      let foundService = '';
      for (const [serviceName, endpoints] of Object.entries(SERVICE_MAPPING)) {
        if (endpoints.includes(endpoint)) {
          foundService = serviceName;
          break;
        }
      }
      
      if (foundService) {
        const serviceStatus = await integrationVerificationService.verifyServiceIntegration(foundService);
        const endpointResult = serviceStatus.endpoints.find(e => e.endpoint === endpoint);
        
        if (endpointResult) {
          setTestResults(prev => ({ ...prev, [endpoint]: endpointResult }));
        }
      }
    } catch (error) {
      console.error(`Endpoint test execution failed for ${endpoint}:`, error);
    } finally {
      setIsRunning(false);
      setCurrentTest(null);
    }
  };

  const stopTests = () => {
    setIsRunning(false);
    setCurrentTest(null);
  };

  const clearResults = () => {
    setTestResults({});
  };

  const exportResults = () => {
    const dataStr = JSON.stringify(testResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `integration-test-results-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyResults = () => {
    navigator.clipboard.writeText(JSON.stringify(testResults, null, 2));
  };

  const toggleServiceExpansion = (serviceName: string) => {
    const newExpanded = new Set(expandedServices);
    if (newExpanded.has(serviceName)) {
      newExpanded.delete(serviceName);
    } else {
      newExpanded.add(serviceName);
    }
    setExpandedServices(newExpanded);
  };

  const toggleEndpointExpansion = (endpoint: string) => {
    const newExpanded = new Set(expandedEndpoints);
    if (newExpanded.has(endpoint)) {
      newExpanded.delete(endpoint);
    } else {
      newExpanded.add(endpoint);
    }
    setExpandedEndpoints(newExpanded);
  };

  const getStatusIcon = (status: EndpointTestResult['status']) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'timeout':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'unauthorized':
        return <Lock className="w-4 h-4 text-orange-500" />;
      default:
        return <Info className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: EndpointTestResult['status']) => {
    switch (status) {
      case 'success':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'failed':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'timeout':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'unauthorized':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getServiceIcon = (serviceName: string) => {
    const iconMap: Record<string, React.ReactNode> = {
      'sastService': <Code className="w-5 h-5" />,
      'dastService': <Target className="w-5 h-5" />,
      'raspService': <Shield className="w-5 h-5" />,
      'cloudSecurityService': <Cloud className="w-5 h-5" />,
      'networkSecurityService': <Network className="w-5 h-5" />,
      'endpointSecurityService': <Monitor className="w-5 h-5" />,
      'dataSecurityService': <Database className="w-5 h-5" />,
      'siemSoarService': <BarChart3 className="w-5 h-5" />,
      'threatIntelligenceService': <AlertCircle className="w-5 h-5" />,
      'authService': <Lock className="w-5 h-5" />,
      'default': <Server className="w-5 h-5" />
    };
    
    return iconMap[serviceName] || iconMap.default;
  };

  const getTestSummary = () => {
    const total = Object.keys(testResults).length;
    const successful = Object.values(testResults).filter(r => r.status === 'success').length;
    const failed = Object.values(testResults).filter(r => r.status === 'failed').length;
    const timeout = Object.values(testResults).filter(r => r.status === 'timeout').length;
    const unauthorized = Object.values(testResults).filter(r => r.status === 'unauthorized').length;
    
    return { total, successful, failed, timeout, unauthorized };
  };

  const summary = getTestSummary();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Integration Test Runner</h1>
            <p className="text-gray-600">
              Test individual endpoints and verify integration status
            </p>
          </div>
          <div className="flex space-x-3">
            {!isRunning ? (
              <button
                onClick={runAllTests}
                className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors flex items-center"
              >
                <Play className="w-4 h-4 mr-2" />
                Run All Tests
              </button>
            ) : (
              <button
                onClick={stopTests}
                className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 transition-colors flex items-center"
              >
                <Square className="w-4 h-4 mr-2" />
                Stop Tests
              </button>
            )}
            <button
              onClick={clearResults}
              className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700 transition-colors flex items-center"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Clear Results
            </button>
            <button
              onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
              className="bg-purple-600 text-white px-4 py-2 rounded-md hover:bg-purple-700 transition-colors flex items-center"
            >
              <Settings className="w-4 h-4 mr-2" />
              Advanced
            </button>
          </div>
        </div>

        {/* Advanced Options */}
        {showAdvancedOptions && (
          <div className="bg-gray-50 rounded-lg p-4 space-y-4">
            <h3 className="font-medium text-gray-900">Advanced Test Configuration</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Timeout (ms)
                </label>
                <input
                  type="number"
                  value={timeout}
                  onChange={(e) => setTimeout(Number(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  min="1000"
                  max="60000"
                  step="1000"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Retry Count
                </label>
                <input
                  type="number"
                  value={retryCount}
                  onChange={(e) => setRetryCount(Number(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  min="0"
                  max="10"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Concurrent Tests
                </label>
                <input
                  type="number"
                  value={concurrentTests}
                  onChange={(e) => setConcurrentTests(Number(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  min="1"
                  max="20"
                />
              </div>
            </div>
          </div>
        )}

        {/* Current Test Status */}
        {currentTest && (
          <div className="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center">
              <RefreshCw className="w-5 h-5 animate-spin text-blue-500 mr-3" />
              <span className="text-blue-800 font-medium">{currentTest}</span>
            </div>
          </div>
        )}

        {/* Test Results Summary */}
        {summary.total > 0 && (
          <div className="mt-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Test Results Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="bg-gray-50 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-gray-900">{summary.total}</p>
                <p className="text-sm text-gray-600">Total</p>
              </div>
              <div className="bg-green-50 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-green-600">{summary.successful}</p>
                <p className="text-sm text-green-600">Successful</p>
              </div>
              <div className="bg-red-50 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-red-600">{summary.failed}</p>
                <p className="text-sm text-red-600">Failed</p>
              </div>
              <div className="bg-yellow-50 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-yellow-600">{summary.timeout}</p>
                <p className="text-sm text-yellow-600">Timeout</p>
              </div>
              <div className="bg-orange-50 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-orange-600">{summary.unauthorized}</p>
                <p className="text-sm text-orange-600">Unauthorized</p>
              </div>
            </div>
            
            <div className="mt-4 flex space-x-3">
              <button
                onClick={exportResults}
                className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 transition-colors flex items-center"
              >
                <Download className="w-4 h-4 mr-2" />
                Export Results
              </button>
              <button
                onClick={copyResults}
                className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors flex items-center"
              >
                <Copy className="w-4 h-4 mr-2" />
                Copy Results
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Test Suites */}
      <div className="space-y-4">
        <h2 className="text-xl font-semibold text-gray-900">Test Suites</h2>
        
        {testSuites.map((suite) => (
          <div key={suite.name} className="bg-white rounded-lg shadow-sm border border-gray-200">
            <div className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className="p-2 bg-gray-100 rounded-lg mr-3">
                    {suite.icon}
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900">{suite.name}</h3>
                    <p className="text-sm text-gray-600">{suite.description}</p>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => runServiceTests(suite.name.toLowerCase().replace(/\s+/g, '') + 'Service')}
                    disabled={isRunning}
                    className="bg-blue-600 text-white px-3 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors text-sm flex items-center"
                  >
                    <Zap className="w-4 h-4 mr-1" />
                    Test Suite
                  </button>
                  <button
                    onClick={() => toggleServiceExpansion(suite.name)}
                    className="p-2 text-gray-500 hover:text-gray-700 transition-colors"
                  >
                    {expandedServices.has(suite.name) ? (
                      <ChevronDown className="w-4 h-4" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Endpoints List */}
            {expandedServices.has(suite.name) && (
              <div className="border-t border-gray-200 p-4 bg-gray-50">
                <div className="space-y-2">
                  {suite.endpoints.map((endpoint) => (
                    <div key={endpoint} className="flex items-center justify-between p-3 bg-white rounded-lg border border-gray-200">
                      <div className="flex items-center">
                        <Target className="w-4 h-4 text-gray-500 mr-2" />
                        <span className="text-sm text-gray-700 font-mono">{endpoint}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {testResults[endpoint] && (
                          <div className={`px-2 py-1 rounded text-xs font-medium border ${getStatusColor(testResults[endpoint].status)}`}>
                            {getStatusIcon(testResults[endpoint].status)}
                            <span className="ml-1">{testResults[endpoint].status}</span>
                          </div>
                        )}
                        <button
                          onClick={() => runEndpointTest(endpoint)}
                          disabled={isRunning}
                          className="bg-green-600 text-white px-3 py-1 rounded-md hover:bg-green-700 disabled:opacity-50 transition-colors text-xs flex items-center"
                        >
                          <Play className="w-3 h-3 mr-1" />
                          Test
                        </button>
                        <button
                          onClick={() => toggleEndpointExpansion(endpoint)}
                          className="p-1 text-gray-500 hover:text-gray-700 transition-colors"
                        >
                          {expandedEndpoints.has(endpoint) ? (
                            <ChevronDown className="w-3 h-3" />
                          ) : (
                            <ChevronRight className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Detailed Results */}
      {Object.keys(testResults).length > 0 && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">Detailed Test Results</h2>
            <div className="space-y-4">
              {Object.entries(testResults).map(([endpoint, result]) => (
                <div key={endpoint} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center">
                      {getStatusIcon(result.status)}
                      <span className="ml-2 font-medium text-gray-900">{endpoint}</span>
                    </div>
                    <div className={`px-3 py-1 rounded-full text-sm font-medium border ${getStatusColor(result.status)}`}>
                      {result.status}
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-gray-600">Method:</span>
                      <span className="ml-2 font-medium">{result.method}</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Response Time:</span>
                      <span className="ml-2 font-medium">{result.responseTime}ms</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Status Code:</span>
                      <span className="ml-2 font-medium">{result.statusCode || 'N/A'}</span>
                    </div>
                  </div>
                  
                  {result.error && (
                    <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                      <p className="text-sm text-red-800">
                        <span className="font-medium">Error:</span> {result.error}
                      </p>
                    </div>
                  )}
                  
                  {result.response && (
                    <div className="mt-3">
                      <button
                        onClick={() => toggleEndpointExpansion(endpoint)}
                        className="text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center"
                      >
                        {expandedEndpoints.has(endpoint) ? (
                          <>
                            <EyeOff className="w-4 h-4 mr-1" />
                            Hide Response
                          </>
                        ) : (
                          <>
                            <Eye className="w-4 h-4 mr-1" />
                            Show Response
                          </>
                        )}
                      </button>
                      
                      {expandedEndpoints.has(endpoint) && (
                        <div className="mt-2 p-3 bg-gray-50 border border-gray-200 rounded-lg">
                          <pre className="text-xs text-gray-800 overflow-x-auto">
                            {JSON.stringify(result.response, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IntegrationTestRunner;
