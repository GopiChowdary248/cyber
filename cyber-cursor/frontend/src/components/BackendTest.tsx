import React, { useState, useEffect } from 'react';
import { serviceRegistry } from '../services/serviceRegistry';
import { API_ENDPOINTS } from '../services/comprehensiveIntegrationService';

interface TestResult {
  endpoint: string;
  status: 'pending' | 'success' | 'error';
  message: string;
  data?: any;
}

const BackendTest: React.FC = () => {
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);

  const testEndpoints = [
    { name: 'Health Check', endpoint: '/api/v1/health' },
    { name: 'SAST Overview', endpoint: API_ENDPOINTS.SAST.OVERVIEW },
    { name: 'DAST Overview', endpoint: API_ENDPOINTS.DAST.OVERVIEW },
    { name: 'RASP Dashboard', endpoint: API_ENDPOINTS.RASP.DASHBOARD_OVERVIEW },
    { name: 'Cloud Security', endpoint: API_ENDPOINTS.APPLICATION_SECURITY.OVERVIEW },
    { name: 'Dashboard Overview', endpoint: API_ENDPOINTS.DASHBOARD.OVERVIEW },
  ];

  const runTests = async () => {
    setIsRunning(true);
    const results: TestResult[] = [];

    for (const test of testEndpoints) {
      // Add pending result
      const pendingResult: TestResult = {
        endpoint: test.endpoint,
        status: 'pending',
        message: 'Testing...'
      };
      
      setTestResults(prev => [...prev, pendingResult]);

      try {
        // Test the endpoint
        const data = await serviceRegistry.get(test.endpoint);
        
        // Update with success
        const successResult: TestResult = {
          endpoint: test.endpoint,
          status: 'success',
          message: '✅ Success',
          data
        };
        
        setTestResults(prev => 
          prev.map(r => r.endpoint === test.endpoint ? successResult : r)
        );
        
      } catch (error: any) {
        // Update with error
        const errorResult: TestResult = {
          endpoint: test.endpoint,
          status: 'error',
          message: `❌ Error: ${error.message || 'Unknown error'}`
        };
        
        setTestResults(prev => 
          prev.map(r => r.endpoint === test.endpoint ? errorResult : r)
        );
      }
    }
    
    setIsRunning(false);
  };

  const clearResults = () => {
    setTestResults([]);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'text-green-500';
      case 'error': return 'text-red-500';
      case 'pending': return 'text-yellow-500';
      default: return 'text-gray-500';
    }
  };

  return (
    <div className="p-6 bg-gray-900 rounded-lg">
      <h2 className="text-2xl font-bold text-white mb-4">Backend Functionality Test</h2>
      
      <div className="mb-6 space-y-4">
        <div className="flex space-x-4">
          <button
            onClick={runTests}
            disabled={isRunning}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
          >
            {isRunning ? 'Running Tests...' : 'Test Backend Access'}
          </button>
          
          <button
            onClick={clearResults}
            className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
          >
            Clear Results
          </button>
        </div>

        <div className="text-sm text-gray-400">
          <p>This will test if the frontend can access various backend functionalities.</p>
          <p>Make sure the backend server is running on http://localhost:8000</p>
        </div>
      </div>

      {testResults.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-white">Test Results:</h3>
          
          {testResults.map((result, index) => (
            <div key={index} className="p-3 bg-gray-800 rounded border border-gray-700">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm text-gray-300">
                  {result.endpoint}
                </span>
                <span className={`font-semibold ${getStatusColor(result.status)}`}>
                  {result.message}
                </span>
              </div>
              
              {result.data && (
                <div className="mt-2 p-2 bg-gray-700 rounded text-xs text-gray-300">
                  <pre>{JSON.stringify(result.data, null, 2)}</pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-6 p-4 bg-gray-800 rounded">
        <h4 className="text-lg font-semibold text-white mb-2">Available Endpoints:</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
          {testEndpoints.map((test, index) => (
            <div key={index} className="p-2 bg-gray-700 rounded">
              <div className="font-semibold text-blue-400">{test.name}</div>
              <div className="font-mono text-gray-300">{test.endpoint}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default BackendTest;
