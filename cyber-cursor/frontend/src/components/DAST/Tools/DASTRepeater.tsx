import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Send, 
  Save, 
  Trash2, 
  Copy, 
  Download, 
  Plus, 
  Settings, 
  Eye, 
  EyeOff, 
  Code,
  FileText,
  Hexagon,
  BarChart3,
  RefreshCw,
  Play,
  Square,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle
} from 'lucide-react';

interface RepeaterRequest {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  params: Record<string, string>;
  created_at: string;
  last_sent?: string;
  response_count: number;
}

interface RepeaterResponse {
  id: string;
  request_id: string;
  status_code: number;
  headers: Record<string, string>;
  body: string;
  content_type: string;
  size: number;
  duration: number;
  timestamp: string;
  error?: string;
}

interface EnvironmentVariable {
  key: string;
  value: string;
  description?: string;
}

interface DASTRepeaterProps {
  projectId: string;
}

type ViewMode = 'hex' | 'raw' | 'parsed';

const DASTRepeater: React.FC<DASTRepeaterProps> = ({ projectId }) => {
  const [requests, setRequests] = useState<RepeaterRequest[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<RepeaterRequest | null>(null);
  const [responses, setResponses] = useState<RepeaterResponse[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('parsed');
  const [isSending, setIsSending] = useState(false);
  const [environmentVariables, setEnvironmentVariables] = useState<EnvironmentVariable[]>([
    { key: 'HOST', value: 'localhost', description: 'Target host' },
    { key: 'PORT', value: '8080', description: 'Target port' },
    { key: 'PROTOCOL', value: 'http', description: 'Protocol to use' }
  ]);
  const [showEnvironment, setShowEnvironment] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [settings, setSettings] = useState({
    followRedirects: true,
    verifySSL: false,
    timeout: 30,
    maxRedirects: 5
  });

  const requestNameRef = useRef<HTMLInputElement>(null);
  const urlRef = useRef<HTMLInputElement>(null);

  // Create new request
  const createNewRequest = useCallback(() => {
    const newRequest: RepeaterRequest = {
      id: `req_${Date.now()}`,
      name: `Request ${requests.length + 1}`,
      method: 'GET',
      url: 'http://localhost:8080/',
      headers: {
        'User-Agent': 'DAST-Security-Suite/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
      },
      body: '',
      params: {},
      created_at: new Date().toISOString(),
      response_count: 0
    };

    setRequests(prev => [newRequest, ...prev]);
    setSelectedRequest(newRequest);
  }, [requests]);

  // Update request
  const updateRequest = useCallback((requestId: string, updates: Partial<RepeaterRequest>) => {
    setRequests(prev => prev.map(req => 
      req.id === requestId ? { ...req, ...updates } : req
    ));
    
    if (selectedRequest?.id === requestId) {
      setSelectedRequest(prev => prev ? { ...prev, ...updates } : null);
    }
  }, [selectedRequest]);

  // Delete request
  const deleteRequest = useCallback((requestId: string) => {
    setRequests(prev => prev.filter(req => req.id !== requestId));
    setResponses(prev => prev.filter(resp => resp.request_id !== requestId));
    
    if (selectedRequest?.id === requestId) {
      setSelectedRequest(requests.find(req => req.id !== requestId) || null);
    }
  }, [selectedRequest, requests]);

  // Send request
  const sendRequest = useCallback(async (request: RepeaterRequest) => {
    if (!request.url.trim()) return;

    setIsSending(true);
    const startTime = Date.now();

    try {
      // Process environment variables
      let processedUrl = request.url;
      let processedHeaders = { ...request.headers };
      let processedBody = request.body;

      environmentVariables.forEach(variable => {
        const regex = new RegExp(`\\{\\{${variable.key}\\}\\}`, 'g');
        processedUrl = processedUrl.replace(regex, variable.value);
        processedBody = processedBody.replace(regex, variable.value);
        
        Object.keys(processedHeaders).forEach(headerKey => {
          processedHeaders[headerKey] = processedHeaders[headerKey].replace(regex, variable.value);
        });
      });

      // Prepare request data
      const requestData = {
        method: request.method,
        url: processedUrl,
        headers: processedHeaders,
        body: request.body || undefined,
        params: request.params
      };

      // Send request (this would integrate with your backend)
      const response = await fetch('/api/v1/dast/projects/' + projectId + '/repeater/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData)
      });

      const responseData = await response.json();
      const duration = Date.now() - startTime;

      // Create response record
      const newResponse: RepeaterResponse = {
        id: `resp_${Date.now()}`,
        request_id: request.id,
        status_code: response.status,
        headers: responseData.headers || {},
        body: responseData.body || '',
        content_type: responseData.content_type || 'text/plain',
        size: responseData.body ? responseData.body.length : 0,
        duration,
        timestamp: new Date().toISOString()
      };

      setResponses(prev => [newResponse, ...prev]);
      
      // Update request stats
      updateRequest(request.id, {
        last_sent: new Date().toISOString(),
        response_count: request.response_count + 1
      });

    } catch (error) {
      const duration = Date.now() - startTime;
      const errorResponse: RepeaterResponse = {
        id: `resp_${Date.now()}`,
        request_id: request.id,
        status_code: 0,
        headers: {},
        body: '',
        content_type: 'text/plain',
        size: 0,
        duration,
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error'
      };

      setResponses(prev => [errorResponse, ...prev]);
    } finally {
      setIsSending(false);
    }
  }, [projectId, environmentVariables, updateRequest]);

  // Get latest response for a request
  const getLatestResponse = useCallback((requestId: string) => {
    return responses.find(resp => resp.request_id === requestId);
  }, [responses]);

  // Render content based on view mode
  const renderContent = (content: string, contentType: string) => {
    if (viewMode === 'hex') {
      return (
        <div className="font-mono text-xs bg-gray-900 text-green-400 p-4 rounded overflow-auto">
          {Array.from(content).map((char, index) => (
            <span key={index} className="inline-block w-8 text-center">
              {char.charCodeAt(0).toString(16).padStart(2, '0')}
            </span>
          ))}
        </div>
      );
    }

    if (viewMode === 'raw') {
      return (
        <pre className="font-mono text-xs bg-gray-100 p-4 rounded overflow-auto">
          {content}
        </pre>
      );
    }

    // Parsed view
    if (contentType.includes('json')) {
      try {
        const parsed = JSON.parse(content);
        return (
          <pre className="font-mono text-xs bg-gray-100 p-4 rounded overflow-auto">
            {JSON.stringify(parsed, null, 2)}
          </pre>
        );
      } catch {
        return (
          <pre className="font-mono text-xs bg-gray-100 p-4 rounded overflow-auto">
            {content}
          </pre>
        );
      }
    }

    if (contentType.includes('html')) {
      return (
        <div className="bg-gray-100 p-4 rounded overflow-auto">
          <div dangerouslySetInnerHTML={{ __html: content }} />
        </div>
      );
    }

    return (
      <pre className="font-mono text-xs bg-gray-100 p-4 rounded overflow-auto">
        {content}
      </pre>
    );
  };

  // Add header
  const addHeader = useCallback((requestId: string) => {
    const newKey = `Header-${Object.keys(selectedRequest?.headers || {}).length + 1}`;
    updateRequest(requestId, {
      headers: { ...selectedRequest?.headers, [newKey]: '' }
    });
  }, [selectedRequest, updateRequest]);

  // Remove header
  const removeHeader = useCallback((requestId: string, headerKey: string) => {
    const newHeaders = { ...selectedRequest?.headers };
    delete newHeaders[headerKey];
    updateRequest(requestId, { headers: newHeaders });
  }, [selectedRequest, updateRequest]);

  // Update header
  const updateHeader = useCallback((requestId: string, headerKey: string, value: string) => {
    const newHeaders = { ...selectedRequest?.headers };
    newHeaders[headerKey] = value;
    updateRequest(requestId, { headers: newHeaders });
  }, [selectedRequest, updateRequest]);

  // Copy request as cURL
  const copyAsCurl = useCallback((request: RepeaterRequest) => {
    const headers = Object.entries(request.headers)
      .map(([key, value]) => `-H '${key}: ${value}'`)
      .join(' ');
    
    const body = request.body ? `-d '${request.body}'` : '';
    const method = request.method !== 'GET' ? `-X ${request.method}` : '';
    
    const curl = `curl ${method} ${headers} ${body} '${request.url}'`;
    
    navigator.clipboard.writeText(curl);
  }, []);

  // Export request
  const exportRequest = useCallback((request: RepeaterRequest) => {
    const data = {
      ...request,
      export_time: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `repeater_request_${request.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  // Auto-focus name input when creating new request
  useEffect(() => {
    if (selectedRequest && requestNameRef.current) {
      requestNameRef.current.focus();
    }
  }, [selectedRequest]);

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="bg-white border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-semibold text-gray-900">Repeater</h2>
            <span className="text-sm text-gray-500">
              {requests.length} requests • {responses.length} responses
            </span>
          </div>
          
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setShowEnvironment(!showEnvironment)}
              className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm ${
                showEnvironment ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'
              }`}
            >
              <Code className="w-4 h-4" />
              <span>Environment</span>
            </button>
            
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="flex items-center space-x-2 px-3 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200"
            >
              <Settings className="w-4 h-4" />
              <span>Settings</span>
            </button>
            
            <button
              onClick={createNewRequest}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              <Plus className="w-4 h-4" />
              <span>New Request</span>
            </button>
          </div>
        </div>

        {/* Environment Variables */}
        <AnimatePresence>
          {showEnvironment && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 p-4 bg-gray-50 rounded-lg"
            >
              <h3 className="text-sm font-medium text-gray-900 mb-3">Environment Variables</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {environmentVariables.map((variable, index) => (
                  <div key={index} className="space-y-2">
                    <input
                      type="text"
                      placeholder="Variable name"
                      value={variable.key}
                      onChange={(e) => {
                        const newVars = [...environmentVariables];
                        newVars[index].key = e.target.value;
                        setEnvironmentVariables(newVars);
                      }}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <input
                      type="text"
                      placeholder="Value"
                      value={variable.value}
                      onChange={(e) => {
                        const newVars = [...environmentVariables];
                        newVars[index].value = e.target.value;
                        setEnvironmentVariables(newVars);
                      }}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <input
                      type="text"
                      placeholder="Description (optional)"
                      value={variable.description || ''}
                      onChange={(e) => {
                        const newVars = [...environmentVariables];
                        newVars[index].description = e.target.value;
                        setEnvironmentVariables(newVars);
                      }}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                ))}
              </div>
              <div className="mt-3 text-xs text-gray-600">
                Use variables in requests with {{VARIABLE_NAME}} syntax
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Settings */}
        <AnimatePresence>
          {showSettings && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 p-4 bg-gray-50 rounded-lg"
            >
              <h3 className="text-sm font-medium text-gray-900 mb-3">Request Settings</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={settings.followRedirects}
                    onChange={(e) => setSettings(prev => ({ ...prev, followRedirects: e.target.checked }))}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm">Follow Redirects</span>
                </label>
                
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={settings.verifySSL}
                    onChange={(e) => setSettings(prev => ({ ...prev, verifySSL: e.target.checked }))}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm">Verify SSL</span>
                </label>
                
                <div>
                  <label className="block text-xs text-gray-700 mb-1">Timeout (s)</label>
                  <input
                    type="number"
                    value={settings.timeout}
                    onChange={(e) => setSettings(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
                    className="w-full px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-xs text-gray-700 mb-1">Max Redirects</label>
                  <input
                    type="number"
                    value={settings.maxRedirects}
                    onChange={(e) => setSettings(prev => ({ ...prev, maxRedirects: parseInt(e.target.value) }))}
                    className="w-full px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Requests List */}
        <div className="w-80 bg-white border-r border-gray-200 overflow-y-auto">
          <div className="p-4 border-b border-gray-200">
            <h3 className="text-sm font-medium text-gray-900">Requests</h3>
          </div>
          
          <div className="divide-y divide-gray-200">
            {requests.map((request) => {
              const latestResponse = getLatestResponse(request.id);
              return (
                <div
                  key={request.id}
                  onClick={() => setSelectedRequest(request)}
                  className={`p-3 cursor-pointer hover:bg-gray-50 transition-colors ${
                    selectedRequest?.id === request.id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <input
                      ref={requestNameRef}
                      type="text"
                      value={request.name}
                      onChange={(e) => updateRequest(request.id, { name: e.target.value })}
                      className="text-sm font-medium bg-transparent border-none focus:outline-none focus:ring-0 flex-1"
                      onClick={(e) => e.stopPropagation()}
                    />
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteRequest(request.id);
                      }}
                      className="text-gray-400 hover:text-red-600"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                  
                  <div className="text-xs text-gray-600 mb-2">
                    <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                      request.method === 'GET' ? 'bg-green-100 text-green-800' :
                      request.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                      request.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                      request.method === 'DELETE' ? 'bg-red-100 text-red-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {request.method}
                    </span>
                    <span className="ml-2 truncate">{request.url}</span>
                  </div>
                  
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>{request.response_count} responses</span>
                    {latestResponse && (
                      <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                        latestResponse.status_code >= 200 && latestResponse.status_code < 300 ? 'bg-green-100 text-green-800' :
                        latestResponse.status_code >= 300 && latestResponse.status_code < 400 ? 'bg-blue-100 text-blue-800' :
                        latestResponse.status_code >= 400 && latestResponse.status_code < 500 ? 'bg-yellow-100 text-yellow-800' :
                        latestResponse.status_code >= 500 ? 'bg-red-100 text-red-800' :
                        latestResponse.error ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'
                      }`}>
                        {latestResponse.error ? 'Error' : latestResponse.status_code}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          
          {requests.length === 0 && (
            <div className="p-8 text-center text-gray-500">
              <Code className="w-12 h-12 mx-auto mb-4 text-gray-300" />
              <p className="text-sm">No requests yet</p>
              <p className="text-xs">Create your first request to get started</p>
            </div>
          )}
        </div>

        {/* Request Editor and Response Viewer */}
        <div className="flex-1 flex flex-col">
          {selectedRequest ? (
            <>
              {/* Request Editor */}
              <div className="flex-1 flex flex-col border-b border-gray-200">
                <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                  <h3 className="font-medium text-gray-900">Request Editor</h3>
                </div>
                
                <div className="flex-1 p-4 space-y-4">
                  {/* Method and URL */}
                  <div className="flex space-x-2">
                    <select
                      value={selectedRequest.method}
                      onChange={(e) => updateRequest(selectedRequest.id, { method: e.target.value })}
                      className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="GET">GET</option>
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                      <option value="DELETE">DELETE</option>
                      <option value="PATCH">PATCH</option>
                      <option value="HEAD">HEAD</option>
                      <option value="OPTIONS">OPTIONS</option>
                    </select>
                    
                    <input
                      ref={urlRef}
                      type="text"
                      value={selectedRequest.url}
                      onChange={(e) => updateRequest(selectedRequest.id, { url: e.target.value })}
                      placeholder="Enter URL..."
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    
                    <button
                      onClick={() => sendRequest(selectedRequest)}
                      disabled={isSending}
                      className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2"
                    >
                      {isSending ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Sending...</span>
                        </>
                      ) : (
                        <>
                          <Send className="w-4 h-4" />
                          <span>Send</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Headers */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-medium text-gray-700">Headers</h4>
                      <button
                        onClick={() => addHeader(selectedRequest.id)}
                        className="text-blue-600 hover:text-blue-700 text-sm"
                      >
                        <Plus className="w-4 h-4 inline mr-1" />
                        Add Header
                      </button>
                    </div>
                    
                    <div className="space-y-2">
                      {Object.entries(selectedRequest.headers).map(([key, value]) => (
                        <div key={key} className="flex space-x-2">
                          <input
                            type="text"
                            value={key}
                            onChange={(e) => {
                              const newHeaders = { ...selectedRequest.headers };
                              delete newHeaders[key];
                              newHeaders[e.target.value] = value;
                              updateRequest(selectedRequest.id, { headers: newHeaders });
                            }}
                            className="w-1/3 px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                          />
                          <input
                            type="text"
                            value={value}
                            onChange={(e) => updateHeader(selectedRequest.id, key, e.target.value)}
                            className="flex-1 px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                          />
                          <button
                            onClick={() => removeHeader(selectedRequest.id, key)}
                            className="px-2 py-1 text-red-600 hover:text-red-700"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Body */}
                  {(selectedRequest.method === 'POST' || selectedRequest.method === 'PUT' || selectedRequest.method === 'PATCH') && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-700 mb-2">Request Body</h4>
                      <textarea
                        value={selectedRequest.body}
                        onChange={(e) => updateRequest(selectedRequest.id, { body: e.target.value })}
                        placeholder="Enter request body..."
                        rows={6}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                      />
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex items-center space-x-2 pt-2">
                    <button
                      onClick={() => copyAsCurl(selectedRequest)}
                      className="flex items-center space-x-2 px-3 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
                    >
                      <Copy className="w-4 h-4" />
                      <span>Copy as cURL</span>
                    </button>
                    
                    <button
                      onClick={() => exportRequest(selectedRequest)}
                      className="flex items-center space-x-2 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                    >
                      <Download className="w-4 h-4" />
                      <span>Export</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Response Viewer */}
              <div className="flex-1 flex flex-col">
                <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                  <div className="flex items-center justify-between">
                    <h3 className="font-medium text-gray-900">Response Viewer</h3>
                    
                    <div className="flex space-x-1">
                      <button
                        onClick={() => setViewMode('parsed')}
                        className={`px-3 py-1 text-xs font-medium rounded ${
                          viewMode === 'parsed' 
                            ? 'bg-blue-100 text-blue-700' 
                            : 'text-gray-500 hover:text-gray-700'
                        }`}
                      >
                        <FileText className="w-3 h-3 inline mr-1" />
                        Parsed
                      </button>
                      <button
                        onClick={() => setViewMode('raw')}
                        className={`px-3 py-1 text-xs font-medium rounded ${
                          viewMode === 'raw' 
                            ? 'bg-blue-100 text-blue-700' 
                            : 'text-gray-500 hover:text-gray-700'
                        }`}
                      >
                        <Code className="w-3 h-3 inline mr-1" />
                        Raw
                      </button>
                      <button
                        onClick={() => setViewMode('hex')}
                        className={`px-3 py-1 text-xs font-medium rounded ${
                          viewMode === 'hex' 
                            ? 'bg-blue-100 text-blue-700' 
                            : 'text-gray-500 hover:text-gray-700'
                        }`}
                      >
                        <Hexagon className="w-3 h-3 inline mr-1" />
                        Hex
                      </button>
                    </div>
                  </div>
                </div>
                
                <div className="flex-1 p-4 overflow-auto">
                  {(() => {
                    const latestResponse = getLatestResponse(selectedRequest.id);
                    
                    if (!latestResponse) {
                      return (
                        <div className="text-center text-gray-500 py-8">
                          <Send className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                          <p className="text-lg font-medium">No response yet</p>
                          <p className="text-sm">Click Send to make a request</p>
                        </div>
                      );
                    }

                    if (latestResponse.error) {
                      return (
                        <div className="text-center text-red-500 py-8">
                          <XCircle className="w-16 h-16 mx-auto mb-4" />
                          <p className="text-lg font-medium">Request Failed</p>
                          <p className="text-sm">{latestResponse.error}</p>
                        </div>
                      );
                    }

                    return (
                      <div className="space-y-4">
                        {/* Response Info */}
                        <div className="bg-gray-50 rounded-lg p-4">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div>
                              <span className="font-medium text-gray-700">Status:</span>
                              <span className={`ml-2 inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                                latestResponse.status_code >= 200 && latestResponse.status_code < 300 ? 'bg-green-100 text-green-800' :
                                latestResponse.status_code >= 300 && latestResponse.status_code < 400 ? 'bg-blue-100 text-blue-800' :
                                latestResponse.status_code >= 400 && latestResponse.status_code < 500 ? 'bg-yellow-100 text-yellow-800' :
                                latestResponse.status_code >= 500 ? 'bg-red-100 text-red-800' :
                                'bg-gray-100 text-gray-800'
                              }`}>
                                {latestResponse.status_code}
                              </span>
                            </div>
                            <div>
                              <span className="font-medium text-gray-700">Size:</span>
                              <span className="ml-2 text-gray-600">{latestResponse.size.toLocaleString()} bytes</span>
                            </div>
                            <div>
                              <span className="font-medium text-gray-700">Duration:</span>
                              <span className="ml-2 text-gray-600">{latestResponse.duration}ms</span>
                            </div>
                            <div>
                              <span className="font-medium text-gray-700">Time:</span>
                              <span className="ml-2 text-gray-600">{new Date(latestResponse.timestamp).toLocaleTimeString()}</span>
                            </div>
                          </div>
                        </div>

                        {/* Response Headers */}
                        <div>
                          <h4 className="text-sm font-medium text-gray-700 mb-2">Response Headers</h4>
                          <div className="bg-gray-50 rounded p-3">
                            {Object.entries(latestResponse.headers).map(([key, value]) => (
                              <div key={key} className="text-xs font-mono">
                                <span className="text-blue-600">{key}:</span> {value}
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Response Body */}
                        {latestResponse.body && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-700 mb-2">Response Body</h4>
                            {renderContent(latestResponse.body, latestResponse.content_type)}
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center">
                <Code className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                <p className="text-lg font-medium">No request selected</p>
                <p className="text-sm">Choose a request from the list or create a new one</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DASTRepeater;
