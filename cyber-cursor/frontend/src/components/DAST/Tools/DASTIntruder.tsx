import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Zap,
  Play,
  Square,
  RefreshCw,
  Download,
  Trash2,
  Plus,
  Settings,
  Target,
  List,
  BarChart3,
  FileText,
  Code,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  Copy,
  Save
} from 'lucide-react';

interface IntruderRequest {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  params: Record<string, string>;
  attack_type: 'sniper' | 'battering_ram' | 'pitchfork' | 'cluster_bomb';
  payload_sets: PayloadSet[];
  created_at: string;
  status: 'idle' | 'running' | 'paused' | 'completed' | 'error';
  progress: number;
  total_requests: number;
  completed_requests: number;
  successful_requests: number;
  failed_requests: number;
}

interface PayloadSet {
  id: string;
  name: string;
  payloads: string[];
  position: string;
  type: 'simple' | 'regex' | 'file';
}

interface IntruderResult {
  id: string;
  request_id: string;
  payload: string;
  status_code: number;
  response_size: number;
  response_time: number;
  timestamp: string;
  response_headers: Record<string, string>;
  response_body: string;
  content_type: string;
  error?: string;
  highlighted: boolean;
  notes?: string;
}

interface DASTIntruderProps {
  projectId: string;
}

const DASTIntruder: React.FC<DASTIntruderProps> = ({ projectId }) => {
  const [requests, setRequests] = useState<IntruderRequest[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<IntruderRequest | null>(null);
  const [results, setResults] = useState<IntruderResult[]>([]);
  const [showPayloadEditor, setShowPayloadEditor] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [settings, setSettings] = useState({
    threads: 10,
    delay: 0,
    timeout: 30,
    followRedirects: true,
    verifySSL: false
  });
  const [isRunning, setIsRunning] = useState(false);

  const payloadEditorRef = useRef<HTMLTextAreaElement>(null);

  // Create new intruder request
  const createNewRequest = useCallback(() => {
    const newRequest: IntruderRequest = {
      id: `int_${Date.now()}`,
      name: `Intruder Request ${requests.length + 1}`,
      method: 'GET',
      url: 'http://localhost:8080/api/test',
      headers: {
        'User-Agent': 'DAST-Security-Suite/1.0',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: '',
      params: {
        'id': '{{PAYLOAD}}',
        'search': '{{PAYLOAD}}'
      },
      attack_type: 'sniper',
      payload_sets: [
        {
          id: 'ps_1',
          name: 'Default Payloads',
          payloads: ['1', '2', '3', 'admin', 'test', 'null', 'undefined', 'true', 'false'],
          position: 'id',
          type: 'simple'
        }
      ],
      created_at: new Date().toISOString(),
      status: 'idle',
      progress: 0,
      total_requests: 0,
      completed_requests: 0,
      successful_requests: 0,
      failed_requests: 0
    };

    setRequests(prev => [newRequest, ...prev]);
    setSelectedRequest(newRequest);
  }, [requests]);

  // Update request
  const updateRequest = useCallback((requestId: string, updates: Partial<IntruderRequest>) => {
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
    setResults(prev => prev.filter(res => res.request_id !== requestId));

    if (selectedRequest?.id === requestId) {
      setSelectedRequest(requests.find(req => req.id !== requestId) || null);
    }
  }, [selectedRequest, requests]);

  // Add payload set
  const addPayloadSet = useCallback((requestId: string) => {
    const newPayloadSet: PayloadSet = {
      id: `ps_${Date.now()}`,
      name: `Payload Set ${Date.now()}`,
      payloads: ['payload1', 'payload2', 'payload3'],
      position: 'param',
      type: 'simple'
    };

    updateRequest(requestId, {
      payload_sets: [...(selectedRequest?.payload_sets || []), newPayloadSet]
    });
  }, [selectedRequest, updateRequest]);

  // Update payload set
  const updatePayloadSet = useCallback((requestId: string, payloadSetId: string, updates: Partial<PayloadSet>) => {
    const request = requests.find(req => req.id === requestId);
    if (!request) return;

    const updatedPayloadSets = request.payload_sets.map(ps =>
      ps.id === payloadSetId ? { ...ps, ...updates } : ps
    );

    updateRequest(requestId, { payload_sets: updatedPayloadSets });
  }, [requests, updateRequest]);

  // Remove payload set
  const removePayloadSet = useCallback((requestId: string, payloadSetId: string) => {
    const request = requests.find(req => req.id === requestId);
    if (!request) return;

    const updatedPayloadSets = request.payload_sets.filter(ps => ps.id !== payloadSetId);
    updateRequest(requestId, { payload_sets: updatedPayloadSets });
  }, [requests, updateRequest]);

  // Calculate total requests for attack
  const calculateTotalRequests = useCallback((request: IntruderRequest) => {
    switch (request.attack_type) {
      case 'sniper':
        return request.payload_sets.reduce((total, ps) => total + ps.payloads.length, 0);
      case 'battering_ram':
        return Math.max(...request.payload_sets.map(ps => ps.payloads.length));
      case 'pitchfork':
        const minLength = Math.min(...request.payload_sets.map(ps => ps.payloads.length));
        return minLength;
      case 'cluster_bomb':
        return request.payload_sets.reduce((total, ps) => total * ps.payloads.length, 1);
      default:
        return 0;
    }
  }, []);

  // Start attack
  const startAttack = useCallback(async (request: IntruderRequest) => {
    if (!request.url.trim()) return;

    setIsRunning(true);
    updateRequest(request.id, {
      status: 'running',
      progress: 0,
      total_requests: calculateTotalRequests(request),
      completed_requests: 0,
      successful_requests: 0,
      failed_requests: 0
    });

    try {
      // Simulate attack progress
      const totalRequests = calculateTotalRequests(request);
      let completed = 0;
      let successful = 0;
      let failed = 0;

      const interval = setInterval(() => {
        completed += Math.min(settings.threads, totalRequests - completed);
        successful += Math.floor(completed * 0.8);
        failed = completed - successful;

        const progress = (completed / totalRequests) * 100;

        updateRequest(request.id, {
          progress,
          completed_requests: completed,
          successful_requests: successful,
          failed_requests: failed
        });

        if (completed >= totalRequests) {
          clearInterval(interval);
          updateRequest(request.id, { status: 'completed' });
          setIsRunning(false);
        }
      }, 100);

    } catch (error) {
      console.error('Attack failed:', error);
      updateRequest(request.id, { status: 'error' });
      setIsRunning(false);
    }
  }, [calculateTotalRequests, settings.threads, updateRequest]);

  // Stop attack
  const stopAttack = useCallback((requestId: string) => {
    updateRequest(requestId, { status: 'paused' });
    setIsRunning(false);
  }, [updateRequest]);

  // Generate payload combinations
  const generatePayloadCombinations = useCallback((request: IntruderRequest) => {
    const combinations: string[][] = [];

    switch (request.attack_type) {
      case 'sniper':
        request.payload_sets.forEach(ps => {
          ps.payloads.forEach(payload => {
            combinations.push([payload]);
          });
        });
        break;

      case 'battering_ram':
        const maxLength = Math.max(...request.payload_sets.map(ps => ps.payloads.length));
        for (let i = 0; i < maxLength; i++) {
          const combination = request.payload_sets.map(ps => 
            ps.payloads[i] || ps.payloads[ps.payloads.length - 1]
          );
          combinations.push(combination);
        }
        break;

      case 'pitchfork':
        const minLength = Math.min(...request.payload_sets.map(ps => ps.payloads.length));
        for (let i = 0; i < minLength; i++) {
          const combination = request.payload_sets.map(ps => ps.payloads[i]);
          combinations.push(combination);
        }
        break;

      case 'cluster_bomb':
        const generateCombinations = (sets: PayloadSet[], index: number, current: string[]): void => {
          if (index === sets.length) {
            combinations.push([...current]);
            return;
          }

          sets[index].payloads.forEach(payload => {
            current[index] = payload;
            generateCombinations(sets, index + 1, current);
          });
        };

        generateCombinations(request.payload_sets, 0, new Array(request.payload_sets.length));
        break;
    }

    return combinations;
  }, []);

  // Export results
  const exportResults = useCallback((requestId: string) => {
    const requestResults = results.filter(res => res.request_id === requestId);
    const data = {
      request: requests.find(req => req.id === requestId),
      results: requestResults,
      export_time: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `intruder_results_${requestId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [results, requests]);

  // Copy request as cURL
  const copyAsCurl = useCallback((request: IntruderRequest) => {
    const headers = Object.entries(request.headers)
      .map(([key, value]) => `-H '${key}: ${value}'`)
      .join(' ');

    const body = request.body ? `-d '${request.body}'` : '';
    const method = request.method !== 'GET' ? `-X ${request.method}` : '';

    const curl = `curl ${method} ${headers} ${body} '${request.url}'`;

    navigator.clipboard.writeText(curl);
  }, []);

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="bg-white border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-semibold text-gray-900">Intruder</h2>
            <span className="text-sm text-gray-500">
              {requests.length} requests • {results.length} results
            </span>
          </div>

          <div className="flex items-center space-x-4">
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

        {/* Settings */}
        <AnimatePresence>
          {showSettings && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 p-4 bg-gray-50 rounded-lg"
            >
              <h3 className="text-sm font-medium text-gray-900 mb-3">Attack Settings</h3>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div>
                  <label className="block text-xs text-gray-700 mb-1">Threads</label>
                  <input
                    type="number"
                    value={settings.threads}
                    onChange={(e) => setSettings(prev => ({ ...prev, threads: parseInt(e.target.value) }))}
                    className="w-full px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs text-gray-700 mb-1">Delay (ms)</label>
                  <input
                    type="number"
                    value={settings.delay}
                    onChange={(e) => setSettings(prev => ({ ...prev, delay: parseInt(e.target.value) }))}
                    className="w-full px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs text-gray-700 mb-1">Timeout (s)</label>
                  <input
                    type="number"
                    value={settings.timeout}
                    onChange={(e) => setSettings(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
                    className="w-full px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

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
            <h3 className="text-sm font-medium text-gray-900">Intruder Requests</h3>
          </div>

          <div className="divide-y divide-gray-200">
            {requests.map((request) => (
              <div
                key={request.id}
                onClick={() => setSelectedRequest(request)}
                className={`p-3 cursor-pointer hover:bg-gray-50 transition-colors ${
                  selectedRequest?.id === request.id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <input
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

                <div className="flex items-center justify-between text-xs text-gray-500 mb-2">
                  <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                    request.attack_type === 'sniper' ? 'bg-blue-100 text-blue-800' :
                    request.attack_type === 'battering_ram' ? 'bg-green-100 text-green-800' :
                    request.attack_type === 'pitchfork' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-purple-100 text-purple-800'
                  }`}>
                    {request.attack_type.replace('_', ' ')}
                  </span>
                  <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                    request.status === 'running' ? 'bg-green-100 text-green-800' :
                    request.status === 'completed' ? 'bg-blue-100 text-blue-800' :
                    request.status === 'error' ? 'bg-red-100 text-red-800' :
                    request.status === 'paused' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-gray-100 text-gray-600'
                  }`}>
                    {request.status}
                  </span>
                </div>

                {request.status === 'running' && (
                  <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                    <div
                      className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${request.progress}%` }}
                    />
                  </div>
                )}

                <div className="text-xs text-gray-500">
                  {request.completed_requests} / {request.total_requests} requests
                  {request.status === 'completed' && (
                    <span className="ml-2">
                      • {request.successful_requests} success • {request.failed_requests} failed
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {requests.length === 0 && (
            <div className="p-8 text-center text-gray-500">
              <Zap className="w-12 h-12 mx-auto mb-4 text-gray-300" />
              <p className="text-sm">No intruder requests yet</p>
              <p className="text-xs">Create your first request to get started</p>
            </div>
          )}
        </div>

        {/* Request Editor and Results */}
        <div className="flex-1 flex flex-col">
          {selectedRequest ? (
            <>
              {/* Request Editor */}
              <div className="flex-1 flex flex-col border-b border-gray-200">
                <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                  <div className="flex items-center justify-between">
                    <h3 className="font-medium text-gray-900">Request Editor</h3>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => copyAsCurl(selectedRequest)}
                        className="flex items-center space-x-2 px-3 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
                      >
                        <Copy className="w-4 h-4" />
                        <span>Copy as cURL</span>
                      </button>

                      {selectedRequest.status === 'running' ? (
                        <button
                          onClick={() => stopAttack(selectedRequest.id)}
                          className="flex items-center space-x-2 px-3 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
                        >
                          <Square className="w-4 h-4" />
                          <span>Stop</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => startAttack(selectedRequest)}
                          disabled={isRunning}
                          className="flex items-center space-x-2 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
                        >
                          <Play className="w-4 h-4" />
                          <span>Start Attack</span>
                        </button>
                      )}
                    </div>
                  </div>
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
                    </select>

                    <input
                      type="text"
                      value={selectedRequest.url}
                      onChange={(e) => updateRequest(selectedRequest.id, { url: e.target.value })}
                      placeholder="Enter URL..."
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  {/* Attack Type */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Attack Type</label>
                    <select
                      value={selectedRequest.attack_type}
                      onChange={(e) => updateRequest(selectedRequest.id, { attack_type: e.target.value as any })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="sniper">Sniper - Single payload, single position</option>
                      <option value="battering_ram">Battering Ram - Same payload, multiple positions</option>
                      <option value="pitchfork">Pitchfork - Multiple payloads, multiple positions</option>
                      <option value="cluster_bomb">Cluster Bomb - All combinations</option>
                    </select>
                  </div>

                  {/* Payload Sets */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-medium text-gray-700">Payload Sets</h4>
                      <button
                        onClick={() => addPayloadSet(selectedRequest.id)}
                        className="text-blue-600 hover:text-blue-700 text-sm"
                      >
                        <Plus className="w-4 h-4 inline mr-1" />
                        Add Payload Set
                      </button>
                    </div>

                    <div className="space-y-3">
                      {selectedRequest.payload_sets.map((payloadSet, index) => (
                        <div key={payloadSet.id} className="border border-gray-200 rounded-lg p-3">
                          <div className="flex items-center justify-between mb-2">
                            <input
                              type="text"
                              value={payloadSet.name}
                              onChange={(e) => updatePayloadSet(selectedRequest.id, payloadSet.id, { name: e.target.value })}
                              className="text-sm font-medium bg-transparent border-none focus:outline-none focus:ring-0"
                            />
                            <button
                              onClick={() => removePayloadSet(selectedRequest.id, payloadSet.id)}
                              className="text-red-600 hover:text-red-700"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>

                          <div className="grid grid-cols-2 gap-2 mb-2">
                            <input
                              type="text"
                              value={payloadSet.position}
                              onChange={(e) => updatePayloadSet(selectedRequest.id, payloadSet.id, { position: e.target.value })}
                              placeholder="Position (e.g., id, search)"
                              className="px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <select
                              value={payloadSet.type}
                              onChange={(e) => updatePayloadSet(selectedRequest.id, payloadSet.id, { type: e.target.value as any })}
                              className="px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                            >
                              <option value="simple">Simple List</option>
                              <option value="regex">Regex</option>
                              <option value="file">File</option>
                            </select>
                          </div>

                          <textarea
                            value={payloadSet.payloads.join('\n')}
                            onChange={(e) => updatePayloadSet(selectedRequest.id, payloadSet.id, { 
                              payloads: e.target.value.split('\n').filter(p => p.trim()) 
                            })}
                            placeholder="Enter payloads (one per line)"
                            rows={3}
                            className="w-full px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                          />
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
                        rows={4}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                      />
                    </div>
                  )}
                </div>
              </div>

              {/* Results */}
              <div className="flex-1 flex flex-col">
                <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                  <div className="flex items-center justify-between">
                    <h3 className="font-medium text-gray-900">Attack Results</h3>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => exportResults(selectedRequest.id)}
                        className="flex items-center space-x-2 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                      >
                        <Download className="w-4 h-4" />
                        <span>Export</span>
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex-1 p-4 overflow-auto">
                  {selectedRequest.status === 'idle' ? (
                    <div className="text-center text-gray-500 py-8">
                      <Target className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                      <p className="text-lg font-medium">Ready to Attack</p>
                      <p className="text-sm">Configure your payloads and click Start Attack</p>
                    </div>
                  ) : selectedRequest.status === 'running' ? (
                    <div className="text-center text-gray-500 py-8">
                      <RefreshCw className="w-16 h-16 mx-auto mb-4 text-gray-300 animate-spin" />
                      <p className="text-lg font-medium">Attack in Progress</p>
                      <p className="text-sm">
                        {selectedRequest.completed_requests} of {selectedRequest.total_requests} requests completed
                      </p>
                    </div>
                  ) : selectedRequest.status === 'completed' ? (
                    <div className="text-center text-gray-500 py-8">
                      <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-500" />
                      <p className="text-lg font-medium">Attack Completed</p>
                      <p className="text-sm">
                        {selectedRequest.successful_requests} successful • {selectedRequest.failed_requests} failed
                      </p>
                    </div>
                  ) : (
                    <div className="text-center text-gray-500 py-8">
                      <AlertTriangle className="w-16 h-16 mx-auto mb-4 text-red-500" />
                      <p className="text-lg font-medium">Attack Failed</p>
                      <p className="text-sm">Check your configuration and try again</p>
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center">
                <Zap className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                <p className="text-lg font-medium">No request selected</p>
                <p className="text-sm">Choose an intruder request from the list or create a new one</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DASTIntruder;
