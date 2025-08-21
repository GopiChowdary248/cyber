import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Search, 
  Filter, 
  Download, 
  Trash2, 
  Eye, 
  EyeOff, 
  Copy, 
  Send, 
  RefreshCw,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Code,
  FileText,
  Hexagon,
  BarChart3,
  Settings
} from 'lucide-react';
import { dastProjectToolsService } from '../../../services/dastProjectToolsService';

interface HttpEntry {
  id: string;
  method: string;
  url: string;
  status_code?: number;
  content_type?: string;
  request_size: number;
  response_size: number;
  time: string;
  duration: number;
  request: {
    headers: Record<string, string>;
    body?: string;
    params?: Record<string, string>;
  };
  response?: {
    headers: Record<string, string>;
    body?: string;
    status_code: number;
  };
  tags: string[];
  notes?: string;
  highlighted: boolean;
}

interface DASTHttpHistoryProps {
  projectId: string;
}

type ViewMode = 'hex' | 'raw' | 'parsed';
type SortField = 'time' | 'method' | 'url' | 'status' | 'size' | 'duration';

const DASTHttpHistory: React.FC<DASTHttpHistoryProps> = ({ projectId }) => {
  const [entries, setEntries] = useState<HttpEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<HttpEntry | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('parsed');
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    method: 'all',
    status: 'all',
    contentType: 'all',
    tags: [] as string[]
  });
  const [sortField, setSortField] = useState<SortField>('time');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [showFilters, setShowFilters] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState<NodeJS.Timeout | null>(null);

  // Load HTTP history
  const loadHistory = useCallback(async () => {
    try {
      setLoading(true);
      const response = await dastProjectToolsService.getHttpHistory(projectId, {
        page: 1,
        page_size: 1000
      });
      
      if (response?.entries) {
        const formattedEntries = response.entries.map((entry: any) => ({
          id: entry.id,
          method: entry.method,
          url: entry.url,
          status_code: entry.status,
          content_type: entry.response?.headers?.['content-type'] || 'unknown',
          request_size: entry.request_size || 0,
          response_size: entry.response_size || 0,
          time: entry.created_at || entry.time,
          duration: entry.duration || 0,
          request: {
            headers: entry.request_headers || {},
            body: entry.request_body,
            params: entry.request_params || {}
          },
          response: entry.response ? {
            headers: entry.response.headers || {},
            body: entry.response.body,
            status_code: entry.response.status_code || entry.status
          } : undefined,
          tags: entry.tags || [],
          notes: entry.notes,
          highlighted: false
        }));
        
        setEntries(formattedEntries);
      }
    } catch (error) {
      console.error('Failed to load HTTP history:', error);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  // Auto-refresh setup
  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(loadHistory, 5000);
      setRefreshInterval(interval);
      return () => clearInterval(interval);
    } else if (refreshInterval) {
      clearInterval(refreshInterval);
      setRefreshInterval(null);
    }
  }, [autoRefresh, loadHistory]);

  // Initial load
  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  // Filtered and sorted entries
  const filteredEntries = useMemo(() => {
    let filtered = entries.filter(entry => {
      // Search filter
      if (searchTerm) {
        const searchLower = searchTerm.toLowerCase();
        const matchesSearch = 
          entry.url.toLowerCase().includes(searchLower) ||
          entry.method.toLowerCase().includes(searchLower) ||
          (entry.request.body || '').toLowerCase().includes(searchLower) ||
          (entry.response?.body || '').toLowerCase().includes(searchLower);
        
        if (!matchesSearch) return false;
      }

      // Method filter
      if (filters.method !== 'all' && entry.method !== filters.method) return false;

      // Status filter
      if (filters.status !== 'all') {
        const status = entry.status_code || 0;
        if (filters.status === 'success' && (status < 200 || status >= 300)) return false;
        if (filters.status === 'redirect' && (status < 300 || status >= 400)) return false;
        if (filters.status === 'client_error' && (status < 400 || status >= 500)) return false;
        if (filters.status === 'server_error' && status < 500) return false;
      }

      // Content type filter
      if (filters.contentType !== 'all' && !entry.content_type?.includes(filters.contentType)) return false;

      return true;
    });

    // Sorting
    filtered.sort((a, b) => {
      let aValue: any, bValue: any;
      
      switch (sortField) {
        case 'time':
          aValue = new Date(a.time).getTime();
          bValue = new Date(b.time).getTime();
          break;
        case 'method':
          aValue = a.method;
          bValue = b.method;
          break;
        case 'url':
          aValue = a.url;
          bValue = b.url;
          break;
        case 'status':
          aValue = a.status_code || 0;
          bValue = b.status_code || 0;
          break;
        case 'size':
          aValue = a.request_size + a.response_size;
          bValue = b.request_size + b.response_size;
          break;
        case 'duration':
          aValue = a.duration;
          bValue = b.duration;
          break;
        default:
          aValue = a.time;
          bValue = b.time;
      }

      if (sortDirection === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

    return filtered;
  }, [entries, searchTerm, filters, sortField, sortDirection]);

  // Handle entry selection
  const handleEntrySelect = useCallback((entry: HttpEntry) => {
    setSelectedEntry(entry);
  }, []);

  // Handle sort
  const handleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  }, [sortField]);

  // Send to repeater
  const sendToRepeater = useCallback((entry: HttpEntry) => {
    // This will be implemented when we create the Repeater component
    console.log('Sending to repeater:', entry);
  }, []);

  // Copy as cURL
  const copyAsCurl = useCallback((entry: HttpEntry) => {
    const headers = Object.entries(entry.request.headers)
      .map(([key, value]) => `-H '${key}: ${value}'`)
      .join(' ');
    
    const body = entry.request.body ? `-d '${entry.request.body}'` : '';
    const method = entry.method !== 'GET' ? `-X ${entry.method}` : '';
    
    const curl = `curl ${method} ${headers} ${body} '${entry.url}'`;
    
    navigator.clipboard.writeText(curl);
  }, []);

  // Export entry
  const exportEntry = useCallback((entry: HttpEntry) => {
    const data = {
      ...entry,
      export_time: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `http_entry_${entry.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  // Render request/response content
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

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="bg-white border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-semibold text-gray-900">HTTP History</h2>
            <span className="text-sm text-gray-500">
              {filteredEntries.length} of {entries.length} entries
            </span>
          </div>
          
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm ${
                autoRefresh 
                  ? 'bg-green-100 text-green-700' 
                  : 'bg-gray-100 text-gray-700'
              }`}
            >
              <RefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
              <span>Auto-refresh</span>
            </button>
            
            <button
              onClick={loadHistory}
              disabled={loading}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="mt-4 flex items-center space-x-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search in URL, method, request/response body..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm ${
              showFilters ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'
            }`}
          >
            <Filter className="w-4 h-4" />
            <span>Filters</span>
          </button>
        </div>

        {/* Advanced Filters */}
        <AnimatePresence>
          {showFilters && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4"
            >
              <select
                value={filters.method}
                onChange={(e) => setFilters(prev => ({ ...prev, method: e.target.value }))}
                className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
              </select>
              
              <select
                value={filters.status}
                onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Status</option>
                <option value="success">Success (2xx)</option>
                <option value="redirect">Redirect (3xx)</option>
                <option value="client_error">Client Error (4xx)</option>
                <option value="server_error">Server Error (5xx)</option>
              </select>
              
              <select
                value={filters.contentType}
                onChange={(e) => setFilters(prev => ({ ...prev, contentType: e.target.value }))}
                className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Content Types</option>
                <option value="html">HTML</option>
                <option value="json">JSON</option>
                <option value="xml">XML</option>
                <option value="text">Text</option>
                <option value="image">Image</option>
              </select>
              
              <button
                onClick={() => setFilters({ method: 'all', status: 'all', contentType: 'all', tags: [] })}
                className="px-3 py-2 text-sm text-gray-600 hover:text-gray-800"
              >
                Clear Filters
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Entries List */}
        <div className="w-1/2 bg-white border-r border-gray-200 overflow-y-auto">
          {/* Table Header */}
          <div className="sticky top-0 bg-gray-50 border-b border-gray-200">
            <div className="grid grid-cols-12 gap-2 p-3 text-xs font-medium text-gray-700">
              <div className="col-span-2">
                <button
                  onClick={() => handleSort('method')}
                  className="flex items-center space-x-1 hover:text-gray-900"
                >
                  <span>Method</span>
                  {sortField === 'method' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </button>
              </div>
              <div className="col-span-6">
                <button
                  onClick={() => handleSort('url')}
                  className="flex items-center space-x-1 hover:text-gray-900"
                >
                  <span>URL</span>
                  {sortField === 'url' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </button>
              </div>
              <div className="col-span-1">
                <button
                  onClick={() => handleSort('status')}
                  className="flex items-center space-x-1 hover:text-gray-900"
                >
                  <span>Status</span>
                  {sortField === 'status' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </button>
              </div>
              <div className="col-span-1">
                <button
                  onClick={() => handleSort('size')}
                  className="flex items-center space-x-1 hover:text-gray-900"
                >
                  <span>Size</span>
                  {sortField === 'size' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </button>
              </div>
              <div className="col-span-2">
                <button
                  onClick={() => handleSort('time')}
                  className="flex items-center space-x-1 hover:text-gray-900"
                >
                  <span>Time</span>
                  {sortField === 'time' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Entries */}
          <div className="divide-y divide-gray-200">
            {filteredEntries.map((entry) => (
              <div
                key={entry.id}
                onClick={() => handleEntrySelect(entry)}
                className={`p-3 cursor-pointer hover:bg-gray-50 transition-colors ${
                  selectedEntry?.id === entry.id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
                }`}
              >
                <div className="grid grid-cols-12 gap-2 text-sm">
                  <div className="col-span-2">
                    <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                      entry.method === 'GET' ? 'bg-green-100 text-green-800' :
                      entry.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                      entry.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                      entry.method === 'DELETE' ? 'bg-red-100 text-red-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {entry.method}
                    </span>
                  </div>
                  <div className="col-span-6">
                    <div className="truncate text-gray-900" title={entry.url}>
                      {entry.url}
                    </div>
                  </div>
                  <div className="col-span-1">
                    <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                      (entry.status_code || 0) >= 200 && (entry.status_code || 0) < 300 ? 'bg-green-100 text-green-800' :
                      (entry.status_code || 0) >= 300 && (entry.status_code || 0) < 400 ? 'bg-blue-100 text-blue-800' :
                      (entry.status_code || 0) >= 400 && (entry.status_code || 0) < 500 ? 'bg-yellow-100 text-yellow-800' :
                      (entry.status_code || 0) >= 500 ? 'bg-red-100 text-red-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {entry.status_code || 'N/A'}
                    </span>
                  </div>
                  <div className="col-span-1 text-xs text-gray-500">
                    {(entry.request_size + entry.response_size).toLocaleString()}
                  </div>
                  <div className="col-span-2 text-xs text-gray-500">
                    {new Date(entry.time).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Entry Details */}
        <div className="flex-1 bg-white overflow-y-auto">
          {selectedEntry ? (
            <div className="h-full flex flex-col">
              {/* Entry Header */}
              <div className="bg-gray-50 border-b border-gray-200 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">
                      {selectedEntry.method} {selectedEntry.url}
                    </h3>
                    <p className="text-sm text-gray-600">
                      Status: {selectedEntry.status_code || 'N/A'} • 
                      Size: {(selectedEntry.request_size + selectedEntry.response_size).toLocaleString()} bytes • 
                      Duration: {selectedEntry.duration}ms
                    </p>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => sendToRepeater(selectedEntry)}
                      className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                    >
                      <Send className="w-4 h-4" />
                      <span>Send to Repeater</span>
                    </button>
                    
                    <button
                      onClick={() => copyAsCurl(selectedEntry)}
                      className="flex items-center space-x-2 px-3 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
                    >
                      <Copy className="w-4 h-4" />
                      <span>Copy as cURL</span>
                    </button>
                    
                    <button
                      onClick={() => exportEntry(selectedEntry)}
                      className="flex items-center space-x-2 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                    >
                      <Download className="w-4 h-4" />
                      <span>Export</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* View Mode Tabs */}
              <div className="border-b border-gray-200">
                <div className="flex space-x-1 p-4">
                  <button
                    onClick={() => setViewMode('parsed')}
                    className={`px-3 py-2 text-sm font-medium rounded-md ${
                      viewMode === 'parsed' 
                        ? 'bg-blue-100 text-blue-700' 
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    <FileText className="w-4 h-4 inline mr-2" />
                    Parsed
                  </button>
                  <button
                    onClick={() => setViewMode('raw')}
                    className={`px-3 py-2 text-sm font-medium rounded-md ${
                      viewMode === 'raw' 
                        ? 'bg-blue-100 text-blue-700' 
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    <Code className="w-4 h-4 inline mr-2" />
                    Raw
                  </button>
                  <button
                    onClick={() => setViewMode('hex')}
                    className={`px-3 py-2 text-sm font-medium rounded-md ${
                      viewMode === 'hex' 
                        ? 'bg-blue-100 text-blue-700' 
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    <Hexagon className="w-4 h-4 inline mr-2" />
                    Hex
                  </button>
                </div>
              </div>

              {/* Request/Response Tabs */}
              <div className="flex-1 overflow-hidden">
                <div className="h-full flex">
                  {/* Request */}
                  <div className="w-1/2 border-r border-gray-200 flex flex-col">
                    <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                      <h4 className="font-medium text-gray-900">Request</h4>
                    </div>
                    <div className="flex-1 overflow-auto p-4">
                      {/* Headers */}
                      <div className="mb-4">
                        <h5 className="text-sm font-medium text-gray-700 mb-2">Headers</h5>
                        <div className="bg-gray-50 rounded p-2">
                          {Object.entries(selectedEntry.request.headers).map(([key, value]) => (
                            <div key={key} className="text-xs font-mono">
                              <span className="text-blue-600">{key}:</span> {value}
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      {/* Body */}
                      {selectedEntry.request.body && (
                        <div>
                          <h5 className="text-sm font-medium text-gray-700 mb-2">Body</h5>
                          {renderContent(selectedEntry.request.body, 'text/plain')}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Response */}
                  <div className="w-1/2 flex flex-col">
                    <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                      <h4 className="font-medium text-gray-900">Response</h4>
                    </div>
                    <div className="flex-1 overflow-auto p-4">
                      {selectedEntry.response ? (
                        <>
                          {/* Headers */}
                          <div className="mb-4">
                            <h5 className="text-sm font-medium text-gray-700 mb-2">Headers</h5>
                            <div className="bg-gray-50 rounded p-2">
                              {Object.entries(selectedEntry.response.headers).map(([key, value]) => (
                                <div key={key} className="text-xs font-mono">
                                  <span className="text-blue-600">{key}:</span> {value}
                                </div>
                              ))}
                            </div>
                          </div>
                          
                          {/* Body */}
                          {selectedEntry.response.body && (
                            <div>
                              <h5 className="text-sm font-medium text-gray-700 mb-2">Body</h5>
                              {renderContent(selectedEntry.response.body, selectedEntry.content_type || 'text/plain')}
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="text-gray-500 text-center py-8">
                          No response data available
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center">
                <FileText className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                <p className="text-lg font-medium">Select an entry to view details</p>
                <p className="text-sm">Choose an HTTP request/response from the list to see its full details</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DASTHttpHistory;
