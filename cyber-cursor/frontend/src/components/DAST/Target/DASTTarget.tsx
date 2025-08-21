import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Target,
  Globe,
  Link,
  FileText,
  Code,
  Image,
  Video,
  Archive,
  Filter,
  Search,
  Eye,
  EyeOff,
  Download,
  Trash2,
  Plus,
  Settings,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import { AnimatePresence } from 'framer-motion';

interface SiteMapNode {
  id: string;
  url: string;
  method: string;
  status_code: number;
  content_type: string;
  title?: string;
  depth: number;
  parent_id?: string;
  children: string[];
  discovered_at: string;
  last_accessed?: string;
  in_scope: boolean;
  tags: string[];
  notes?: string;
}

interface DASTTargetProps {
  projectId: string;
}

const DASTTarget: React.FC<DASTTargetProps> = ({ projectId }) => {
  const [siteMap, setSiteMap] = useState<SiteMapNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<SiteMapNode | null>(null);
  const [viewMode, setViewMode] = useState<'tree' | 'list' | 'map'>('tree');
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    method: 'all',
    status: 'all',
    contentType: 'all',
    scope: 'all',
    tags: [] as string[]
  });
  const [expandedNodes, setExpandedNodes] = useState(new Set<string>());
  const [scopeSettings, setScopeSettings] = useState({
    include_patterns: [] as string[],
    exclude_patterns: [] as string[],
    allowed_ports: [80, 443] as number[],
    allowed_filetypes: [] as string[],
    max_depth: 10
  });
  const [showScopeSettings, setShowScopeSettings] = useState(false);
  const [loading, setLoading] = useState(false);

  // Load site map data
  const loadSiteMap = useCallback(async () => {
    try {
      setLoading(true);
      // This would integrate with your backend to get the site map
      // For now, using mock data
      const mockData: SiteMapNode[] = [
        {
          id: '1',
          url: 'https://example.com/',
          method: 'GET',
          status_code: 200,
          content_type: 'text/html',
          title: 'Example Domain',
          depth: 0,
          children: ['2', '3', '4'],
          discovered_at: new Date().toISOString(),
          in_scope: true,
          tags: ['landing', 'public']
        },
        {
          id: '2',
          url: 'https://example.com/login',
          method: 'GET',
          status_code: 200,
          content_type: 'text/html',
          title: 'Login Page',
          depth: 1,
          parent_id: '1',
          children: ['5'],
          discovered_at: new Date().toISOString(),
          in_scope: true,
          tags: ['auth', 'login']
        },
        {
          id: '3',
          url: 'https://example.com/api/users',
          method: 'GET',
          status_code: 401,
          content_type: 'application/json',
          title: 'Users API',
          depth: 1,
          parent_id: '1',
          children: [],
          discovered_at: new Date().toISOString(),
          in_scope: true,
          tags: ['api', 'users']
        },
        {
          id: '4',
          url: 'https://example.com/static/style.css',
          method: 'GET',
          status_code: 200,
          content_type: 'text/css',
          depth: 1,
          parent_id: '1',
          children: [],
          discovered_at: new Date().toISOString(),
          in_scope: false,
          tags: ['static', 'css']
        },
        {
          id: '5',
          url: 'https://example.com/login',
          method: 'POST',
          status_code: 200,
          content_type: 'application/json',
          depth: 2,
          parent_id: '2',
          children: [],
          discovered_at: new Date().toISOString(),
          in_scope: true,
          tags: ['auth', 'login', 'post']
        }
      ];

      setSiteMap(mockData);
    } catch (error) {
      console.error('Failed to load site map:', error);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  // Initial load
  useEffect(() => {
    loadSiteMap();
  }, [loadSiteMap]);

  // Filtered site map
  const filteredSiteMap = siteMap.filter(node => {
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      if (!node.url.toLowerCase().includes(searchLower) &&
          !(node.title || '').toLowerCase().includes(searchLower)) {
        return false;
      }
    }

    if (filters.method !== 'all' && node.method !== filters.method) return false;
    if (filters.status !== 'all') {
      if (filters.status === 'success' && (node.status_code < 200 || node.status_code >= 300)) return false;
      if (filters.status === 'redirect' && (node.status_code < 300 || node.status_code >= 400)) return false;
      if (filters.status === 'client_error' && (node.status_code < 400 || node.status_code >= 500)) return false;
      if (filters.status === 'server_error' && node.status_code < 500) return false;
    }
    if (filters.contentType !== 'all' && !node.content_type.includes(filters.contentType)) return false;
    if (filters.scope === 'in_scope' && !node.in_scope) return false;
    if (filters.scope === 'out_of_scope' && node.in_scope) return false;

    return true;
  });

  // Toggle node expansion
  const toggleNode = useCallback((nodeId: string) => {
    setExpandedNodes(prev => {
      const newSet = new Set(prev);
      if (newSet.has(nodeId)) {
        newSet.delete(nodeId);
      } else {
        newSet.add(nodeId);
      }
      return newSet;
    });
  }, []);

  // Get content type icon
  const getContentTypeIcon = (contentType: string) => {
    if (contentType.includes('html')) return <FileText className="w-4 h-4" />;
    if (contentType.includes('json') || contentType.includes('xml')) return <Code className="w-4 h-4" />;
    if (contentType.includes('css')) return <FileText className="w-4 h-4" />;
    if (contentType.includes('javascript')) return <Code className="w-4 h-4" />;
    if (contentType.includes('image')) return <Image className="w-4 h-4" />;
    if (contentType.includes('video')) return <Video className="w-4 h-4" />;
    if (contentType.includes('zip') || contentType.includes('tar')) return <Archive className="w-4 h-4" />;
    return <FileText className="w-4 h-4" />;
  };

  // Get status color
  const getStatusColor = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'text-green-600 bg-green-100';
    if (statusCode >= 300 && statusCode < 400) return 'text-blue-600 bg-blue-100';
    if (statusCode >= 400 && statusCode < 500) return 'text-yellow-600 bg-yellow-100';
    if (statusCode >= 500) return 'text-red-600 bg-red-100';
    return 'text-gray-600 bg-gray-100';
  };

  // Render tree view
  const renderTreeView = () => {
    const renderNode = (node: SiteMapNode, level: number = 0) => {
      const hasChildren = node.children.length > 0;
      const isExpanded = expandedNodes.has(node.id);

      return (
        <div key={node.id}>
          <div
            className={`flex items-center p-2 hover:bg-gray-50 cursor-pointer ${
              selectedNode?.id === node.id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
            }`}
            style={{ paddingLeft: `${level * 20 + 16}px` }}
            onClick={() => setSelectedNode(node)}
          >
            {hasChildren && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  toggleNode(node.id);
                }}
                className="mr-2 text-gray-400 hover:text-gray-600"
              >
                {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              </button>
            )}

            {!hasChildren && <div className="w-6 mr-2" />}

            <div className="flex items-center space-x-2 flex-1">
              {getContentTypeIcon(node.content_type)}

              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                node.method === 'GET' ? 'bg-green-100 text-green-800' :
                node.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                node.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                node.method === 'DELETE' ? 'bg-red-100 text-red-800' :
                'bg-gray-100 text-gray-800'
              }`}>
                {node.method}
              </span>

              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getStatusColor(node.status_code)}`}>
                {node.status_code}
              </span>

              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                node.in_scope ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'
              }`}>
                {node.in_scope ? 'In Scope' : 'Out of Scope'}
              </span>
            </div>

            <div className="flex items-center space-x-2 text-sm text-gray-600">
              <span className="truncate max-w-xs">{node.title || node.url}</span>
            </div>
          </div>

          {hasChildren && isExpanded && (
            <div>
              {node.children.map(childId => {
                const childNode = siteMap.find(n => n.id === childId);
                return childNode ? renderNode(childNode, level + 1) : null;
              })}
            </div>
          )}
        </div>
      );
    };

    const rootNodes = filteredSiteMap.filter(node => !node.parent_id);
    return (
      <div className="divide-y divide-gray-200">
        {rootNodes.map(node => renderNode(node))}
      </div>
    );
  };

  // Render list view
  const renderListView = () => {
    return (
      <div className="divide-y divide-gray-200">
        {filteredSiteMap.map(node => (
          <div
            key={node.id}
            onClick={() => setSelectedNode(node)}
            className={`p-3 hover:bg-gray-50 cursor-pointer ${
              selectedNode?.id === node.id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                {getContentTypeIcon(node.content_type)}

                <div>
                  <div className="font-medium text-gray-900">{node.title || 'No Title'}</div>
                  <div className="text-sm text-gray-600">{node.url}</div>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                  node.method === 'GET' ? 'bg-green-100 text-green-800' :
                  node.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                  node.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                  node.method === 'DELETE' ? 'bg-red-100 text-red-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {node.method}
                </span>

                <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getStatusColor(node.status_code)}`}>
                  {node.status_code}
                </span>

                <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                  node.in_scope ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'
                }`}>
                  {node.in_scope ? 'In Scope' : 'Out of Scope'}
                </span>
              </div>
            </div>

            <div className="mt-2 flex items-center space-x-2 text-xs text-gray-500">
              <span>Depth: {node.depth}</span>
              <span>•</span>
              <span>Type: {node.content_type}</span>
              <span>•</span>
              <span>Discovered: {new Date(node.discovered_at).toLocaleDateString()}</span>
              {node.tags.length > 0 && (
                <>
                  <span>•</span>
                  <span>Tags: {node.tags.join(', ')}</span>
                </>
              )}
            </div>
          </div>
        ))}
      </div>
    );
  };

  // Render map view (simplified network diagram)
  const renderMapView = () => {
    return (
      <div className="p-8 text-center text-gray-500">
        <Globe className="w-16 h-16 mx-auto mb-4 text-gray-300" />
        <p className="text-lg font-medium">Map View</p>
        <p className="text-sm">Network diagram visualization coming soon</p>
      </div>
    );
  };

  // Add scope pattern
  const addScopePattern = useCallback((type: 'include' | 'exclude') => {
    if (type === 'include') {
      setScopeSettings(prev => ({
        ...prev,
        include_patterns: [...prev.include_patterns, '']
      }));
    } else {
      setScopeSettings(prev => ({
        ...prev,
        exclude_patterns: [...prev.exclude_patterns, '']
      }));
    }
  }, []);

  // Update scope pattern
  const updateScopePattern = useCallback((type: 'include' | 'exclude', index: number, value: string) => {
    if (type === 'include') {
      setScopeSettings(prev => ({
        ...prev,
        include_patterns: prev.include_patterns.map((pattern, i) => i === index ? value : pattern)
      }));
    } else {
      setScopeSettings(prev => ({
        ...prev,
        exclude_patterns: prev.exclude_patterns.map((pattern, i) => i === index ? value : pattern)
      }));
    }
  }, []);

  // Remove scope pattern
  const removeScopePattern = useCallback((type: 'include' | 'exclude', index: number) => {
    if (type === 'include') {
      setScopeSettings(prev => ({
        ...prev,
        include_patterns: prev.include_patterns.filter((_, i) => i !== index)
      }));
    } else {
      setScopeSettings(prev => ({
        ...prev,
        exclude_patterns: prev.exclude_patterns.filter((_, i) => i !== index)
      }));
    }
  }, []);

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="bg-white border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-semibold text-gray-900">Target</h2>
            <span className="text-sm text-gray-500">
              {filteredSiteMap.length} of {siteMap.length} nodes
            </span>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => setShowScopeSettings(!showScopeSettings)}
              className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm ${
                showScopeSettings ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'
              }`}
            >
              <Settings className="w-4 h-4" />
              <span>Scope</span>
            </button>

            <button
              onClick={loadSiteMap}
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
              placeholder="Search in URL, title, tags..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

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
            <option value="css">CSS</option>
            <option value="javascript">JavaScript</option>
          </select>

          <select
            value={filters.scope}
            onChange={(e) => setFilters(prev => ({ ...prev, scope: e.target.value }))}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Scope</option>
            <option value="in_scope">In Scope</option>
            <option value="out_of_scope">Out of Scope</option>
          </select>
        </div>

        {/* View Mode Selector */}
        <div className="mt-4 flex items-center space-x-2">
          <span className="text-sm text-gray-600">View:</span>
          <div className="flex space-x-1">
            <button
              onClick={() => setViewMode('tree')}
              className={`px-3 py-1 text-xs font-medium rounded ${
                viewMode === 'tree'
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              Tree
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`px-3 py-1 text-xs font-medium rounded ${
                viewMode === 'list'
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              List
            </button>
            <button
              onClick={() => setViewMode('map')}
              className={`px-3 py-1 text-xs font-medium rounded ${
                viewMode === 'map'
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              Map
            </button>
          </div>
        </div>
      </div>

      {/* Scope Settings */}
      <AnimatePresence>
        {showScopeSettings && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="bg-gray-50 border-b border-gray-200 p-4"
          >
            <h3 className="text-sm font-medium text-gray-900 mb-3">Scope Configuration</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Include Patterns */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium text-gray-700">Include Patterns</h4>
                  <button
                    onClick={() => addScopePattern('include')}
                    className="text-blue-600 hover:text-blue-700 text-sm"
                  >
                    <Plus className="w-4 h-4 inline mr-1" />
                    Add
                  </button>
                </div>
                <div className="space-y-2">
                  {scopeSettings.include_patterns.map((pattern, index) => (
                    <div key={index} className="flex space-x-2">
                      <input
                        type="text"
                        value={pattern}
                        onChange={(e) => updateScopePattern('include', index, e.target.value)}
                        placeholder="*.example.com/*"
                        className="flex-1 px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <button
                        onClick={() => removeScopePattern('include', index)}
                        className="px-2 py-1 text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                  {scopeSettings.include_patterns.length === 0 && (
                    <div className="text-xs text-gray-500">No include patterns defined</div>
                  )}
                </div>
              </div>

              {/* Exclude Patterns */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium text-gray-700">Exclude Patterns</h4>
                  <button
                    onClick={() => addScopePattern('exclude')}
                    className="text-blue-600 hover:text-blue-700 text-sm"
                  >
                    <Plus className="w-4 h-4 inline mr-1" />
                    Add
                  </button>
                </div>
                <div className="space-y-2">
                  {scopeSettings.exclude_patterns.map((pattern, index) => (
                    <div key={index} className="flex space-x-2">
                      <input
                        type="text"
                        value={pattern}
                        onChange={(e) => updateScopePattern('exclude', index, e.target.value)}
                        placeholder="*.example.com/static/*"
                        className="flex-1 px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <button
                        onClick={() => removeScopePattern('exclude', index)}
                        className="px-2 py-1 text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                  {scopeSettings.exclude_patterns.length === 0 && (
                    <div className="text-xs text-gray-500">No exclude patterns defined</div>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs text-gray-700 mb-1">Max Depth</label>
                <input
                  type="number"
                  value={scopeSettings.max_depth}
                  onChange={(e) => setScopeSettings(prev => ({ ...prev, max_depth: parseInt(e.target.value) }))}
                  className="w-full px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Site Map */}
        <div className="flex-1 bg-white overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <RefreshCw className="w-8 h-8 animate-spin text-blue-600" />
            </div>
          ) : filteredSiteMap.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center">
                <Target className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                <p className="text-lg font-medium">No nodes found</p>
                <p className="text-sm">Try adjusting your search or filters</p>
              </div>
            </div>
          ) : (
            <>
              {viewMode === 'tree' && renderTreeView()}
              {viewMode === 'list' && renderListView()}
              {viewMode === 'map' && renderMapView()}
            </>
          )}
        </div>

        {/* Node Details */}
        <div className="w-96 bg-white border-l border-gray-200 overflow-y-auto">
          {selectedNode ? (
            <div className="p-4">
              <div className="mb-4">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Node Details</h3>
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="font-medium text-gray-700">URL:</span>
                    <div className="text-gray-600 break-all">{selectedNode.url}</div>
                  </div>
                  {selectedNode.title && (
                    <div>
                      <span className="font-medium text-gray-700">Title:</span>
                      <div className="text-gray-600">{selectedNode.title}</div>
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <span className="font-medium text-gray-700">Method:</span>
                      <div className="text-gray-600">{selectedNode.method}</div>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Status:</span>
                      <div className="text-gray-600">{selectedNode.status_code}</div>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Depth:</span>
                      <div className="text-gray-600">{selectedNode.depth}</div>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Children:</span>
                      <div className="text-gray-600">{selectedNode.children.length}</div>
                    </div>
                  </div>
                  <div>
                    <span className="font-medium text-gray-700">Content Type:</span>
                    <div className="text-gray-600">{selectedNode.content_type}</div>
                  </div>
                  <div>
                    <span className="font-medium text-gray-700">Discovered:</span>
                    <div className="text-gray-600">{new Date(selectedNode.discovered_at).toLocaleString()}</div>
                  </div>
                  {selectedNode.tags.length > 0 && (
                    <div>
                      <span className="font-medium text-gray-700">Tags:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {selectedNode.tags.map((tag, index) => (
                          <span
                            key={index}
                            className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-800"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  <div>
                    <span className="font-medium text-gray-700">Scope:</span>
                    <span className={`ml-2 inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                      selectedNode.in_scope ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'
                    }`}>
                      {selectedNode.in_scope ? 'In Scope' : 'Out of Scope'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="border-t border-gray-200 pt-4">
                <h4 className="text-sm font-medium text-gray-700 mb-2">Actions</h4>
                <div className="space-y-2">
                  <button className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
                    <ExternalLink className="w-4 h-4" />
                    <span>Open in Browser</span>
                  </button>
                  <button className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700">
                    <Plus className="w-4 h-4" />
                    <span>Add to Scope</span>
                  </button>
                  <button className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700">
                    <Eye className="w-4 h-4" />
                    <span>View Response</span>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center">
                <Target className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                <p className="text-lg font-medium">No node selected</p>
                <p className="text-sm">Choose a node from the site map to view details</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DASTTarget;
