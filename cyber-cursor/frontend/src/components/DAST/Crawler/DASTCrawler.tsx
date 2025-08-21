import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { 
  Play, 
  Square, 
  Globe, 
  Link, 
  FileText, 
  Code,
  Settings,
  Target,
  Activity,
  CheckCircle,
  Clock,
  XCircle,
  Eye,
  EyeOff,
  Map,
  Network,
  Filter
} from 'lucide-react';
import { 
  startCrawler, 
  stopCrawler, 
  getCrawlerStatus, 
  getCrawlResults,
  getSiteMap,
  updateScope
} from '../../../services/dastProjectToolsService';

interface CrawlResult {
  id: string;
  url: string;
  method: string;
  status_code?: number;
  content_type?: string;
  title?: string;
  depth: number;
  parent_url?: string;
  in_scope: boolean;
  tags: string[];
  discovered_at: string;
}

interface CrawlStatus {
  status: 'idle' | 'running' | 'paused' | 'completed' | 'failed';
  progress: number;
  total_urls: number;
  discovered_urls: number;
  in_scope_urls: number;
  started_at?: string;
  estimated_completion?: string;
  current_url?: string;
  errors: string[];
}

interface DASTCrawlerProps {
  projectId: string;
}

const DASTCrawler: React.FC<DASTCrawlerProps> = ({ projectId }) => {
  const [crawlStatus, setCrawlStatus] = useState<CrawlStatus | null>(null);
  const [crawlResults, setCrawlResults] = useState<CrawlResult[]>([]);
  const [startUrl, setStartUrl] = useState<string>('');
  const [scopeConfig, setScopeConfig] = useState({
    include_patterns: [] as string[],
    exclude_patterns: [] as string[],
    allowed_ports: [80, 443] as number[],
    allowed_protocols: ['http', 'https'] as string[],
    file_extensions: [] as string[],
    max_depth: 3,
    follow_subdomains: true,
    follow_external_links: false
  });
  const [crawlConfig, setCrawlConfig] = useState({
    start_urls: [] as string[],
    max_depth: 3,
    max_pages: 1000,
    follow_redirects: true,
    verify_ssl: false,
    user_agent: 'CyberCursor DAST Crawler',
    delay: 1,
    include_patterns: [] as string[],
    exclude_patterns: [] as string[],
    custom_headers: {} as Record<string, string>
  });
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [showAdvancedConfig, setShowAdvancedConfig] = useState(false);
  const [pollingInterval, setPollingInterval] = useState<NodeJS.Timeout | null>(null);
  const [viewMode, setViewMode] = useState<'list' | 'map'>('list');
  const [filterText, setFilterText] = useState('');

  const handleStartCrawl = useCallback(async () => {
    if (!startUrl.trim()) return;
    
    setIsStarting(true);
    try {
      // Update crawl config with start URL and scope
      const updatedCrawlConfig = {
        ...crawlConfig,
        start_urls: [startUrl],
        include_patterns: scopeConfig.include_patterns,
        exclude_patterns: scopeConfig.exclude_patterns,
        max_depth: scopeConfig.max_depth
      };
      
      const response = await startCrawler(projectId, updatedCrawlConfig);
      
      if (response) {
        // Start polling for status updates
        startStatusPolling();
      }
    } catch (error) {
      console.error('Failed to start crawl:', error);
    } finally {
      setIsStarting(false);
    }
  }, [projectId, startUrl, scopeConfig, crawlConfig]);

  const startStatusPolling = useCallback(() => {
    const interval = setInterval(async () => {
      try {
        const status = await getCrawlerStatus(projectId);
        if (status) {
          setCrawlStatus(status);
          
          if (status.status === 'completed' || status.status === 'failed') {
            clearInterval(interval);
            setPollingInterval(null);
            // Load results when completed
            if (status.status === 'completed') {
              loadCrawlResults();
            }
          }
        }
      } catch (error) {
        console.error('Failed to get crawl status:', error);
      }
    }, 2000);
    
    setPollingInterval(interval);
  }, [projectId]);

  const handleStopCrawl = useCallback(async () => {
    if (!crawlStatus) return;
    
    setIsStopping(true);
    try {
      await stopCrawler(projectId);
      
      if (crawlStatus) {
        setCrawlStatus({ ...crawlStatus, status: 'paused' });
      }
      
      if (pollingInterval) {
        clearInterval(pollingInterval);
        setPollingInterval(null);
      }
    } catch (error) {
      console.error('Failed to stop crawl:', error);
    } finally {
      setIsStopping(false);
    }
  }, [crawlStatus, projectId, pollingInterval]);

  const loadCrawlResults = useCallback(async () => {
    try {
      const resultsResponse = await getCrawlResults(projectId, { page: 1, page_size: 1000 });
      if (resultsResponse.results) {
        setCrawlResults(resultsResponse.results);
      }
    } catch (error) {
      console.error('Failed to load crawl results:', error);
    }
  }, [projectId]);

  useEffect(() => {
    if (crawlStatus?.status === 'completed') {
      loadCrawlResults();
    }
  }, [crawlStatus?.status, loadCrawlResults]);

  useEffect(() => {
    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, [pollingInterval]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-green-600 bg-green-100';
      case 'completed': return 'text-blue-600 bg-blue-100';
      case 'failed': return 'text-red-600 bg-red-100';
      case 'paused': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusCodeColor = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'text-green-600 bg-green-100';
    if (statusCode >= 300 && statusCode < 400) return 'text-blue-600 bg-blue-100';
    if (statusCode >= 400 && statusCode < 500) return 'text-yellow-600 bg-yellow-100';
    if (statusCode >= 500) return 'text-red-600 bg-red-100';
    return 'text-gray-600 bg-gray-100';
  };

  const filteredResults = crawlStatus?.results?.filter(result => 
    result.url.toLowerCase().includes(filterText.toLowerCase()) ||
    result.title.toLowerCase().includes(filterText.toLowerCase())
  ) || [];

  const renderSiteMap = () => {
    if (!crawlResults.length) return null;

    const nodes = crawlResults.map((result, index) => ({
      id: index,
      url: result.url,
      title: result.title || 'No Title',
      status: result.status_code,
      links: [] // We don't have links in the new interface
    }));

    return (
      <div className="bg-gray-50 rounded-lg p-4">
        <div className="text-sm text-gray-600 mb-4">
          Site Map Visualization ({nodes.length} pages discovered)
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {nodes.map((node) => (
            <div key={node.id} className="bg-white p-3 rounded border border-gray-200">
              <div className="flex items-center gap-2 mb-2">
                <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusCodeColor(node.status)}`}>
                  {node.status}
                </span>
                <span className="text-xs text-gray-500">
                  {node.links.length} links
                </span>
              </div>
              <div className="text-sm font-medium text-gray-900 truncate" title={node.title}>
                {node.title || 'No Title'}
              </div>
              <div className="text-xs text-gray-600 truncate" title={node.url}>
                {node.url}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
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
            <Globe className="w-5 h-5 text-blue-600" />
            Crawler Configuration
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
              Start URL
            </label>
            <input
              type="url"
              value={startUrl}
              onChange={(e) => setStartUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Max Depth
              </label>
              <input
                type="number"
                value={scopeConfig.max_depth}
                onChange={(e) => setScopeConfig(prev => ({ ...prev, max_depth: parseInt(e.target.value) }))}
                min="1"
                max="10"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

                         <div>
               <label className="block text-sm font-medium text-gray-700 mb-2">
                 Max Pages
               </label>
               <input
                 type="number"
                 value={crawlConfig.max_pages}
                 onChange={(e) => setCrawlConfig(prev => ({ ...prev, max_pages: parseInt(e.target.value) }))}
                 min="10"
                 max="10000"
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
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Delay (seconds)
                </label>
                <input
                  type="number"
                  value={crawlConfig.delay}
                  onChange={(e) => setCrawlConfig(prev => ({ ...prev, delay: parseFloat(e.target.value) }))}
                  min="0"
                  max="10"
                  step="0.1"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="respectRobots"
                    checked={crawlConfig.respect_robots}
                    onChange={(e) => setCrawlConfig(prev => ({ ...prev, respect_robots: e.target.checked }))}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <label htmlFor="respectRobots" className="text-sm text-gray-700">
                    Respect robots.txt
                  </label>
                </div>

                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="followRedirects"
                    checked={crawlConfig.follow_redirects}
                    onChange={(e) => setCrawlConfig(prev => ({ ...prev, follow_redirects: e.target.checked }))}
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
                    checked={crawlConfig.verify_ssl}
                    onChange={(e) => setCrawlConfig(prev => ({ ...prev, verify_ssl: e.target.checked }))}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <label htmlFor="verifySSL" className="text-sm text-gray-700">
                    Verify SSL
                  </label>
                </div>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Include Patterns (regex)
                </label>
                <textarea
                  value={scopeConfig.include_patterns.join('\n')}
                  onChange={(e) => setScopeConfig(prev => ({ 
                    ...prev, 
                    include_patterns: e.target.value.split('\n').filter(p => p.trim()) 
                  }))}
                  placeholder=".*\.php&#10;.*\.asp"
                  className="w-full h-20 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Exclude Patterns (regex)
                </label>
                <textarea
                  value={scopeConfig.exclude_patterns.join('\n')}
                  onChange={(e) => setScopeConfig(prev => ({ 
                    ...prev, 
                    exclude_patterns: e.target.value.split('\n').filter(p => p.trim()) 
                  }))}
                  placeholder=".*\.pdf&#10;.*\.jpg"
                  className="w-full h-20 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
          </motion.div>
        )}

        <div className="mt-6 flex gap-3">
          <button
            onClick={handleStartCrawl}
            disabled={isStarting || !startUrl.trim() || crawlStatus?.status === 'running'}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play className="w-4 h-4" />
            {isStarting ? 'Starting...' : 'Start Crawl'}
          </button>

          {crawlStatus?.status === 'running' && (
            <button
              onClick={handleStopCrawl}
              disabled={isStopping}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
            >
              <Square className="w-4 h-4" />
              {isStopping ? 'Stopping...' : 'Stop Crawl'}
            </button>
          )}
        </div>
      </motion.div>

      {/* Crawl Status */}
      {crawlStatus && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200 p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <Activity className="w-5 h-5 text-green-600" />
              Crawl Status
            </h3>
            <div className="flex items-center gap-2">
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(crawlStatus.status)}`}>
                {crawlStatus.status.charAt(0).toUpperCase() + crawlStatus.status.slice(1)}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{crawlStatus.progress}%</div>
              <div className="text-sm text-gray-600">Progress</div>
            </div>
                         <div className="text-center">
               <div className="text-2xl font-bold text-green-600">{crawlResults.length}</div>
               <div className="text-sm text-gray-600">Pages Crawled</div>
             </div>
             <div className="text-center">
               <div className="text-2xl font-bold text-orange-600">{crawlStatus.discovered_urls || 0}</div>
               <div className="text-sm text-gray-600">Discovered URLs</div>
             </div>
             <div className="text-center">
               <div className="text-2xl font-bold text-purple-600">{crawlStatus.in_scope_urls || 0}</div>
               <div className="text-sm text-gray-600">In Scope</div>
             </div>
          </div>

          {crawlStatus.status === 'running' && (
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${crawlStatus.progress}%` }}
              />
            </div>
          )}

                     {crawlStatus.errors && crawlStatus.errors.length > 0 && (
             <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
               <div className="flex items-center gap-2 text-red-800">
                 <XCircle className="w-4 h-4" />
                 <span className="text-sm font-medium">Errors:</span>
               </div>
               <div className="mt-2 space-y-1">
                 {crawlStatus.errors.map((error, index) => (
                   <div key={index} className="text-sm text-red-700">{error}</div>
                 ))}
               </div>
             </div>
           )}
        </motion.div>
      )}

             {/* Crawl Results */}
       {crawlResults.length > 0 && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200 p-6"
        >
          <div className="flex items-center justify-between mb-4">
                         <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
               <FileText className="w-5 h-5 text-green-600" />
               Crawl Results ({crawlResults.length} pages)
             </h3>
            
            <div className="flex items-center gap-3">
              <div className="relative">
                <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Filter results..."
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                  className="pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              
              <div className="flex border border-gray-300 rounded-md">
                <button
                  onClick={() => setViewMode('list')}
                  className={`px-3 py-2 text-sm font-medium ${
                    viewMode === 'list' 
                      ? 'bg-blue-600 text-white' 
                      : 'bg-white text-gray-700 hover:bg-gray-50'
                  }`}
                >
                  <FileText className="w-4 h-4 inline mr-1" />
                  List
                </button>
                <button
                  onClick={() => setViewMode('map')}
                  className={`px-3 py-2 text-sm font-medium ${
                    viewMode === 'map' 
                      ? 'bg-blue-600 text-white' 
                      : 'bg-white text-gray-700 hover:bg-gray-50'
                  }`}
                >
                  <Map className="w-4 h-4 inline mr-1" />
                  Map
                </button>
              </div>
            </div>
          </div>

          {viewMode === 'map' ? (
            renderSiteMap()
          ) : (
            <div className="space-y-4">
              {filteredResults.map((result, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <h4 className="font-medium text-gray-900 mb-1">
                        {result.title || 'No Title'}
                      </h4>
                      <div className="text-sm text-gray-600 break-all">{result.url}</div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusCodeColor(result.status_code)}`}>
                        {result.status_code}
                      </span>
                      <span className="text-xs text-gray-500">
                        {result.body_length} bytes
                      </span>
                    </div>
                  </div>
                  
                                     <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                     <div>
                       <span className="font-medium text-gray-700">Content Type:</span>
                       <span className="text-gray-600 ml-2">{result.content_type || 'Unknown'}</span>
                     </div>
                     <div>
                       <span className="font-medium text-gray-700">Depth:</span>
                       <span className="text-gray-600 ml-2">{result.depth}</span>
                     </div>
                     <div>
                       <span className="font-medium text-gray-700">In Scope:</span>
                       <span className="text-gray-600 ml-2">{result.in_scope ? 'Yes' : 'No'}</span>
                     </div>
                   </div>

                   {result.tags && result.tags.length > 0 && (
                     <div className="mt-3">
                       <span className="font-medium text-gray-700 text-sm">Tags:</span>
                       <div className="mt-1 flex flex-wrap gap-1">
                         {result.tags.map((tag, tagIndex) => (
                           <span key={tagIndex} className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded">
                             {tag}
                           </span>
                         ))}
                       </div>
                     </div>
                   )}
                </div>
              ))}
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
};

export default DASTCrawler;
