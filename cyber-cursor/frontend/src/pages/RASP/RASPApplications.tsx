import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  PlusIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  EyeIcon,
  PencilIcon,
  TrashIcon,
  ServerIcon,
  TagIcon,
  GlobeAltIcon
} from '@heroicons/react/24/outline';
import { 
  DocumentTextIcon,
  CodeBracketIcon,
  CogIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/solid';

interface RASPApp {
  id: string;
  name: string;
  owner: string;
  repo_url?: string;
  tags?: string[];
  risk_score: number;
  framework?: string;
  language?: string;
  description?: string;
  created_at: string;
  updated_at?: string;
}

interface RASPApplicationsData {
  items: RASPApp[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

const RASPApplications: React.FC = () => {
  const [data, setData] = useState<RASPApplicationsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedApp, setSelectedApp] = useState<RASPApp | null>(null);
  const [filters, setFilters] = useState({
    framework: '',
    language: '',
    tags: '',
    risk_score_min: '',
    risk_score_max: ''
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  // Form state for create/edit
  const [formData, setFormData] = useState({
    name: '',
    owner: '',
    repo_url: '',
    tags: '',
    framework: '',
    language: '',
    description: ''
  });

  useEffect(() => {
    fetchApplications();
  }, [currentPage, pageSize, filters, searchTerm]);

  const fetchApplications = async () => {
    try {
      setLoading(true);
      // TODO: Replace with actual API calls
      const mockData: RASPApplicationsData = {
        items: [
          {
            id: 'app-1',
            name: 'Web Portal',
            owner: 'Development Team',
            repo_url: 'https://github.com/company/web-portal',
            tags: ['web', 'portal', 'user-facing'],
            risk_score: 8.5,
            framework: 'React',
            language: 'JavaScript',
            description: 'Main customer-facing web portal application',
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-15T00:00:00Z'
          },
          {
            id: 'app-2',
            name: 'API Gateway',
            owner: 'Platform Team',
            repo_url: 'https://github.com/company/api-gateway',
            tags: ['api', 'gateway', 'microservices'],
            risk_score: 7.2,
            framework: 'Express.js',
            language: 'Node.js',
            description: 'API gateway for microservices architecture',
            created_at: '2024-01-02T00:00:00Z',
            updated_at: '2024-01-14T00:00:00Z'
          },
          {
            id: 'app-3',
            name: 'Admin Panel',
            owner: 'Admin Team',
            repo_url: 'https://github.com/company/admin-panel',
            tags: ['admin', 'internal', 'management'],
            risk_score: 6.8,
            framework: 'Vue.js',
            language: 'JavaScript',
            description: 'Internal administration panel',
            created_at: '2024-01-03T00:00:00Z',
            updated_at: '2024-01-13T00:00:00Z'
          }
        ],
        total: 3,
        page: currentPage,
        size: pageSize,
        pages: 1
      };
      
      setData(mockData);
    } catch (error) {
      console.error('Error fetching applications:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateApp = async () => {
    try {
      // TODO: Implement actual API call
      console.log('Creating app:', formData);
      setShowCreateModal(false);
      setFormData({
        name: '',
        owner: '',
        repo_url: '',
        tags: '',
        framework: '',
        language: '',
        description: ''
      });
      fetchApplications();
    } catch (error) {
      console.error('Error creating application:', error);
    }
  };

  const handleEditApp = (app: RASPApp) => {
    setSelectedApp(app);
    setFormData({
      name: app.name,
      owner: app.owner,
      repo_url: app.repo_url || '',
      tags: app.tags?.join(', ') || '',
      framework: app.framework || '',
      language: app.language || '',
      description: app.description || ''
    });
    setShowCreateModal(true);
  };

  const handleUpdateApp = async () => {
    try {
      // TODO: Implement actual API call
      console.log('Updating app:', selectedApp?.id, formData);
      setShowCreateModal(false);
      setSelectedApp(null);
      setFormData({
        name: '',
        owner: '',
        repo_url: '',
        tags: '',
        framework: '',
        language: '',
        description: ''
      });
      fetchApplications();
    } catch (error) {
      console.error('Error updating application:', error);
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 8) return 'text-red-600 bg-red-100';
    if (score >= 6) return 'text-orange-600 bg-orange-100';
    if (score >= 4) return 'text-yellow-600 bg-yellow-100';
    return 'text-green-600 bg-green-100';
  };

  const getRiskScoreLabel = (score: number) => {
    if (score >= 8) return 'High';
    if (score >= 6) return 'Medium';
    if (score >= 4) return 'Low';
    return 'Very Low';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Applications</h1>
          <p className="text-gray-600">Manage your RASP-protected applications</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          <PlusIcon className="w-4 h-4 mr-2" />
          Add Application
        </button>
      </div>

      {/* Filters and Search */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
          <div className="lg:col-span-2">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search applications..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          
          <div>
            <select
              value={filters.framework}
              onChange={(e) => setFilters({ ...filters, framework: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Frameworks</option>
              <option value="React">React</option>
              <option value="Vue.js">Vue.js</option>
              <option value="Angular">Angular</option>
              <option value="Express.js">Express.js</option>
              <option value="Spring">Spring</option>
            </select>
          </div>
          
          <div>
            <select
              value={filters.language}
              onChange={(e) => setFilters({ ...filters, language: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Languages</option>
              <option value="JavaScript">JavaScript</option>
              <option value="TypeScript">TypeScript</option>
              <option value="Java">Java</option>
              <option value="Python">Python</option>
              <option value="C#">C#</option>
            </select>
          </div>
          
          <div>
            <input
              type="number"
              placeholder="Min Risk Score"
              value={filters.risk_score_min}
              onChange={(e) => setFilters({ ...filters, risk_score_min: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div>
            <input
              type="number"
              placeholder="Max Risk Score"
              value={filters.risk_score_max}
              onChange={(e) => setFilters({ ...filters, risk_score_max: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
        </div>
      </div>

      {/* Applications List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-medium text-gray-900">
              Applications ({data?.total || 0})
            </h3>
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-500">Show:</span>
              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                className="px-3 py-1 border border-gray-300 rounded-md text-sm"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>
          </div>
        </div>
        
        <div className="divide-y divide-gray-200">
          {data?.items.map((app) => (
            <motion.div
              key={app.id}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="px-6 py-4 hover:bg-gray-50"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <div className="flex-shrink-0">
                      <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                        <ServerIcon className="w-6 h-6 text-blue-600" />
                      </div>
                    </div>
                    
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <h4 className="text-lg font-medium text-gray-900">{app.name}</h4>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRiskScoreColor(app.risk_score)}`}>
                          {getRiskScoreLabel(app.risk_score)} Risk
                        </span>
                      </div>
                      
                      <div className="mt-1 flex items-center space-x-4 text-sm text-gray-500">
                        <span className="flex items-center">
                          <CodeBracketIcon className="w-4 h-4 mr-1" />
                          {app.language || 'Unknown'}
                        </span>
                        {app.framework && (
                          <span className="flex items-center">
                            <CogIcon className="w-4 h-4 mr-1" />
                            {app.framework}
                          </span>
                        )}
                        <span className="flex items-center">
                          <GlobeAltIcon className="w-4 h-4 mr-1" />
                          {app.owner}
                        </span>
                        <span className="flex items-center">
                          <ShieldCheckIcon className="w-4 h-4 mr-1" />
                          Score: {app.risk_score}
                        </span>
                      </div>
                      
                      {app.description && (
                        <p className="mt-2 text-sm text-gray-600">{app.description}</p>
                      )}
                      
                      {app.tags && app.tags.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {app.tags.map((tag) => (
                            <span
                              key={tag}
                              className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800"
                            >
                              <TagIcon className="w-3 h-3 mr-1" />
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleEditApp(app)}
                    className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md"
                    title="Edit Application"
                  >
                    <PencilIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => {/* TODO: Implement view details */}}
                    className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md"
                    title="View Details"
                  >
                    <EyeIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => {/* TODO: Implement delete */}}
                    className="p-2 text-red-400 hover:text-red-600 hover:bg-red-50 rounded-md"
                    title="Delete Application"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
        
        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-700">
                Showing {((data.page - 1) * data.size) + 1} to {Math.min(data.page * data.size, data.total)} of {data.total} results
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <span className="px-3 py-2 text-sm text-gray-700">
                  Page {currentPage} of {data.pages}
                </span>
                <button
                  onClick={() => setCurrentPage(Math.min(data.pages, currentPage + 1))}
                  disabled={currentPage === data.pages}
                  className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Create/Edit Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                {selectedApp ? 'Edit Application' : 'Create New Application'}
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Name</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Owner</label>
                  <input
                    type="text"
                    value={formData.owner}
                    onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Repository URL</label>
                  <input
                    type="url"
                    value={formData.repo_url}
                    onChange={(e) => setFormData({ ...formData, repo_url: e.target.value })}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Tags (comma-separated)</label>
                  <input
                    type="text"
                    value={formData.tags}
                    onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    placeholder="web, portal, user-facing"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Framework</label>
                  <input
                    type="text"
                    value={formData.framework}
                    onChange={(e) => setFormData({ ...formData, framework: e.target.value })}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Language</label>
                  <input
                    type="text"
                    value={formData.language}
                    onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Description</label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    rows={3}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
              </div>
              
              <div className="flex items-center justify-end space-x-3 mt-6">
                <button
                  onClick={() => {
                    setShowCreateModal(false);
                    setSelectedApp(null);
                    setFormData({
                      name: '',
                      owner: '',
                      repo_url: '',
                      tags: '',
                      framework: '',
                      language: '',
                      description: ''
                    });
                  }}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={selectedApp ? handleUpdateApp : handleCreateApp}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700"
                >
                  {selectedApp ? 'Update' : 'Create'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RASPApplications;
