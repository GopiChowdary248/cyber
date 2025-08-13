import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Clock,
  FileText,
  GitBranch,
  Zap,
  Target,
  Users,
  Settings,
  CheckCircle,
  Eye,
  RefreshCw,
  Download,
  Search,
  Bug,
  ChevronUp,
  ChevronDown,
  MessageSquare,
  ExternalLink,
  User,
  Calendar
} from 'lucide-react';

interface SecurityHotspot {
  id: string;
  project_id: string;
  rule_id: string;
  rule_name: string;
  message: string;
  description?: string;
  status: string;
  resolution?: string;
  file_path: string;
  line_number: number;
  start_line?: number;
  end_line?: number;
  cwe_id?: string;
  cvss_score?: number;
  owasp_category?: string;
  tags?: string[];
  reviewed_by?: string;
  reviewed_at?: string;
  review_comment?: string;
  created_at?: string;
  updated_at?: string;
}

interface Project {
  id: string;
  name: string;
  key: string;
  language: string;
}

const API_BASE_URL = '/api/v1/sast';

const SASTSecurityHotspots: React.FC = () => {
  const [hotspots, setHotspots] = useState<SecurityHotspot[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedHotspot, setSelectedHotspot] = useState<SecurityHotspot | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  
  // Filters
  const [statusFilter, setStatusFilter] = useState('all');
  const [projectFilter, setProjectFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  
  // Review modal
  const [showReviewModal, setShowReviewModal] = useState(false);
  const [reviewStatus, setReviewStatus] = useState('SAFE');
  const [reviewComment, setReviewComment] = useState('');

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('access_token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const [hotspotsRes, projectsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/security-hotspots`, { headers }),
        fetch(`${API_BASE_URL}/projects`, { headers }),
      ]);

      if (hotspotsRes.ok) {
        const hotspotsData = await hotspotsRes.json();
        setHotspots(hotspotsData.hotspots || []);
      }

      if (projectsRes.ok) {
        const projectsData = await projectsRes.json();
        setProjects(projectsData.projects || []);
      }
    } catch (error) {
      console.error('Error fetching security hotspots:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchData().finally(() => setRefreshing(false));
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'safe':
      case 'fixed':
        return 'text-green-600 bg-green-100';
      case 'reviewed':
        return 'text-blue-600 bg-blue-100';
      case 'to_review':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'safe':
      case 'fixed':
        return <CheckCircle className="w-4 h-4" />;
      case 'reviewed':
        return <Eye className="w-4 h-4" />;
      case 'to_review':
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const getCVSSColor = (score?: number) => {
    if (!score) return 'text-gray-400';
    if (score >= 7) return 'text-red-600';
    if (score >= 4) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getCVSSBackground = (score?: number) => {
    if (!score) return 'bg-gray-100';
    if (score >= 7) return 'bg-red-100';
    if (score >= 4) return 'bg-yellow-100';
    return 'bg-green-100';
  };

  const filteredHotspots = hotspots.filter(hotspot => {
    // Status filter
    if (statusFilter !== 'all' && hotspot.status.toLowerCase() !== statusFilter.toLowerCase()) {
      return false;
    }
    
    // Project filter
    if (projectFilter !== 'all' && hotspot.project_id !== projectFilter) {
      return false;
    }
    
    // Severity filter (based on CVSS score)
    if (severityFilter !== 'all') {
      const score = hotspot.cvss_score || 0;
      switch (severityFilter) {
        case 'high':
          if (score < 7) return false;
          break;
        case 'medium':
          if (score < 4 || score >= 7) return false;
          break;
        case 'low':
          if (score >= 4) return false;
          break;
      }
    }
    
    // Search term
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return (
        hotspot.rule_name.toLowerCase().includes(searchLower) ||
        hotspot.message.toLowerCase().includes(searchLower) ||
        hotspot.file_path.toLowerCase().includes(searchLower) ||
        (hotspot.cwe_id && hotspot.cwe_id.toLowerCase().includes(searchLower))
      );
    }
    
    return true;
  });

  const handleReview = async () => {
    if (!selectedHotspot) return;
    
    try {
      const token = localStorage.getItem('access_token') || '';
      const response = await fetch(`${API_BASE_URL}/security-hotspots/${selectedHotspot.id}/review`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status: reviewStatus,
          comment: reviewComment,
        }),
      });

      if (response.ok) {
        // Update the hotspot in the list
        setHotspots(prev => prev.map(h => 
          h.id === selectedHotspot.id 
            ? { ...h, status: reviewStatus, review_comment: reviewComment, reviewed_at: new Date().toISOString() }
            : h
        ));
        setShowReviewModal(false);
        setSelectedHotspot(null);
        setReviewStatus('SAFE');
        setReviewComment('');
      }
    } catch (error) {
      console.error('Error reviewing hotspot:', error);
    }
  };

  const getProjectName = (projectId: string) => {
    const project = projects.find(p => p.id === projectId);
    return project ? project.name : `Project ${projectId}`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Hotspots</h1>
          <p className="text-gray-600">Review and manage security hotspots across all projects</p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white p-6 rounded-lg shadow-sm border">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {/* Search */}
          <div className="lg:col-span-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                placeholder="Search hotspots..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Status</option>
              <option value="to_review">To Review</option>
              <option value="reviewed">Reviewed</option>
              <option value="safe">Safe</option>
              <option value="fixed">Fixed</option>
            </select>
          </div>

          {/* Project Filter */}
          <div>
            <select
              value={projectFilter}
              onChange={(e) => setProjectFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Projects</option>
              {projects.map(project => (
                <option key={project.id} value={project.id}>{project.name}</option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Severities</option>
              <option value="high">High (CVSS 7+)</option>
              <option value="medium">Medium (CVSS 4-6.9)</option>
              <option value="low">Low (CVSS 0-3.9)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-yellow-100 rounded-full">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">To Review</p>
              <p className="text-xl font-bold text-yellow-600">
                {hotspots.filter(h => h.status.toLowerCase() === 'to_review').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-100 rounded-full">
              <Eye className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Reviewed</p>
              <p className="text-xl font-bold text-blue-600">
                {hotspots.filter(h => h.status.toLowerCase() === 'reviewed').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-green-100 rounded-full">
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Safe</p>
              <p className="text-xl font-bold text-green-600">
                {hotspots.filter(h => h.status.toLowerCase() === 'safe').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-red-100 rounded-full">
              <Bug className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">High Risk</p>
              <p className="text-xl font-bold text-red-600">
                {hotspots.filter(h => (h.cvss_score || 0) >= 7).length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Hotspots List */}
      <div className="bg-white rounded-lg shadow-sm border">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">
            Security Hotspots ({filteredHotspots.length})
          </h2>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Rule
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Project
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  File
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  CVSS
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  CWE
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Created
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredHotspots.map((hotspot) => (
                <React.Fragment key={hotspot.id}>
                  <tr 
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => {
                      setSelectedHotspot(selectedHotspot?.id === hotspot.id ? null : hotspot);
                      setShowDetails(selectedHotspot?.id === hotspot.id ? !showDetails : true);
                    }}
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        {selectedHotspot?.id === hotspot.id ? (
                          <ChevronUp className="w-4 h-4 text-gray-400" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-gray-400" />
                        )}
                        <div>
                          <div className="text-sm font-medium text-gray-900">{hotspot.rule_name}</div>
                          <div className="text-sm text-gray-500">{hotspot.message}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">{getProjectName(hotspot.project_id)}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(hotspot.status)}`}>
                        {getStatusIcon(hotspot.status)}
                        <span className="ml-1">{hotspot.status.replace('_', ' ')}</span>
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">{hotspot.file_path}</div>
                      <div className="text-sm text-gray-500">Line {hotspot.line_number}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {hotspot.cvss_score ? (
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getCVSSBackground(hotspot.cvss_score)} ${getCVSSColor(hotspot.cvss_score)}`}>
                          {hotspot.cvss_score.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {hotspot.cwe_id ? (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                          {hotspot.cwe_id}
                        </span>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {hotspot.created_at ? new Date(hotspot.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedHotspot(hotspot);
                            setShowReviewModal(true);
                          }}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          <MessageSquare className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            // Open file in editor
                          }}
                          className="text-green-600 hover:text-green-900"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                  
                  {/* Expanded Details */}
                  {selectedHotspot?.id === hotspot.id && showDetails && (
                    <tr>
                      <td colSpan={8} className="px-6 py-4 bg-gray-50">
                        <div className="space-y-4">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                              <h4 className="text-sm font-medium text-gray-900 mb-2">Description</h4>
                              <p className="text-sm text-gray-600">
                                {hotspot.description || 'No description available.'}
                              </p>
                            </div>
                            <div>
                              <h4 className="text-sm font-medium text-gray-900 mb-2">Security Details</h4>
                              <div className="space-y-2">
                                {hotspot.owasp_category && (
                                  <div className="flex justify-between">
                                    <span className="text-sm text-gray-600">OWASP Category:</span>
                                    <span className="text-sm font-medium text-gray-900">{hotspot.owasp_category}</span>
                                  </div>
                                )}
                                {hotspot.tags && hotspot.tags.length > 0 && (
                                  <div>
                                    <span className="text-sm text-gray-600">Tags:</span>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {hotspot.tags.map((tag, index) => (
                                        <span key={index} className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                          {tag}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                          
                          {hotspot.review_comment && (
                            <div>
                              <h4 className="text-sm font-medium text-gray-900 mb-2">Review Comment</h4>
                              <p className="text-sm text-gray-600 bg-white p-3 rounded border">
                                {hotspot.review_comment}
                              </p>
                            </div>
                          )}
                          
                          <div className="flex justify-between items-center pt-4 border-t border-gray-200">
                            <div className="flex items-center space-x-4 text-sm text-gray-500">
                              {hotspot.reviewed_by && (
                                <div className="flex items-center space-x-1">
                                  <User className="w-4 h-4" />
                                  <span>Reviewed by {hotspot.reviewed_by}</span>
                                </div>
                              )}
                              {hotspot.reviewed_at && (
                                <div className="flex items-center space-x-1">
                                  <Calendar className="w-4 h-4" />
                                  <span>{new Date(hotspot.reviewed_at).toLocaleDateString()}</span>
                                </div>
                              )}
                            </div>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedHotspot(hotspot);
                                setShowReviewModal(true);
                              }}
                              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
                            >
                              Review Hotspot
                            </button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Review Modal */}
      {showReviewModal && selectedHotspot && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Review Security Hotspot</h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Rule: {selectedHotspot.rule_name}
                  </label>
                  <p className="text-sm text-gray-600 mb-4">{selectedHotspot.message}</p>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Status
                  </label>
                  <select
                    value={reviewStatus}
                    onChange={(e) => setReviewStatus(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="SAFE">Safe</option>
                    <option value="FIXED">Fixed</option>
                    <option value="ACKNOWLEDGED">Acknowledged</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Comment
                  </label>
                  <textarea
                    value={reviewComment}
                    onChange={(e) => setReviewComment(e.target.value)}
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="Add your review comment..."
                  />
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => {
                    setShowReviewModal(false);
                    setSelectedHotspot(null);
                    setReviewStatus('SAFE');
                    setReviewComment('');
                  }}
                  className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleReview}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Submit Review
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SASTSecurityHotspots; 