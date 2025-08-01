import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface Incident {
  id: number;
  title: string;
  description: string;
  incident_type: string;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  priority: string;
  tags: string[];
  evidence_files?: string[];
  comments?: Comment[];
}

interface Comment {
  id: number;
  user: string;
  message: string;
  created_at: string;
  is_internal: boolean;
}

const MyIncidents: React.FC = () => {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [showIncidentModal, setShowIncidentModal] = useState(false);
  const [newComment, setNewComment] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchUserIncidents();
  }, []);

  const fetchUserIncidents = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/user/incidents`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch incidents');
      }

      const data = await response.json();
      setIncidents(data || getMockIncidents());
    } catch (err) {
      console.error('Error fetching incidents:', err);
      setIncidents(getMockIncidents());
    } finally {
      setLoading(false);
    }
  };

  const getMockIncidents = (): Incident[] => [
    {
      id: 1,
      title: "Suspicious Email Report",
      description: "Received an email claiming to be from IT support asking for password reset",
      incident_type: "phishing",
      severity: "medium",
      status: "open",
      priority: "medium",
      created_at: "2024-01-15T10:30:00Z",
      updated_at: "2024-01-15T14:20:00Z",
      assigned_to: "Security Team",
      tags: ["phishing", "email", "credentials"],
      evidence_files: ["screenshot.png", "email.eml"],
      comments: [
        {
          id: 1,
          user: "Security Analyst",
          message: "Thank you for reporting this. We're investigating the email source.",
          created_at: "2024-01-15T11:00:00Z",
          is_internal: false
        }
      ]
    },
    {
      id: 2,
      title: "Unauthorized Access Attempt",
      description: "Multiple failed login attempts detected on my account",
      incident_type: "unauthorized_access",
      severity: "high",
      status: "investigating",
      priority: "high",
      created_at: "2024-01-14T16:45:00Z",
      updated_at: "2024-01-15T09:15:00Z",
      assigned_to: "Security Team",
      tags: ["login", "brute_force", "account_security"],
      evidence_files: ["login_logs.txt"],
      comments: [
        {
          id: 2,
          user: "Security Analyst",
          message: "We've reset your password and enabled additional security measures.",
          created_at: "2024-01-14T17:00:00Z",
          is_internal: false
        }
      ]
    },
    {
      id: 3,
      title: "Suspicious USB Device",
      description: "Found an unknown USB device connected to my workstation",
      incident_type: "suspicious_activity",
      severity: "low",
      status: "resolved",
      priority: "low",
      created_at: "2024-01-10T08:30:00Z",
      updated_at: "2024-01-10T12:00:00Z",
      assigned_to: "IT Support",
      tags: ["usb", "workstation", "physical_security"],
      evidence_files: ["device_photo.jpg"],
      comments: [
        {
          id: 3,
          user: "IT Support",
          message: "Device has been removed and scanned. No threats detected.",
          created_at: "2024-01-10T12:00:00Z",
          is_internal: false
        }
      ]
    }
  ];

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open': return 'text-orange-400 bg-orange-900/20';
      case 'investigating': return 'text-blue-400 bg-blue-900/20';
      case 'resolved': return 'text-green-400 bg-green-900/20';
      case 'closed': return 'text-gray-400 bg-gray-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-900/20';
      case 'high': return 'text-orange-400 bg-orange-900/20';
      case 'medium': return 'text-yellow-400 bg-yellow-900/20';
      case 'low': return 'text-green-400 bg-green-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'urgent': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const handleAddComment = async () => {
    if (!newComment.trim() || !selectedIncident) return;

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_URL}/api/v1/user/incidents/${selectedIncident.id}/comments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: newComment }),
      });

      if (response.ok) {
        setNewComment('');
        fetchUserIncidents(); // Refresh to get updated comments
      }
    } catch (error) {
      console.error('Error adding comment:', error);
    }
  };

  const filteredIncidents = incidents.filter(incident => {
    if (filterStatus && incident.status !== filterStatus) return false;
    if (filterSeverity && incident.severity !== filterSeverity) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-accent"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900/20 to-purple-900/20 border border-cyber-accent/30 rounded-lg p-6">
        <h1 className="text-3xl font-bold text-white mb-2">📋 My Incidents</h1>
        <p className="text-gray-400">
          Track and manage your reported security incidents.
        </p>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-white">{incidents.length}</div>
          <div className="text-gray-400">Total Incidents</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-orange-400">
            {incidents.filter(i => i.status === 'open').length}
          </div>
          <div className="text-gray-400">Open</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-blue-400">
            {incidents.filter(i => i.status === 'investigating').length}
          </div>
          <div className="text-gray-400">Investigating</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">
            {incidents.filter(i => i.status === 'resolved').length}
          </div>
          <div className="text-gray-400">Resolved</div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Status</label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            >
              <option value="">All Status</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Severity</label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            >
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => { setFilterStatus(''); setFilterSeverity(''); }}
              className="w-full bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Incidents List */}
      <div className="space-y-4">
        {filteredIncidents.map((incident) => (
          <div key={incident.id} className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6 hover:border-cyber-accent/50 transition-colors">
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <h3 className="text-lg font-semibold text-white">{incident.title}</h3>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(incident.status)}`}>
                    {incident.status}
                  </span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(incident.severity)}`}>
                    {incident.severity}
                  </span>
                  <span className={`text-xs font-medium ${getPriorityColor(incident.priority)}`}>
                    Priority: {incident.priority}
                  </span>
                </div>
                <p className="text-gray-400 mb-3">{incident.description}</p>
                <div className="flex items-center space-x-4 text-sm text-gray-500">
                  <span>Reported: {new Date(incident.created_at).toLocaleDateString()}</span>
                  <span>Updated: {new Date(incident.updated_at).toLocaleDateString()}</span>
                  {incident.assigned_to && (
                    <span>Assigned to: {incident.assigned_to}</span>
                  )}
                </div>
              </div>
              <button
                onClick={() => { setSelectedIncident(incident); setShowIncidentModal(true); }}
                className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
              >
                View Details
              </button>
            </div>
            
            {/* Tags */}
            {incident.tags.length > 0 && (
              <div className="flex flex-wrap gap-2 mb-3">
                {incident.tags.map((tag, index) => (
                  <span key={index} className="px-2 py-1 bg-cyber-dark text-cyber-accent text-xs rounded">
                    #{tag}
                  </span>
                ))}
              </div>
            )}
            
            {/* Evidence Files */}
            {incident.evidence_files && incident.evidence_files.length > 0 && (
              <div className="flex items-center space-x-2 text-sm text-gray-400">
                <span>📎 Evidence:</span>
                {incident.evidence_files.map((file, index) => (
                  <span key={index} className="text-cyber-accent hover:underline cursor-pointer">
                    {file}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Incident Detail Modal */}
      {showIncidentModal && selectedIncident && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white">{selectedIncident.title}</h2>
              <button
                onClick={() => setShowIncidentModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-3">Incident Details</h3>
                <div className="space-y-3">
                  <div>
                    <span className="text-gray-400">Description:</span>
                    <p className="text-white mt-1">{selectedIncident.description}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <span className="text-gray-400">Type:</span>
                      <p className="text-white">{selectedIncident.incident_type}</p>
                    </div>
                    <div>
                      <span className="text-gray-400">Severity:</span>
                      <p className="text-white">{selectedIncident.severity}</p>
                    </div>
                    <div>
                      <span className="text-gray-400">Status:</span>
                      <p className="text-white">{selectedIncident.status}</p>
                    </div>
                    <div>
                      <span className="text-gray-400">Priority:</span>
                      <p className="text-white">{selectedIncident.priority}</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-3">Timeline</h3>
                <div className="space-y-3">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                    <div>
                      <p className="text-white text-sm">Incident Reported</p>
                      <p className="text-gray-400 text-xs">{new Date(selectedIncident.created_at).toLocaleString()}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-blue-400 rounded-full"></div>
                    <div>
                      <p className="text-white text-sm">Last Updated</p>
                      <p className="text-gray-400 text-xs">{new Date(selectedIncident.updated_at).toLocaleString()}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Comments Section */}
            <div className="border-t border-cyber-accent/20 pt-6">
              <h3 className="text-lg font-semibold text-white mb-4">Comments & Updates</h3>
              
              <div className="space-y-4 mb-4">
                {selectedIncident.comments?.map((comment) => (
                  <div key={comment.id} className="bg-cyber-dark rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-medium">{comment.user}</span>
                      <span className="text-gray-400 text-sm">{new Date(comment.created_at).toLocaleString()}</span>
                    </div>
                    <p className="text-gray-300">{comment.message}</p>
                  </div>
                ))}
              </div>
              
              {/* Add Comment */}
              <div className="space-y-3">
                <textarea
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  placeholder="Add a comment or update..."
                  className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
                  rows={3}
                />
                <div className="flex justify-end space-x-3">
                  <button
                    onClick={() => setShowIncidentModal(false)}
                    className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg"
                  >
                    Close
                  </button>
                  <button
                    onClick={handleAddComment}
                    disabled={!newComment.trim()}
                    className="bg-cyber-accent hover:bg-cyber-accent/80 disabled:bg-gray-600 text-white px-4 py-2 rounded-lg"
                  >
                    Add Comment
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MyIncidents; 