import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Play, Square, RefreshCw, Download, Trash2, Plus, Settings,
  Target, AlertTriangle, CheckCircle, XCircle, Clock, BarChart3, FileText
} from 'lucide-react';

interface ScanProfile {
  id: string;
  name: string;
  description: string;
  modules: string[];
  settings: {
    timeout: number;
    follow_redirects: boolean;
    verify_ssl: boolean;
    max_depth: number;
    max_requests: number;
    delay: number;
  };
  created_at: string;
  is_default: boolean;
}

interface ActiveScan {
  id: string;
  name: string;
  target_url: string;
  profile_id: string;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'error';
  progress: number;
  total_requests: number;
  completed_requests: number;
  issues_found: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

interface ScanIssue {
  id: string;
  scan_id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  url: string;
  evidence?: string;
  confidence: number;
  cwe_id?: string;
  cvss_score?: number;
  discovered_at: string;
  status: 'open' | 'confirmed' | 'false_positive' | 'fixed';
  tags: string[];
}

interface DASTScannerIntegrationProps {
  projectId: string;
}

const DASTScannerIntegration: React.FC<DASTScannerIntegrationProps> = ({ projectId }) => {
  const [scanProfiles, setScanProfiles] = useState<ScanProfile[]>([]);
  const [activeScans, setActiveScans] = useState<ActiveScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<ActiveScan | null>(null);
  const [scanIssues, setScanIssues] = useState<ScanIssue[]>([]);
  const [showCreateScan, setShowCreateScan] = useState(false);
  const [showProfileManager, setShowProfileManager] = useState(false);
  const [loading, setLoading] = useState(false);

  // Load scan profiles
  const loadScanProfiles = useCallback(async () => {
    const mockProfiles: ScanProfile[] = [
      {
        id: 'profile_1',
        name: 'Quick Scan',
        description: 'Fast scan with basic checks',
        modules: ['sql_injection', 'xss', 'open_redirect'],
        settings: {
          timeout: 30,
          follow_redirects: true,
          verify_ssl: false,
          max_depth: 3,
          max_requests: 100,
          delay: 0
        },
        created_at: new Date().toISOString(),
        is_default: true
      },
      {
        id: 'profile_2',
        name: 'Full Scan',
        description: 'Comprehensive security assessment',
        modules: ['sql_injection', 'xss', 'open_redirect', 'csrf', 'file_inclusion'],
        settings: {
          timeout: 60,
          follow_redirects: true,
          verify_ssl: true,
          max_depth: 10,
          max_requests: 1000,
          delay: 100
        },
        created_at: new Date().toISOString(),
        is_default: false
      }
    ];
    setScanProfiles(mockProfiles);
  }, []);

  // Load active scans
  const loadActiveScans = useCallback(async () => {
    const mockScans: ActiveScan[] = [
      {
        id: 'scan_1',
        name: 'Main Website Scan',
        target_url: 'https://example.com',
        profile_id: 'profile_1',
        status: 'completed',
        progress: 100,
        total_requests: 150,
        completed_requests: 150,
        issues_found: 3,
        started_at: new Date(Date.now() - 3600000).toISOString(),
        completed_at: new Date().toISOString(),
        created_at: new Date(Date.now() - 7200000).toISOString()
      }
    ];
    setActiveScans(mockScans);
  }, []);

  // Load scan issues
  const loadScanIssues = useCallback(async () => {
    const mockIssues: ScanIssue[] = [
      {
        id: 'issue_1',
        scan_id: 'scan_1',
        type: 'sql_injection',
        severity: 'high',
        title: 'SQL Injection Vulnerability',
        description: 'The application is vulnerable to SQL injection attacks.',
        url: 'https://example.com/search?q=test',
        evidence: "Payload: ' OR 1=1--",
        confidence: 90,
        cwe_id: 'CWE-89',
        cvss_score: 8.5,
        discovered_at: new Date().toISOString(),
        status: 'open',
        tags: ['sql', 'injection', 'high']
      }
    ];
    setScanIssues(mockIssues);
  }, []);

  // Initial load
  useEffect(() => {
    loadScanProfiles();
    loadActiveScans();
    loadScanIssues();
  }, [loadScanProfiles, loadActiveScans, loadScanIssues]);

  // Create new scan
  const createNewScan = useCallback(async (scanData: {
    name: string;
    target_url: string;
    profile_id: string;
  }) => {
    const newScan: ActiveScan = {
      id: `scan_${Date.now()}`,
      name: scanData.name,
      target_url: scanData.target_url,
      profile_id: scanData.profile_id,
      status: 'pending',
      progress: 0,
      total_requests: 0,
      completed_requests: 0,
      issues_found: 0,
      created_at: new Date().toISOString()
    };

    setActiveScans(prev => [newScan, ...prev]);
    setSelectedScan(newScan);
    setShowCreateScan(false);
  }, []);

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-800 bg-red-100';
      case 'high': return 'text-red-700 bg-red-100';
      case 'medium': return 'text-yellow-700 bg-yellow-100';
      case 'low': return 'text-blue-700 bg-blue-100';
      default: return 'text-gray-700 bg-gray-100';
    }
  };

  // Get status color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-green-600 bg-green-100';
      case 'completed': return 'text-blue-600 bg-blue-100';
      case 'error': return 'text-red-600 bg-red-100';
      case 'paused': return 'text-yellow-600 bg-yellow-100';
      case 'pending': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="bg-white border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-semibold text-gray-900">Scanner</h2>
            <span className="text-sm text-gray-500">
              {activeScans.length} active scans • {scanIssues.length} issues found
            </span>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => setShowProfileManager(!showProfileManager)}
              className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm ${
                showProfileManager ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Profiles</span>
            </button>

            <button
              onClick={() => setShowCreateScan(true)}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              <Plus className="w-4 h-4" />
              <span>New Scan</span>
            </button>
          </div>
        </div>

        {/* Profile Manager */}
        <AnimatePresence>
          {showProfileManager && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 p-4 bg-gray-50 rounded-lg"
            >
              <h3 className="text-sm font-medium text-gray-900 mb-3">Scan Profiles</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {scanProfiles.map((profile) => (
                  <div key={profile.id} className="border border-gray-200 rounded-lg p-3 bg-white">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium text-gray-900">{profile.name}</h4>
                      {profile.is_default && (
                        <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-blue-100 text-blue-800">
                          Default
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-600 mb-3">{profile.description}</p>
                    <div className="text-xs text-gray-500">
                      <div>Modules: {profile.modules.length}</div>
                      <div>Timeout: {profile.settings.timeout}s</div>
                      <div>Max Depth: {profile.settings.max_depth}</div>
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Scans List */}
        <div className="w-80 bg-white border-r border-gray-200 overflow-y-auto">
          <div className="p-4 border-b border-gray-200">
            <h3 className="text-sm font-medium text-gray-900">Active Scans</h3>
          </div>

          <div className="divide-y divide-gray-200">
            {activeScans.map((scan) => (
              <div
                key={scan.id}
                onClick={() => setSelectedScan(scan)}
                className={`p-3 cursor-pointer hover:bg-gray-50 transition-colors ${
                  selectedScan?.id === scan.id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex-1">
                    <div className="font-medium text-gray-900 truncate">{scan.name}</div>
                    <div className="text-xs text-gray-600 truncate">{scan.target_url}</div>
                  </div>
                </div>

                <div className="flex items-center space-x-2 mb-2">
                  <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getStatusColor(scan.status)}`}>
                    {scan.status}
                  </span>
                  <span className="text-xs text-gray-500">
                    {scan.issues_found} issues
                  </span>
                </div>

                <div className="text-xs text-gray-500">
                  {scan.completed_requests} / {scan.total_requests} requests
                </div>
              </div>
            ))}
          </div>

          {activeScans.length === 0 && (
            <div className="p-8 text-center text-gray-500">
              <Shield className="w-12 h-12 mx-auto mb-4 text-gray-300" />
              <p className="text-sm">No active scans</p>
              <p className="text-xs">Create a new scan to get started</p>
            </div>
          )}
        </div>

        {/* Scan Details and Issues */}
        <div className="flex-1 flex flex-col">
          {selectedScan ? (
            <>
              {/* Scan Details */}
              <div className="flex-1 flex flex-col border-b border-gray-200">
                <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                  <h3 className="font-medium text-gray-900">Scan Details</h3>
                </div>

                <div className="flex-1 p-4 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Scan Name</label>
                      <input
                        type="text"
                        value={selectedScan.name}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        readOnly
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Target URL</label>
                      <input
                        type="url"
                        value={selectedScan.target_url}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        readOnly
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-gray-50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-blue-600">{selectedScan.total_requests}</div>
                      <div className="text-sm text-gray-600">Total Requests</div>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-green-600">{selectedScan.completed_requests}</div>
                      <div className="text-sm text-gray-600">Completed</div>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-red-600">{selectedScan.issues_found}</div>
                      <div className="text-sm text-gray-600">Issues Found</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Issues */}
              <div className="flex-1 flex flex-col">
                <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                  <h3 className="font-medium text-gray-900">Scan Issues</h3>
                </div>

                <div className="flex-1 p-4 overflow-auto">
                  {scanIssues.length === 0 ? (
                    <div className="text-center text-gray-500 py-8">
                      <AlertTriangle className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                      <p className="text-lg font-medium">No issues found</p>
                      <p className="text-sm">The scan completed without finding any security issues</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {scanIssues.map((issue) => (
                        <div key={issue.id} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-2">
                                <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getSeverityColor(issue.severity)}`}>
                                  {issue.severity.toUpperCase()}
                                </span>
                                <span className="text-sm font-medium text-gray-900">{issue.title}</span>
                              </div>
                              <p className="text-sm text-gray-600 mb-2">{issue.description}</p>
                              <div className="text-xs text-gray-500">
                                <span>URL: {issue.url}</span>
                                {issue.cwe_id && <span className="ml-4">CWE: {issue.cwe_id}</span>}
                                {issue.cvss_score && <span className="ml-4">CVSS: {issue.cvss_score}</span>}
                              </div>
                            </div>
                          </div>

                          {issue.evidence && (
                            <div className="bg-gray-50 rounded p-2 mb-3">
                              <div className="text-xs font-medium text-gray-700 mb-1">Evidence:</div>
                              <code className="text-xs text-gray-800">{issue.evidence}</code>
                            </div>
                          )}

                          <div className="flex items-center justify-between text-xs text-gray-500">
                            <span>Confidence: {issue.confidence}%</span>
                            <span>Discovered: {new Date(issue.discovered_at).toLocaleString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              <div className="text-center">
                <Shield className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                <p className="text-lg font-medium">No scan selected</p>
                <p className="text-sm">Choose a scan from the list or create a new one</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create Scan Dialog */}
      <AnimatePresence>
        {showCreateScan && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-white rounded-lg p-6 w-96"
            >
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New Scan</h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Scan Name</label>
                  <input
                    type="text"
                    placeholder="My Security Scan"
                    id="scan-name"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Target URL</label>
                  <input
                    type="url"
                    placeholder="https://example.com"
                    id="target-url"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Scan Profile</label>
                  <select
                    id="scan-profile"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {scanProfiles.map((profile) => (
                      <option key={profile.id} value={profile.id}>
                        {profile.name} - {profile.description}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              
              <div className="flex items-center justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowCreateScan(false)}
                  className="px-4 py-2 text-gray-700 hover:text-gray-900"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    const name = (document.getElementById('scan-name') as HTMLInputElement).value;
                    const targetUrl = (document.getElementById('target-url') as HTMLInputElement).value;
                    const profileId = (document.getElementById('scan-profile') as HTMLSelectElement).value;
                    
                    if (name && targetUrl && profileId) {
                      createNewScan({ name, target_url: targetUrl, profile_id: profileId });
                    }
                  }}
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                >
                  Create Scan
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default DASTScannerIntegration;
