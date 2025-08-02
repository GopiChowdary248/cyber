import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { 
  ArrowLeftIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  DocumentTextIcon,
  ChartBarIcon,
  EyeIcon,
  CodeBracketIcon,
  ShieldExclamationIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';

import { EnhancedCard, EnhancedButton, EnhancedBadge, EnhancedTabs, EnhancedModal } from '../../components/UI/Enhanced';
import { useAuth } from '../../contexts/AuthContext';
import { apiClient } from '../../utils/apiClient';

// Use window.innerWidth for web instead of React Native Dimensions
const width = window.innerWidth;

interface Vulnerability {
  id: number;
  scan_id: number;
  file_path: string;
  line_no: number;
  column_no?: number;
  vulnerability: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  recommendation?: string;
  tool_name: string;
  cwe_id?: string;
  confidence: string;
  status: 'open' | 'fixed' | 'false_positive' | 'wont_fix' | 'in_progress';
  detected_at: string;
}

interface ScanDetails {
  id: number;
  project_id: number;
  project_name: string;
  triggered_by: string;
  start_time: string;
  end_time?: string;
  status: 'running' | 'completed' | 'failed';
  scan_type: string;
  scan_config: any;
  total_files: number;
  scanned_files: number;
  vulnerabilities_found: number;
  created_at: string;
}

interface ScanSummary {
  scan_id: number;
  project_name: string;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  risk_score: number;
  scan_duration?: number;
  languages_detected: string[];
  tools_used: string[];
  most_common_vulnerabilities: Array<{ type: string; count: number }>;
  severity_distribution: Record<string, number>;
}

const SASTScanDetails: React.FC = () => {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const { user } = useAuth();

  const [scanDetails, setScanDetails] = useState<ScanDetails | null>(null);
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedTool, setSelectedTool] = useState<string>('all');
  const [showVulnModal, setShowVulnModal] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);

  useEffect(() => {
    if (scanId) {
      fetchScanData();
    }
  }, [scanId]);

  const fetchScanData = async () => {
    try {
      setLoading(true);
      const [detailsResponse, summaryResponse, vulnsResponse] = await Promise.all([
        apiClient.get(`/api/v1/sast/scans/${scanId}`),
        apiClient.get(`/api/v1/sast/scans/${scanId}/summary`),
        apiClient.get(`/api/v1/sast/scans/${scanId}/vulnerabilities`)
      ]);

      setScanDetails(detailsResponse.data);
      setScanSummary(summaryResponse.data);
      setVulnerabilities(vulnsResponse.data);
    } catch (error) {
      console.error('Error fetching scan data:', error);
      // Use web alert instead of React Native Alert
      alert('Error: Failed to load scan data');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchScanData();
    setRefreshing(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'warning';
      case 'failed': return 'danger';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'running':
        return <ClockIcon className="w-5 h-5 text-yellow-500" />;
      case 'failed':
        return <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />;
      default:
        return <InformationCircleIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'danger';
      case 'high': return 'danger';
      case 'medium': return 'warning';
      case 'low': return 'info';
      case 'info': return 'default';
      default: return 'default';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <ShieldExclamationIcon className="w-4 h-4 text-red-500" />;
      case 'medium':
        return <ExclamationTriangleIcon className="w-4 h-4 text-yellow-500" />;
      case 'low':
      case 'info':
        return <InformationCircleIcon className="w-4 h-4 text-blue-500" />;
      default:
        return <InformationCircleIcon className="w-4 h-4 text-gray-500" />;
    }
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return 'N/A';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours}h ${minutes}m ${secs}s`;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const updateVulnerabilityStatus = async (vulnId: number, status: string) => {
    try {
      await apiClient.put(`/api/v1/sast/vulnerabilities/${vulnId}/status`, {
        status: status
      });
      
      // Update local state
      setVulnerabilities(prev => prev.map(v => 
        v.id === vulnId ? { ...v, status: status as any } : v
      ));
      
      alert('Success: Vulnerability status updated successfully');
    } catch (error) {
      console.error('Error updating vulnerability status:', error);
      alert('Error: Failed to update vulnerability status');
    }
  };

  const downloadReport = async (reportType: string) => {
    try {
      const response = await apiClient.get(`/api/v1/sast/scans/${scanId}/reports/${reportType}`, {
        responseType: 'blob'
      });
      
      // Handle file download for web
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `sast-report-${scanId}.${reportType}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      alert(`Success: ${reportType.toUpperCase()} report downloaded successfully`);
    } catch (error) {
      console.error('Error downloading report:', error);
      alert('Error: Failed to download report');
    }
  };

  const openVulnerabilityDetails = (vulnerability: Vulnerability) => {
    setSelectedVulnerability(vulnerability);
    setShowVulnModal(true);
  };

  if (loading) {
    return (
      <div className="flex-1 justify-center items-center bg-gray-50 min-h-screen flex flex-col">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <p className="mt-4 text-gray-600">Loading scan details...</p>
      </div>
    );
  }

  if (!scanDetails || !scanSummary) {
    return (
      <div className="flex-1 justify-center items-center bg-gray-50 min-h-screen flex flex-col">
        <p className="text-gray-600">Scan not found</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <button
              onClick={() => navigate(-1)}
              className="p-2 mr-3 hover:bg-gray-100 rounded"
            >
              <ArrowLeftIcon className="w-5 h-5 text-gray-600" />
            </button>
            <div>
              <h1 className="text-xl font-bold text-gray-900">{scanDetails.project_name}</h1>
              <p className="text-gray-600">Scan #{scanDetails.id}</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {getStatusIcon(scanDetails.status)}
            <EnhancedBadge variant={getStatusColor(scanDetails.status)}>
              {scanDetails.status}
            </EnhancedBadge>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="p-6">
        <EnhancedCard className="mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Quick Actions</h2>
          </div>
          <div className="flex space-x-3">
            <EnhancedButton
              onClick={() => downloadReport('pdf')}
              className="flex-1"
              variant="secondary"
            >
              <DocumentTextIcon className="w-4 h-4 mr-2" />
              Download PDF
            </EnhancedButton>
            <EnhancedButton
              onClick={() => downloadReport('json')}
              className="flex-1"
              variant="secondary"
            >
              <DocumentTextIcon className="w-4 h-4 mr-2" />
              Download JSON
            </EnhancedButton>
          </div>
        </EnhancedCard>

        {/* Scan Summary */}
        <EnhancedCard className="mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Scan Summary</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-red-600">{scanSummary.critical_count}</p>
              <p className="text-sm text-gray-600">Critical</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-orange-600">{scanSummary.high_count}</p>
              <p className="text-sm text-gray-600">High</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-yellow-600">{scanSummary.medium_count}</p>
              <p className="text-sm text-gray-600">Medium</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-blue-600">{scanSummary.low_count}</p>
              <p className="text-sm text-gray-600">Low</p>
            </div>
          </div>
        </EnhancedCard>

        {/* Vulnerabilities List */}
        <EnhancedCard>
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Vulnerabilities</h2>
          <div className="space-y-4">
            {vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      {getSeverityIcon(vuln.severity)}
                      <EnhancedBadge variant={getSeverityColor(vuln.severity)}>
                        {vuln.severity}
                      </EnhancedBadge>
                      <span className="text-sm text-gray-500">{vuln.tool_name}</span>
                    </div>
                    <h3 className="font-medium text-gray-900">{vuln.vulnerability}</h3>
                    <p className="text-sm text-gray-600 mt-1">
                      File: {vuln.file_path}:{vuln.line_no}
                    </p>
                    {vuln.recommendation && (
                      <p className="text-sm text-gray-700 mt-2">{vuln.recommendation}</p>
                    )}
                  </div>
                  <button
                    onClick={() => openVulnerabilityDetails(vuln)}
                    className="p-2 hover:bg-gray-100 rounded"
                  >
                    <EyeIcon className="w-4 h-4 text-gray-600" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </EnhancedCard>
      </div>

      {/* Vulnerability Details Modal */}
      {showVulnModal && selectedVulnerability && (
        <EnhancedModal
          isOpen={showVulnModal}
          onClose={() => setShowVulnModal(false)}
          title="Vulnerability Details"
        >
          <div className="space-y-4">
            <div>
              <h3 className="font-medium text-gray-900">Vulnerability</h3>
              <p className="text-gray-700">{selectedVulnerability.vulnerability}</p>
            </div>
            <div>
              <h3 className="font-medium text-gray-900">File Location</h3>
              <p className="text-gray-700">{selectedVulnerability.file_path}:{selectedVulnerability.line_no}</p>
            </div>
            {selectedVulnerability.recommendation && (
              <div>
                <h3 className="font-medium text-gray-900">Recommendation</h3>
                <p className="text-gray-700">{selectedVulnerability.recommendation}</p>
              </div>
            )}
            <div>
              <h3 className="font-medium text-gray-900">Status</h3>
              <select
                value={selectedVulnerability.status}
                onChange={(e) => updateVulnerabilityStatus(selectedVulnerability.id, e.target.value)}
                className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="open">Open</option>
                <option value="fixed">Fixed</option>
                <option value="false_positive">False Positive</option>
                <option value="wont_fix">Won't Fix</option>
                <option value="in_progress">In Progress</option>
              </select>
            </div>
          </div>
        </EnhancedModal>
      )}
    </div>
  );
};

export default SASTScanDetails; 