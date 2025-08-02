import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  CodeBracketIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon,
  ClockIcon,
  DocumentTextIcon,
  CloudArrowUpIcon,
  ChartBarIcon,
  CogIcon,
  PlayIcon,
  StopIcon
} from '@heroicons/react/24/outline';

interface SASTScan {
  id: string;
  project_name: string;
  status: 'running' | 'completed' | 'failed';
  start_time: string;
  end_time?: string;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_duration?: number;
  languages_detected?: string[];
  tools_used?: string[];
  created_at: string;
}

interface SASTSummary {
  total_scans: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  average_risk_score: number;
  most_common_vulnerabilities: Array<{ type: string; count: number }>;
  scan_trends: Array<{ date: string; scans: number; vulnerabilities: number }>;
}

const SASTDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');
  const [scans, setScans] = useState<SASTScan[]>([]);
  const [summary, setSummary] = useState<SASTSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [scansResponse, summaryResponse] = await Promise.all([
        fetch('/api/v1/sast/scans'),
        fetch('/api/v1/sast/summary')
      ]);
      
      if (scansResponse.ok && summaryResponse.ok) {
        const scansData = await scansResponse.json();
        const summaryData = await summaryResponse.json();
        setScans(scansData);
        setSummary(summaryData);
      } else {
        throw new Error('Failed to fetch data');
      }
    } catch (error) {
      console.error('Error fetching SAST data:', error);
      alert('Failed to load SAST data');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchData();
    setRefreshing(false);
  };

  const triggerNewScan = async () => {
    try {
      setScanning(true);
      const response = await fetch('/api/v1/sast/scan/trigger', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        alert('New scan triggered successfully!');
        await fetchData(); // Refresh the data
      } else {
        throw new Error('Failed to trigger scan');
      }
    } catch (error) {
      console.error('Error triggering scan:', error);
      alert('Failed to trigger new scan');
    } finally {
      setScanning(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-100';
      case 'running': return 'text-blue-600 bg-blue-100';
      case 'failed': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleIcon className="h-5 w-5" />;
      case 'running': return <ClockIcon className="h-5 w-5" />;
      case 'failed': return <ExclamationTriangleIcon className="h-5 w-5" />;
      default: return <ClockIcon className="h-5 w-5" />;
    }
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return 'N/A';
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString();
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between py-6">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">SAST Dashboard</h1>
              <p className="text-gray-600 mt-1">Static Application Security Testing</p>
            </div>
            <div className="flex space-x-3">
              <button
                onClick={() => navigate('/sast/upload')}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
              >
                <CloudArrowUpIcon className="h-5 w-5 mr-2" />
                Upload & Scan
              </button>
              <button
                onClick={triggerNewScan}
                disabled={scanning}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
              >
                {scanning ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-gray-600 mr-2"></div>
                    Scanning...
                  </>
                ) : (
                  <>
                    <PlayIcon className="h-5 w-5 mr-2" />
                    New Scan
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <CodeBracketIcon className="h-6 w-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Scans</p>
                  <p className="text-2xl font-bold text-gray-900">{summary.total_scans}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center">
                <div className="p-2 bg-red-100 rounded-lg">
                  <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Vulnerabilities</p>
                  <p className="text-2xl font-bold text-gray-900">{summary.total_vulnerabilities}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center">
                <div className="p-2 bg-yellow-100 rounded-lg">
                  <ChartBarIcon className="h-6 w-6 text-yellow-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Risk Score</p>
                  <p className="text-2xl font-bold text-gray-900">{summary.average_risk_score.toFixed(1)}</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <CheckCircleIcon className="h-6 w-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Critical Issues</p>
                  <p className="text-2xl font-bold text-gray-900">{summary.critical_count}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="border-b border-gray-200">
            <nav className="flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab('overview')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'overview'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                Overview
              </button>
              <button
                onClick={() => setActiveTab('scans')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'scans'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                Recent Scans
              </button>
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Vulnerability Distribution */}
                {summary && (
                  <div>
                    <h3 className="text-lg font-medium text-gray-900 mb-4">Vulnerability Distribution</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="text-center p-4 bg-red-50 rounded-lg">
                        <p className="text-2xl font-bold text-red-600">{summary.critical_count}</p>
                        <p className="text-sm text-red-600">Critical</p>
                      </div>
                      <div className="text-center p-4 bg-orange-50 rounded-lg">
                        <p className="text-2xl font-bold text-orange-600">{summary.high_count}</p>
                        <p className="text-sm text-orange-600">High</p>
                      </div>
                      <div className="text-center p-4 bg-yellow-50 rounded-lg">
                        <p className="text-2xl font-bold text-yellow-600">{summary.medium_count}</p>
                        <p className="text-sm text-yellow-600">Medium</p>
                      </div>
                      <div className="text-center p-4 bg-green-50 rounded-lg">
                        <p className="text-2xl font-bold text-green-600">{summary.low_count}</p>
                        <p className="text-sm text-green-600">Low</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Most Common Vulnerabilities */}
                {summary && summary.most_common_vulnerabilities.length > 0 && (
                  <div>
                    <h3 className="text-lg font-medium text-gray-900 mb-4">Most Common Vulnerabilities</h3>
                    <div className="space-y-2">
                      {summary.most_common_vulnerabilities.slice(0, 5).map((vuln, index) => (
                        <div key={index} className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                          <span className="text-sm font-medium text-gray-900">{vuln.type}</span>
                          <span className="text-sm text-gray-600">{vuln.count} occurrences</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'scans' && (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-medium text-gray-900">Recent Scans</h3>
                  <button
                    onClick={onRefresh}
                    disabled={refreshing}
                    className="text-sm text-blue-600 hover:text-blue-800 disabled:opacity-50"
                  >
                    {refreshing ? 'Refreshing...' : 'Refresh'}
                  </button>
                </div>

                {scans.length === 0 ? (
                  <div className="text-center py-12">
                    <CodeBracketIcon className="mx-auto h-12 w-12 text-gray-400" />
                    <h3 className="mt-2 text-sm font-medium text-gray-900">No scans yet</h3>
                    <p className="mt-1 text-sm text-gray-500">Get started by uploading your code for analysis.</p>
                    <div className="mt-6">
                      <button
                        onClick={() => navigate('/sast/upload')}
                        className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                      >
                        <CloudArrowUpIcon className="h-5 w-5 mr-2" />
                        Upload & Scan
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {scans.map((scan) => (
                      <div key={scan.id} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-4">
                            <div className={`p-2 rounded-lg ${getStatusColor(scan.status)}`}>
                              {getStatusIcon(scan.status)}
                            </div>
                            <div>
                              <h4 className="text-sm font-medium text-gray-900">{scan.project_name}</h4>
                              <p className="text-sm text-gray-500">
                                Started {formatDate(scan.start_time)}
                                {scan.scan_duration && ` • Duration: ${formatDuration(scan.scan_duration)}`}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-4">
                            <div className="text-right">
                              <p className="text-sm font-medium text-gray-900">{scan.total_vulnerabilities} issues</p>
                              <p className="text-xs text-gray-500">
                                {scan.critical_count} critical, {scan.high_count} high
                              </p>
                            </div>
                            <button
                              onClick={() => navigate(`/sast/scan/${scan.id}`)}
                              className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                            >
                              View Details
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SASTDashboard; 