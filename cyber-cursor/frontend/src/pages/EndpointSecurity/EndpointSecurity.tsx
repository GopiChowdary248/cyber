import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Lock,
  Monitor,
  Laptop,
  Smartphone,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Plus,
  Search,
  Filter,
  Download,
  Upload,
  Eye,
  EyeOff,
  Users,
  Settings,
  Zap
} from 'lucide-react';

interface EndpointSecurityData {
  overview: {
    totalEndpoints: number;
    protectedEndpoints: number;
    threatsBlocked: number;
    securityScore: number;
  };
  antivirus: {
    totalScans: number;
    activeProtection: number;
    threatsDetected: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  edr: {
    totalAlerts: number;
    criticalAlerts: number;
    falsePositives: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  dlp: {
    policyViolations: number;
    dataBreaches: number;
    protectedFiles: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  patching: {
    totalUpdates: number;
    pendingUpdates: number;
    lastPatchDate: string;
    status: 'healthy' | 'warning' | 'critical';
  };
}

const EndpointSecurity: React.FC = () => {
  const [data, setData] = useState<EndpointSecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Simulate API call
    const fetchData = async () => {
      try {
        // Mock data - in real app, this would be an API call
        const mockData: EndpointSecurityData = {
          overview: {
            totalEndpoints: 245,
            protectedEndpoints: 238,
            threatsBlocked: 156,
            securityScore: 94
          },
          antivirus: {
            totalScans: 1247,
            activeProtection: 238,
            threatsDetected: 23,
            status: 'healthy'
          },
          edr: {
            totalAlerts: 67,
            criticalAlerts: 5,
            falsePositives: 18,
            status: 'warning'
          },
          dlp: {
            policyViolations: 12,
            dataBreaches: 0,
            protectedFiles: 15420,
            status: 'healthy'
          },
          patching: {
            totalUpdates: 89,
            pendingUpdates: 7,
            lastPatchDate: '2025-08-01',
            status: 'warning'
          }
        };
        
        setData(mockData);
      } catch (error) {
        console.error('Error fetching endpoint security data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-500 bg-green-100';
      case 'warning':
        return 'text-yellow-500 bg-yellow-100';
      case 'critical':
        return 'text-red-500 bg-red-100';
      default:
        return 'text-gray-500 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-5 h-5" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5" />;
      case 'critical':
        return <AlertTriangle className="w-5 h-5" />;
      default:
        return <TrendingUp className="w-5 h-5" />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <TrendingUp className="w-4 h-4" /> },
    { id: 'antivirus', label: 'Antivirus', icon: <Shield className="w-4 h-4" /> },
    { id: 'edr', label: 'EDR', icon: <Lock className="w-4 h-4" /> },
    { id: 'dlp', label: 'DLP', icon: <Shield className="w-4 h-4" /> },
    { id: 'patching', label: 'Patching', icon: <Settings className="w-4 h-4" /> },
    { id: 'monitoring', label: 'Monitoring', icon: <Monitor className="w-4 h-4" /> }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900">Error Loading Data</h3>
          <p className="text-gray-600">Unable to load endpoint security data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Endpoint Security</h1>
          <p className="text-gray-600">Monitor and manage endpoint protection across all devices</p>
        </div>
        <div className="flex items-center space-x-2">
          <Smartphone className="w-8 h-8 text-blue-600" />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-6"
      >
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Endpoints</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.totalEndpoints}</p>
                </div>
                <Smartphone className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Protected Endpoints</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.protectedEndpoints}</p>
                </div>
                <Shield className="w-8 h-8 text-green-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Threats Blocked</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.threatsBlocked}</p>
                </div>
                <Shield className="w-8 h-8 text-red-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.securityScore}%</p>
                </div>
                <TrendingUp className="w-8 h-8 text-purple-600" />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'antivirus' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Antivirus Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.antivirus.status)}`}>
                  {getStatusIcon(data.antivirus.status)}
                  <span className="capitalize">{data.antivirus.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Scans</p>
                  <p className="text-xl font-semibold text-gray-900">{data.antivirus.totalScans}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Protection</p>
                  <p className="text-xl font-semibold text-gray-900">{data.antivirus.activeProtection}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Threats Detected</p>
                  <p className="text-xl font-semibold text-gray-900">{data.antivirus.threatsDetected}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'edr' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">EDR Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.edr.status)}`}>
                  {getStatusIcon(data.edr.status)}
                  <span className="capitalize">{data.edr.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Alerts</p>
                  <p className="text-xl font-semibold text-gray-900">{data.edr.totalAlerts}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Critical Alerts</p>
                  <p className="text-xl font-semibold text-red-600">{data.edr.criticalAlerts}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">False Positives</p>
                  <p className="text-xl font-semibold text-gray-900">{data.edr.falsePositives}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'dlp' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">DLP Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.dlp.status)}`}>
                  {getStatusIcon(data.dlp.status)}
                  <span className="capitalize">{data.dlp.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Policy Violations</p>
                  <p className="text-xl font-semibold text-gray-900">{data.dlp.policyViolations}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Data Breaches</p>
                  <p className="text-xl font-semibold text-red-600">{data.dlp.dataBreaches}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Protected Files</p>
                  <p className="text-xl font-semibold text-gray-900">{data.dlp.protectedFiles.toLocaleString()}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'patching' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Patching Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.patching.status)}`}>
                  {getStatusIcon(data.patching.status)}
                  <span className="capitalize">{data.patching.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Updates</p>
                  <p className="text-xl font-semibold text-gray-900">{data.patching.totalUpdates}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Pending Updates</p>
                  <p className="text-xl font-semibold text-yellow-600">{data.patching.pendingUpdates}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Last Patch Date</p>
                  <p className="text-xl font-semibold text-gray-900">{data.patching.lastPatchDate}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'monitoring' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Endpoint Security Monitoring</h3>
            <p className="text-gray-600">Real-time monitoring dashboard for endpoint security events and alerts.</p>
            <div className="mt-4 p-4 bg-gray-50 rounded-lg">
              <p className="text-sm text-gray-500">Monitoring features coming soon...</p>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default EndpointSecurity; 