import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ChartBarIcon,
  ExclamationTriangleIcon,
  DocumentMagnifyingGlassIcon,
  BugAntIcon,
  WrenchScrewdriverIcon,
  ClipboardDocumentIcon,
  CogIcon,
  DocumentTextIcon,
  ShieldCheckIcon,
  BellIcon,
  ArrowPathIcon,
  ServerIcon,
  TagIcon,
  LockClosedIcon,
  ClockIcon
} from '@heroicons/react/24/outline';
import { Shield, Zap, Activity } from 'lucide-react';
import RASPDashboard from './RASPDashboard';
import RASPApplications from './RASPApplications';

interface RASPData {
  overview: {
    totalProjects: number;
    activeMonitoring: number;
    attacksBlocked: number;
    securityScore: number;
  };
  attacks: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  environments: {
    production: number;
    staging: number;
    development: number;
    testing: number;
  };
  recentScans: Array<{
    id: string;
    projectName: string;
    status: 'completed' | 'running' | 'failed' | 'queued';
    attacksDetected: number;
    duration: string;
    timestamp: string;
  }>;
}

const RASP: React.FC = () => {
  const [data, setData] = useState<RASPData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const mockData: RASPData = {
          overview: {
            totalProjects: 24,
            activeMonitoring: 18,
            attacksBlocked: 156,
            securityScore: 92
          },
          attacks: {
            critical: 3,
            high: 12,
            medium: 28,
            low: 45,
            total: 88
          },
          environments: {
            production: 8,
            staging: 6,
            development: 7,
            testing: 3
          },
          recentScans: [
            {
              id: 'scan-001',
              projectName: 'E-commerce Platform',
              status: 'completed',
              attacksDetected: 2,
              duration: '1m 45s',
              timestamp: '2 hours ago'
            },
            {
              id: 'scan-002',
              projectName: 'API Gateway',
              status: 'running',
              attacksDetected: 0,
              duration: '45s',
              timestamp: '5 minutes ago'
            },
            {
              id: 'scan-003',
              projectName: 'User Management',
              status: 'completed',
              attacksDetected: 1,
              duration: '2m 12s',
              timestamp: '1 hour ago'
            }
          ]
        };
        setData(mockData);
      } catch (error) {
        console.error('Error loading RASP data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: <ChartBarIcon className="w-4 h-4" /> },
    { id: 'applications', label: 'Applications', icon: <DocumentTextIcon className="w-4 h-4" /> },
    { id: 'agents', label: 'Agents', icon: <ServerIcon className="w-4 h-4" /> },
    { id: 'incidents', label: 'Incidents', icon: <ExclamationTriangleIcon className="w-4 h-4" /> },
    { id: 'policies', label: 'Policies', icon: <ShieldCheckIcon className="w-4 h-4" /> },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <BugAntIcon className="w-4 h-4" /> },
    { id: 'traces', label: 'Traces', icon: <DocumentMagnifyingGlassIcon className="w-4 h-4" /> },
    { id: 'integrations', label: 'Integrations', icon: <CogIcon className="w-4 h-4" /> }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-600 bg-green-100';
      case 'running':
        return 'text-blue-600 bg-blue-100';
      case 'failed':
        return 'text-red-600 bg-red-100';
      case 'queued':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <ShieldCheckIcon className="w-4 h-4" />;
      case 'running':
        return <ChartBarIcon className="w-4 h-4" />;
      case 'failed':
        return <ExclamationTriangleIcon className="w-4 h-4" />;
      case 'queued':
        return <ClockIcon className="w-4 h-4" />;
      default:
        return <ClockIcon className="w-4 h-4" />;
    }
  };

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
          <ExclamationTriangleIcon className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900">Error Loading Data</h3>
          <p className="text-gray-600">Unable to load RASP data</p>
        </div>
      </div>
    );
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <RASPDashboard />;
      case 'applications':
        return <RASPApplications />;
      case 'agents':
        return (
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">RASP Agents</h2>
            <p className="text-gray-600">Agent management interface coming soon...</p>
          </div>
        );
      case 'incidents':
        return (
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">RASP Incidents</h2>
            <p className="text-gray-600">Incident management interface coming soon...</p>
          </div>
        );
      case 'policies':
        return (
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">RASP Policies</h2>
            <p className="text-gray-600">Policy management interface coming soon...</p>
          </div>
        );
      case 'vulnerabilities':
        return (
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">RASP Vulnerabilities</h2>
            <p className="text-gray-600">Vulnerability management interface coming soon...</p>
          </div>
        );
      case 'traces':
        return (
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">RASP Traces</h2>
            <p className="text-gray-600">Trace management interface coming soon...</p>
          </div>
        );
      case 'integrations':
        return (
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">RASP Integrations</h2>
            <p className="text-gray-600">Integration management interface coming soon...</p>
          </div>
        );
      default:
        return <RASPDashboard />;
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">RASP - Runtime Application Self-Protection</h1>
          <p className="text-gray-600">Monitor and protect your applications in real-time with advanced runtime security controls</p>
        </div>
        <div className="flex items-center space-x-2">
          <Shield className="w-8 h-8 text-blue-600" />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
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
        {renderTabContent()}
      </motion.div>
    </div>
  );
};

export default RASP;
