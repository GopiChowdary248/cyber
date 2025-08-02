import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  DocumentTextIcon, 
  ShieldCheckIcon, 
  BellIcon, 
  UserCircleIcon, 
  ComputerDesktopIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  CogIcon,
  LockClosedIcon,
  ServerIcon,
  ExclamationCircleIcon,
  ClockIcon,
  DocumentDuplicateIcon,
  MagnifyingGlassIcon,
  PlayIcon,
  StopIcon,
  EyeIcon,
  ChartPieIcon,
  GlobeAltIcon,
  WifiIcon,
  CloudIcon,
  KeyIcon,
  UserGroupIcon,
  Cog6ToothIcon,
  CommandLineIcon,
  BoltIcon,
  ShieldExclamationIcon,
  FireIcon
} from '@heroicons/react/24/outline';

interface SIEMSOARData {
  overview: {
    totalLogs: number;
    activeAlerts: number;
    openIncidents: number;
    securityScore: number;
  };
  logCollection: {
    totalSources: number;
    logsPerSecond: number;
    storageUsed: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  eventCorrelation: {
    correlationRules: number;
    activeRules: number;
    eventsCorrelated: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  incidentManagement: {
    totalIncidents: number;
    openIncidents: number;
    resolvedToday: number;
    avgResolutionTime: number;
  };
  playbooks: {
    totalPlaybooks: number;
    activePlaybooks: number;
    executionsToday: number;
    successRate: number;
  };
  threatIntelligence: {
    totalFeeds: number;
    activeFeeds: number;
    iocsProcessed: number;
    lastUpdate: string;
  };
  automation: {
    totalActions: number;
    successfulActions: number;
    failedActions: number;
    avgResponseTime: number;
  };
  compliance: {
    totalReports: number;
    complianceScore: number;
    auditLogs: number;
    lastAudit: string;
  };
}

const SIEMSOAR: React.FC = () => {
  const [data, setData] = useState<SIEMSOARData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Simulate API call
    const fetchData = async () => {
      try {
        // Mock data - in real app, this would be an API call
        const mockData: SIEMSOARData = {
          overview: {
            totalLogs: 15420000,
            activeAlerts: 23,
            openIncidents: 8,
            securityScore: 94
          },
          logCollection: {
            totalSources: 156,
            logsPerSecond: 2450,
            storageUsed: 2.4,
            status: 'healthy'
          },
          eventCorrelation: {
            correlationRules: 89,
            activeRules: 85,
            eventsCorrelated: 45670,
            status: 'healthy'
          },
          incidentManagement: {
            totalIncidents: 234,
            openIncidents: 8,
            resolvedToday: 12,
            avgResolutionTime: 2.5
          },
          playbooks: {
            totalPlaybooks: 45,
            activePlaybooks: 42,
            executionsToday: 156,
            successRate: 98.5
          },
          threatIntelligence: {
            totalFeeds: 23,
            activeFeeds: 21,
            iocsProcessed: 12340,
            lastUpdate: '2 minutes ago'
          },
          automation: {
            totalActions: 890,
            successfulActions: 875,
            failedActions: 15,
            avgResponseTime: 0.8
          },
          compliance: {
            totalReports: 89,
            complianceScore: 96,
            auditLogs: 45670,
            lastAudit: '1 hour ago'
          }
        };
        
        setData(mockData);
      } catch (error) {
        console.error('Error fetching SIEM/SOAR data:', error);
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
        return <CheckCircleIcon className="w-5 h-5" />;
      case 'warning':
        return <ExclamationTriangleIcon className="w-5 h-5" />;
      case 'critical':
        return <XCircleIcon className="w-5 h-5" />;
      default:
        return <ChartBarIcon className="w-5 h-5" />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" /> },
    { id: 'log-collection', label: 'Log Collection', icon: <ServerIcon className="w-4 h-4" /> },
    { id: 'event-correlation', label: 'Event Correlation', icon: <MagnifyingGlassIcon className="w-4 h-4" /> },
    { id: 'incident-management', label: 'Incident Management', icon: <ExclamationTriangleIcon className="w-4 h-4" /> },
    { id: 'playbooks', label: 'Playbooks', icon: <PlayIcon className="w-4 h-4" /> },
    { id: 'threat-intelligence', label: 'Threat Intelligence', icon: <GlobeAltIcon className="w-4 h-4" /> },
    { id: 'automation', label: 'Automation', icon: <BoltIcon className="w-4 h-4" /> },
    { id: 'compliance', label: 'Compliance', icon: <ShieldCheckIcon className="w-4 h-4" /> }
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
          <ExclamationTriangleIcon className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900">Error Loading Data</h3>
          <p className="text-gray-600">Unable to load SIEM/SOAR data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SIEM & SOAR</h1>
          <p className="text-gray-600">Security Information and Event Management with Orchestration, Automation, and Response</p>
        </div>
        <div className="flex items-center space-x-2">
          <ShieldExclamationIcon className="w-8 h-8 text-blue-600" />
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
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Logs</p>
                  <p className="text-2xl font-bold text-gray-900">{(data.overview.totalLogs / 1000000).toFixed(1)}M</p>
                </div>
                <ServerIcon className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Active Alerts</p>
                  <p className="text-2xl font-bold text-red-600">{data.overview.activeAlerts}</p>
                </div>
                <BellIcon className="w-8 h-8 text-red-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Open Incidents</p>
                  <p className="text-2xl font-bold text-orange-600">{data.overview.openIncidents}</p>
                </div>
                <ExclamationTriangleIcon className="w-8 h-8 text-orange-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.securityScore}%</p>
                </div>
                <ChartBarIcon className="w-8 h-8 text-green-600" />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'log-collection' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Log Collection Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.logCollection.status)}`}>
                  {getStatusIcon(data.logCollection.status)}
                  <span className="capitalize">{data.logCollection.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Sources</p>
                  <p className="text-xl font-semibold text-gray-900">{data.logCollection.totalSources}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Logs per Second</p>
                  <p className="text-xl font-semibold text-gray-900">{data.logCollection.logsPerSecond.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Storage Used</p>
                  <p className="text-xl font-semibold text-gray-900">{data.logCollection.storageUsed} TB</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Log Sources</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <ServerIcon className="w-4 h-4 text-blue-600" />
                    <span className="text-sm">Servers</span>
                  </div>
                  <span className="text-sm font-medium">45</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <WifiIcon className="w-4 h-4 text-green-600" />
                    <span className="text-sm">Network Devices</span>
                  </div>
                  <span className="text-sm font-medium">23</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <CloudIcon className="w-4 h-4 text-purple-600" />
                    <span className="text-sm">Cloud Services</span>
                  </div>
                  <span className="text-sm font-medium">12</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                                         <ServerIcon className="w-4 h-4 text-orange-600" />
                    <span className="text-sm">Applications</span>
                  </div>
                  <span className="text-sm font-medium">76</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'event-correlation' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Correlation Engine</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.eventCorrelation.status)}`}>
                  {getStatusIcon(data.eventCorrelation.status)}
                  <span className="capitalize">{data.eventCorrelation.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Rules</p>
                  <p className="text-xl font-semibold text-gray-900">{data.eventCorrelation.correlationRules}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Rules</p>
                  <p className="text-xl font-semibold text-gray-900">{data.eventCorrelation.activeRules}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Events Correlated</p>
                  <p className="text-xl font-semibold text-gray-900">{data.eventCorrelation.eventsCorrelated.toLocaleString()}</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Correlation Rules</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Brute Force Detection</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Data Exfiltration</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Privilege Escalation</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Malware Detection</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'incident-management' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Incident Overview</h3>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Incidents</p>
                  <p className="text-xl font-semibold text-gray-900">{data.incidentManagement.totalIncidents}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Open Incidents</p>
                  <p className="text-xl font-semibold text-orange-600">{data.incidentManagement.openIncidents}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Resolved Today</p>
                  <p className="text-xl font-semibold text-green-600">{data.incidentManagement.resolvedToday}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Avg Resolution Time</p>
                  <p className="text-xl font-semibold text-gray-900">{data.incidentManagement.avgResolutionTime} hours</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Incident Severity</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-red-600">Critical</span>
                  <span className="text-sm font-medium">2</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-orange-600">High</span>
                  <span className="text-sm font-medium">3</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-yellow-600">Medium</span>
                  <span className="text-sm font-medium">2</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-blue-600">Low</span>
                  <span className="text-sm font-medium">1</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'playbooks' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Playbook Overview</h3>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Playbooks</p>
                  <p className="text-xl font-semibold text-gray-900">{data.playbooks.totalPlaybooks}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Playbooks</p>
                  <p className="text-xl font-semibold text-green-600">{data.playbooks.activePlaybooks}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Executions Today</p>
                  <p className="text-xl font-semibold text-gray-900">{data.playbooks.executionsToday}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Success Rate</p>
                  <p className="text-xl font-semibold text-green-600">{data.playbooks.successRate}%</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Popular Playbooks</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">IP Blocking</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Host Isolation</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Account Disable</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Email Quarantine</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'threat-intelligence' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Intel Overview</h3>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Feeds</p>
                  <p className="text-xl font-semibold text-gray-900">{data.threatIntelligence.totalFeeds}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Feeds</p>
                  <p className="text-xl font-semibold text-green-600">{data.threatIntelligence.activeFeeds}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">IOCs Processed</p>
                  <p className="text-xl font-semibold text-gray-900">{data.threatIntelligence.iocsProcessed.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Last Update</p>
                  <p className="text-xl font-semibold text-gray-900">{data.threatIntelligence.lastUpdate}</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Intel Sources</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">VirusTotal</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">AbuseIPDB</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">AlienVault OTX</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">ThreatConnect</span>
                  <span className="text-sm font-medium text-green-600">Active</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'automation' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Automation Overview</h3>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Actions</p>
                  <p className="text-xl font-semibold text-gray-900">{data.automation.totalActions}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Successful</p>
                  <p className="text-xl font-semibold text-green-600">{data.automation.successfulActions}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Failed</p>
                  <p className="text-xl font-semibold text-red-600">{data.automation.failedActions}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Avg Response Time</p>
                  <p className="text-xl font-semibold text-gray-900">{data.automation.avgResponseTime}s</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Automated Actions</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">IP Blocking</span>
                  <span className="text-sm font-medium text-green-600">45</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Host Isolation</span>
                  <span className="text-sm font-medium text-green-600">12</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Account Disable</span>
                  <span className="text-sm font-medium text-green-600">8</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Email Quarantine</span>
                  <span className="text-sm font-medium text-green-600">23</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'compliance' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Overview</h3>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Reports</p>
                  <p className="text-xl font-semibold text-gray-900">{data.compliance.totalReports}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Compliance Score</p>
                  <p className="text-xl font-semibold text-green-600">{data.compliance.complianceScore}%</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Audit Logs</p>
                  <p className="text-xl font-semibold text-gray-900">{data.compliance.auditLogs.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Last Audit</p>
                  <p className="text-xl font-semibold text-gray-900">{data.compliance.lastAudit}</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Frameworks</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">GDPR</span>
                  <span className="text-sm font-medium text-green-600">Compliant</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">PCI DSS</span>
                  <span className="text-sm font-medium text-green-600">Compliant</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">HIPAA</span>
                  <span className="text-sm font-medium text-green-600">Compliant</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">SOX</span>
                  <span className="text-sm font-medium text-green-600">Compliant</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default SIEMSOAR; 