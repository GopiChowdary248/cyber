import React, { useState } from 'react';
import {
  Activity,
  BarChart3,
  CheckCircle,
  Clock,
  Code,
  Cloud,
  Database,
  Eye,
  EyeOff,
  Network,
  Shield,
  Target,
  Zap,
  Settings,
  RefreshCw,
  AlertTriangle,
  Info,
  TrendingUp,
  AlertCircle,
  Lock,
  Monitor,
  Server
} from 'lucide-react';
import IntegrationStatusDashboard from '../../components/Integration/IntegrationStatusDashboard';
import IntegrationTestRunner from '../../components/Integration/IntegrationTestRunner';
import ComprehensiveIntegrationDashboard from '../../components/Integration/ComprehensiveIntegrationDashboard';

const Integration: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'comprehensive' | 'dashboard' | 'test-runner'>('comprehensive');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(30000);

  const tabs = [
    {
      id: 'comprehensive',
      name: 'Comprehensive Dashboard',
      icon: <BarChart3 className="w-5 h-5" />,
      description: 'Complete overview of all frontend-backend integrations'
    },
    {
      id: 'dashboard',
      name: 'Integration Dashboard',
      icon: <Activity className="w-5 h-5" />,
      description: 'Monitor overall integration health and status'
    },
    {
      id: 'test-runner',
      name: 'Test Runner',
      icon: <Zap className="w-5 h-5" />,
      description: 'Run individual endpoint tests and verify functionality'
    }
  ];

  const integrationStats = [
    {
      name: 'Total Services',
      value: '15',
      icon: <Server className="w-6 h-6 text-blue-600" />,
      color: 'bg-blue-50 text-blue-700'
    },
    {
      name: 'Active Integrations',
      value: '142',
      icon: <CheckCircle className="w-6 h-6 text-green-600" />,
      color: 'bg-green-50 text-green-700'
    },
    {
      name: 'Response Time',
      value: '45ms',
      icon: <Clock className="w-6 h-6 text-yellow-600" />,
      color: 'bg-yellow-50 text-yellow-700'
    },
    {
      name: 'Success Rate',
      value: '98.5%',
      icon: <TrendingUp className="w-6 h-6 text-purple-600" />,
      color: 'bg-purple-50 text-purple-700'
    }
  ];

  const serviceCategories = [
    {
      name: 'Security Testing',
      services: ['SAST', 'DAST', 'RASP'],
      icon: <Shield className="w-5 h-5" />,
      color: 'bg-red-50 border-red-200'
    },
    {
      name: 'Cloud & Network',
      services: ['Cloud Security', 'Network Security', 'Endpoint Security'],
      icon: <Cloud className="w-5 h-5" />,
      color: 'bg-blue-50 border-blue-200'
    },
    {
      name: 'Data & Analytics',
      services: ['Data Security', 'SIEM/SOAR', 'Analytics'],
      icon: <Database className="w-5 h-5" />,
      color: 'bg-green-50 border-green-200'
    },
    {
      name: 'Intelligence & Auth',
      services: ['Threat Intelligence', 'Authentication', 'Admin'],
      icon: <AlertCircle className="w-5 h-5" />,
      color: 'bg-purple-50 border-purple-200'
    }
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Integration Management</h1>
                <p className="mt-2 text-gray-600">
                  Monitor, test, and manage all backend service integrations
                </p>
              </div>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="auto-refresh"
                    checked={autoRefresh}
                    onChange={(e) => setAutoRefresh(e.target.checked)}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <label htmlFor="auto-refresh" className="text-sm text-gray-600">
                    Auto-refresh
                  </label>
                </div>
                <button
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700 transition-colors flex items-center"
                >
                  <Settings className="w-4 h-4 mr-2" />
                  {showAdvanced ? 'Hide' : 'Show'} Advanced
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Advanced Settings */}
      {showAdvanced && (
        <div className="bg-white border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Refresh Interval (seconds)
                </label>
                <select
                  value={refreshInterval / 1000}
                  onChange={(e) => setRefreshInterval(Number(e.target.value) * 1000)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value={15}>15 seconds</option>
                  <option value={30}>30 seconds</option>
                  <option value={60}>1 minute</option>
                  <option value={300}>5 minutes</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Test Timeout
                </label>
                <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value={5000}>5 seconds</option>
                  <option value={10000}>10 seconds</option>
                  <option value={30000}>30 seconds</option>
                  <option value={60000}>1 minute</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Concurrent Tests
                </label>
                <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value={3}>3 tests</option>
                  <option value={5}>5 tests</option>
                  <option value={10}>10 tests</option>
                  <option value={20}>20 tests</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Quick Stats */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {integrationStats.map((stat) => (
            <div key={stat.name} className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center">
                <div className={`p-3 rounded-lg ${stat.color}`}>
                  {stat.icon}
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">{stat.name}</p>
                  <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Service Categories Overview */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-6">Service Categories</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {serviceCategories.map((category) => (
            <div key={category.name} className={`bg-white rounded-lg shadow-sm border ${category.color} p-6`}>
              <div className="flex items-center mb-4">
                <div className="p-2 bg-white rounded-lg mr-3">
                  {category.icon}
                </div>
                <h3 className="font-semibold text-gray-900">{category.name}</h3>
              </div>
              <div className="space-y-2">
                {category.services.map((service) => (
                  <div key={service} className="flex items-center text-sm text-gray-700">
                    <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                    {service}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as 'comprehensive' | 'dashboard' | 'test-runner')}
                className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab.icon}
                <span>{tab.name}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Tab Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'comprehensive' && (
          <ComprehensiveIntegrationDashboard />
        )}
        {activeTab === 'dashboard' && (
          <IntegrationStatusDashboard
            autoRefresh={autoRefresh}
            refreshInterval={refreshInterval}
          />
        )}
        {activeTab === 'test-runner' && (
          <IntegrationTestRunner
            autoRun={false}
            showAdvanced={showAdvanced}
          />
        )}
      </div>

      {/* Integration Tips */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
          <div className="flex items-start">
            <Info className="w-6 h-6 text-blue-600 mr-3 mt-0.5" />
            <div>
              <h3 className="text-lg font-semibold text-blue-800">Integration Best Practices</h3>
              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-700">
                <div>
                  <p className="font-medium mb-2">• Monitor endpoint response times regularly</p>
                  <p className="font-medium mb-2">• Set up alerts for failed integrations</p>
                  <p className="font-medium mb-2">• Test critical endpoints before deployments</p>
                </div>
                <div>
                  <p className="font-medium mb-2">• Use retry mechanisms for transient failures</p>
                  <p className="font-medium mb-2">• Implement circuit breakers for failing services</p>
                  <p className="font-medium mb-2">• Keep integration documentation updated</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Integration;
