import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface Integration {
  id: string;
  name: string;
  type: string;
  provider: string;
  enabled: boolean;
  status: string;
  last_sync: string | null;
}

interface IntegrationStatus {
  total_integrations: number;
  enabled_integrations: number;
  active_integrations: number;
  type_statistics: Record<string, any>;
  recent_syncs: Array<{
    integration_id: string;
    last_sync: string;
  }>;
}

interface SupportedProvider {
  name: string;
  description: string;
  capabilities: string[];
}

interface SupportedProviders {
  siem: Record<string, SupportedProvider>;
  email: Record<string, SupportedProvider>;
  cloud: Record<string, SupportedProvider>;
}

const IntegrationManagement: React.FC = () => {
  const { user } = useAuth();
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [status, setStatus] = useState<IntegrationStatus | null>(null);
  const [supportedProviders, setSupportedProviders] = useState<SupportedProviders | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [testResult, setTestResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const [integrationsResponse, statusResponse, providersResponse] = await Promise.all([
        fetch(`${API_URL}/api/v1/integrations`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/integrations/status/overview`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
        fetch(`${API_URL}/api/v1/integrations/providers/supported`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        })
      ]);

      if (integrationsResponse.ok) {
        const integrationsData = await integrationsResponse.json();
        setIntegrations(integrationsData);
      }

      if (statusResponse.ok) {
        const statusData = await statusResponse.json();
        setStatus(statusData);
      }

      if (providersResponse.ok) {
        const providersData = await providersResponse.json();
        setSupportedProviders(providersData);
      }
    } catch (err) {
      console.error('Error fetching integration data:', err);
      setError('Failed to load integration data');
    } finally {
      setLoading(false);
    }
  };

  const testIntegration = async (integrationId: string) => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/integrations/${integrationId}/test`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const result = await response.json();
        setTestResult(result);
        setShowTestModal(true);
      } else {
        throw new Error('Failed to test integration');
      }
    } catch (err) {
      console.error('Error testing integration:', err);
      setError('Failed to test integration');
    } finally {
      setLoading(false);
    }
  };

  const syncIntegration = async (integrationId: string) => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/integrations/${integrationId}/sync`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        setSuccess('Integration sync started successfully');
        setTimeout(() => fetchData(), 2000); // Refresh data after sync
      } else {
        throw new Error('Failed to start integration sync');
      }
    } catch (err) {
      console.error('Error syncing integration:', err);
      setError('Failed to sync integration');
    } finally {
      setLoading(false);
    }
  };

  const toggleIntegration = async (integrationId: string, enabled: boolean) => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const endpoint = enabled ? 'enable' : 'disable';
      const response = await fetch(`${API_URL}/api/v1/integrations/${integrationId}/${endpoint}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        setSuccess(`Integration ${enabled ? 'enabled' : 'disabled'} successfully`);
        fetchData();
      } else {
        throw new Error(`Failed to ${enabled ? 'enable' : 'disable'} integration`);
      }
    } catch (err) {
      console.error('Error toggling integration:', err);
      setError(`Failed to ${enabled ? 'enable' : 'disable'} integration`);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active': return 'text-green-400 bg-green-900/20';
      case 'inactive': return 'text-red-400 bg-red-900/20';
      case 'error': return 'text-yellow-400 bg-yellow-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'siem': return '🛡️';
      case 'email': return '📧';
      case 'cloud': return '☁️';
      case 'slack': return '💬';
      case 'teams': return '👥';
      default: return '🔗';
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading && !integrations.length) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-400"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-red-900/20 to-orange-900/20 border border-red-700/30 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">🔗 Integration Management</h1>
            <p className="text-gray-400">Configure and monitor third-party integrations</p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-red-600 hover:bg-red-700 text-white px-6 py-2 rounded-lg transition-colors"
          >
            ➕ Add Integration
          </button>
        </div>
      </div>

      {/* Success/Error Messages */}
      {success && (
        <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
          <p className="text-green-400">{success}</p>
        </div>
      )}

      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-4">
        <div className="flex space-x-4">
          {[
            { id: 'overview', name: 'Overview', icon: '📊' },
            { id: 'integrations', name: 'Integrations', icon: '🔗' },
            { id: 'providers', name: 'Providers', icon: '📋' },
            { id: 'logs', name: 'Logs', icon: '📝' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-red-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-red-700/20'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && status && (
        <div className="space-y-6">
          {/* Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🔗</div>
                <div className="text-blue-400 text-sm">Total</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{status.total_integrations}</div>
              <div className="text-gray-400">Integrations</div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">✅</div>
                <div className="text-green-400 text-sm">Active</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{status.enabled_integrations}</div>
              <div className="text-gray-400">Enabled</div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">🟢</div>
                <div className="text-green-400 text-sm">Online</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{status.active_integrations}</div>
              <div className="text-gray-400">Active</div>
            </div>

            <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="text-2xl">📈</div>
                <div className="text-purple-400 text-sm">Health</div>
              </div>
              <div className="text-3xl font-bold text-white mb-2">
                {status.total_integrations > 0 ? Math.round((status.active_integrations / status.total_integrations) * 100) : 0}%
              </div>
              <div className="text-gray-400">Uptime</div>
            </div>
          </div>

          {/* Type Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {Object.entries(status.type_statistics).map(([type, stats]) => (
              <div key={type} className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  {getTypeIcon(type)} {type.toUpperCase()}
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total</span>
                    <span className="text-white">{stats.total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Enabled</span>
                    <span className="text-green-400">{stats.enabled}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Active</span>
                    <span className="text-blue-400">{stats.active}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Recent Syncs */}
          <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">🕒 Recent Syncs</h3>
            <div className="space-y-3">
              {status.recent_syncs.length > 0 ? (
                status.recent_syncs.map((sync, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                      <span className="text-white">{sync.integration_id}</span>
                    </div>
                    <span className="text-gray-400 text-sm">{formatDate(sync.last_sync)}</span>
                  </div>
                ))
              ) : (
                <p className="text-gray-400 text-center py-4">No recent syncs</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Integrations Tab */}
      {activeTab === 'integrations' && (
        <div className="space-y-6">
          <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6">🔗 Active Integrations</h2>
            
            {integrations.length > 0 ? (
              <div className="space-y-4">
                {integrations.map((integration) => (
                  <div key={integration.id} className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <div className="text-2xl">{getTypeIcon(integration.type)}</div>
                        <div>
                          <h3 className="text-white font-semibold">{integration.name}</h3>
                          <p className="text-gray-400 text-sm">
                            {integration.type.toUpperCase()} • {integration.provider}
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-4">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(integration.status)}`}>
                          {integration.status}
                        </span>
                        
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => testIntegration(integration.id)}
                            className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition-colors"
                            title="Test Connection"
                          >
                            🧪 Test
                          </button>
                          
                          <button
                            onClick={() => syncIntegration(integration.id)}
                            className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-sm transition-colors"
                            title="Sync Now"
                          >
                            🔄 Sync
                          </button>
                          
                          <button
                            onClick={() => toggleIntegration(integration.id, !integration.enabled)}
                            className={`px-3 py-1 rounded text-sm transition-colors ${
                              integration.enabled
                                ? 'bg-red-600 hover:bg-red-700 text-white'
                                : 'bg-green-600 hover:bg-green-700 text-white'
                            }`}
                            title={integration.enabled ? 'Disable' : 'Enable'}
                          >
                            {integration.enabled ? '🚫' : '✅'}
                          </button>
                        </div>
                      </div>
                    </div>
                    
                    <div className="mt-3 pt-3 border-t border-red-700/20">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-400">
                          Last sync: {formatDate(integration.last_sync)}
                        </span>
                        <span className={`text-xs ${integration.enabled ? 'text-green-400' : 'text-red-400'}`}>
                          {integration.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <div className="text-4xl mb-4">🔗</div>
                <p className="text-gray-400 mb-4">No integrations configured</p>
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="bg-red-600 hover:bg-red-700 text-white px-6 py-2 rounded-lg transition-colors"
                >
                  Add Your First Integration
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Providers Tab */}
      {activeTab === 'providers' && supportedProviders && (
        <div className="space-y-6">
          {Object.entries(supportedProviders).map(([category, providers]) => (
            <div key={category} className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-6 flex items-center">
                {getTypeIcon(category)} {category.toUpperCase()} Providers
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(providers as Record<string, SupportedProvider>).map(([provider, details]) => (
                  <div key={provider} className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                    <h3 className="text-white font-semibold mb-2">{details.name}</h3>
                    <p className="text-gray-400 text-sm mb-3">{details.description}</p>
                    
                    <div className="space-y-2">
                      <h4 className="text-gray-300 text-xs font-semibold">Capabilities:</h4>
                      <div className="flex flex-wrap gap-1">
                        {details.capabilities.map((capability, index) => (
                          <span key={index} className="bg-blue-900/20 text-blue-400 text-xs px-2 py-1 rounded">
                            {capability}
                          </span>
                        ))}
                      </div>
                    </div>
                    
                    <button
                      onClick={() => {
                        setSelectedIntegration({
                          id: '',
                          name: details.name,
                          type: category,
                          provider: provider,
                          enabled: false,
                          status: 'inactive',
                          last_sync: null
                        });
                        setShowCreateModal(true);
                      }}
                      className="w-full mt-4 bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg transition-colors text-sm"
                    >
                      Configure {details.name}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6">
          <h2 className="text-xl font-bold text-white mb-6">📝 Integration Logs</h2>
          <div className="text-center py-8">
            <div className="text-4xl mb-4">📝</div>
            <p className="text-gray-400">Integration logs and monitoring coming soon...</p>
          </div>
        </div>
      )}

      {/* Test Result Modal */}
      {showTestModal && testResult && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6 max-w-md w-full mx-4">
            <div className="text-center mb-6">
              <div className={`text-4xl mb-4 ${testResult.success ? 'text-green-400' : 'text-red-400'}`}>
                {testResult.success ? '✅' : '❌'}
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Connection Test Result</h3>
              <p className="text-gray-400">{testResult.message}</p>
            </div>
            
            {testResult.details && (
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4 mb-4">
                <h4 className="text-white font-semibold mb-2">Details:</h4>
                <pre className="text-gray-300 text-sm overflow-auto">
                  {JSON.stringify(testResult.details, null, 2)}
                </pre>
              </div>
            )}
            
            <button
              onClick={() => setShowTestModal(false)}
              className="w-full bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Create Integration Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-red-700/30 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">
                {selectedIntegration ? 'Configure Integration' : 'Add New Integration'}
              </h3>
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setSelectedIntegration(null);
                }}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            
            <div className="text-center py-8">
              <div className="text-4xl mb-4">🔧</div>
              <p className="text-gray-400">Integration configuration interface coming soon...</p>
              <p className="text-gray-500 text-sm mt-2">
                This will include forms for configuring each provider's specific settings.
              </p>
            </div>
            
            <div className="flex space-x-3">
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setSelectedIntegration(null);
                }}
                className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setSelectedIntegration(null);
                  setSuccess('Integration configuration interface will be available soon');
                }}
                className="flex-1 bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg transition-colors"
              >
                Configure Later
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IntegrationManagement; 