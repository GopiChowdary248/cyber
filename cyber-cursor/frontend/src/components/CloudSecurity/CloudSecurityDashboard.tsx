import React, { useState, useEffect } from 'react';
import CloudSecuritySidebar from './CloudSecuritySidebar';
import CSPMDashboard from './CSPMDashboard';
import CASBDashboard from './CASBDashboard';
import CloudNativeDashboard from './CloudNativeDashboard';
import SecurityOverview from './SecurityOverview';
import SecurityFindings from './SecurityFindings';
import CloudApps from './CloudApps';

interface CloudSecurityDashboardProps {}

const CloudSecurityDashboard: React.FC<CloudSecurityDashboardProps> = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('overview');
  const [selectedProvider, setSelectedProvider] = useState<string>('dashboard');
  const [loading, setLoading] = useState(false);

  const handleProviderSelect = (category: string, provider: string) => {
    setSelectedCategory(category);
    setSelectedProvider(provider);
  };

  const renderContent = () => {
    if (loading) {
      return (
        <div className="flex items-center justify-center h-full">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
        </div>
      );
    }

    switch (selectedCategory) {
      case 'cspm':
        return <CSPMDashboard provider={selectedProvider} />;
      case 'casb':
        return <CASBDashboard provider={selectedProvider} />;
      case 'cloud_native':
        return <CloudNativeDashboard provider={selectedProvider} />;
      case 'overview':
        switch (selectedProvider) {
          case 'dashboard':
            return <SecurityOverview />;
          case 'findings':
            return <SecurityFindings />;
          case 'apps':
            return <CloudApps />;
          default:
            return <SecurityOverview />;
        }
      default:
        return <SecurityOverview />;
    }
  };

  const getPageTitle = () => {
    switch (selectedCategory) {
      case 'cspm':
        return `CSPM - ${selectedProvider.replace('_', ' ').toUpperCase()}`;
      case 'casb':
        return `CASB - ${selectedProvider.replace('_', ' ').toUpperCase()}`;
      case 'cloud_native':
        return `Cloud-Native Security - ${selectedProvider.replace('_', ' ').toUpperCase()}`;
      case 'overview':
        switch (selectedProvider) {
          case 'dashboard':
            return 'Cloud Security Overview';
          case 'findings':
            return 'Security Findings';
          case 'apps':
            return 'Cloud Applications';
          default:
            return 'Cloud Security Overview';
        }
      default:
        return 'Cloud Security';
    }
  };

  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar */}
      <CloudSecuritySidebar
        onProviderSelect={handleProviderSelect}
        selectedCategory={selectedCategory}
        selectedProvider={selectedProvider}
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-white shadow-sm border-b border-gray-200">
          <div className="px-6 py-4">
            <h1 className="text-2xl font-bold text-gray-900">{getPageTitle()}</h1>
            <p className="text-sm text-gray-600 mt-1">
              Monitor and manage your cloud security posture across all providers
            </p>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-auto p-6">
          {renderContent()}
        </main>
      </div>
    </div>
  );
};

export default CloudSecurityDashboard; 