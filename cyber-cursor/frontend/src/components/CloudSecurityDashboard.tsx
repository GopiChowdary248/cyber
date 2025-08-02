import React, { useState, useEffect } from 'react';
import CloudSecuritySidebar from './CloudSecuritySidebar';
import CSPMDashboard from './CSPMDashboard';
import CASBDashboard from './CASBDashboard';
import CloudNativeDashboard from './CloudNativeDashboard';
import SecurityOverview from './SecurityOverview';
import SecurityFindings from './SecurityFindings';
import CloudApps from './CloudApps';

const CloudSecurityDashboard: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState('overview');
  const [selectedProvider, setSelectedProvider] = useState('');

  const handleCategorySelect = (category: string) => {
    setSelectedCategory(category);
  };

  const handleProviderSelect = (category: string, provider: string) => {
    setSelectedCategory(category);
    setSelectedProvider(provider);
  };

  const renderContent = () => {
    if (selectedCategory === 'overview') {
      return <SecurityOverview />;
    } else if (selectedCategory === 'findings') {
      return <SecurityFindings />;
    } else if (selectedCategory === 'cspm' && selectedProvider) {
      return <CSPMDashboard providerName={selectedProvider} />;
    } else if (selectedCategory === 'casb' && selectedProvider) {
      return <CASBDashboard providerName={selectedProvider} />;
    } else if (selectedCategory === 'cloud-native' && selectedProvider) {
      return <CloudNativeDashboard providerName={selectedProvider} />;
    } else if (selectedCategory === 'settings') {
      return <CloudSecuritySettings />;
    } else {
      return <CategoryOverview category={selectedCategory} />;
    }
  };

  return (
    <div className="flex h-screen bg-gray-900">
      <CloudSecuritySidebar
        onCategorySelect={handleCategorySelect}
        onProviderSelect={handleProviderSelect}
        selectedCategory={selectedCategory}
        selectedProvider={selectedProvider}
      />
      <div className="flex-1 overflow-auto">
        {renderContent()}
      </div>
    </div>
  );
};

// Placeholder components
const CloudSecuritySettings: React.FC = () => {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-white mb-6">Cloud Security Settings</h1>
      <div className="bg-gray-800 rounded-lg p-6">
        <p className="text-gray-300">Settings configuration will be implemented here.</p>
      </div>
    </div>
  );
};

const CategoryOverview: React.FC<{ category: string }> = ({ category }) => {
  const getCategoryTitle = () => {
    switch (category) {
      case 'cspm':
        return 'Cloud Security Posture Management (CSPM)';
      case 'casb':
        return 'Cloud Access Security Broker (CASB)';
      case 'cloud-native':
        return 'Cloud-Native Security';
      default:
        return category.charAt(0).toUpperCase() + category.slice(1);
    }
  };

  const getCategoryDescription = () => {
    switch (category) {
      case 'cspm':
        return 'Monitor and manage cloud security posture across multiple cloud providers. Select a provider from the sidebar to view detailed information.';
      case 'casb':
        return 'Monitor and control cloud application usage, enforce security policies, and detect threats in cloud applications. Select a provider from the sidebar to view detailed information.';
      case 'cloud-native':
        return 'Native security services provided by cloud providers for DDoS protection, threat detection, and security monitoring. Select a provider from the sidebar to view detailed information.';
      default:
        return 'Select a provider from the sidebar to view detailed information.';
    }
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-white mb-4">{getCategoryTitle()}</h1>
      <p className="text-gray-300 mb-6">{getCategoryDescription()}</p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Select Provider</h3>
          <p className="text-gray-400 text-sm">
            Choose a provider from the sidebar to view detailed metrics, configurations, and security status.
          </p>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Quick Actions</h3>
          <p className="text-gray-400 text-sm">
            Access common actions like scanning, syncing, and configuration management for selected providers.
          </p>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Security Overview</h3>
          <p className="text-gray-400 text-sm">
            View overall security metrics and compliance status across all providers in this category.
          </p>
        </div>
      </div>
    </div>
  );
};

export default CloudSecurityDashboard; 