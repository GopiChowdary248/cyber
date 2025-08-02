import React, { useState } from 'react';
import NetworkSecuritySidebar from './NetworkSecuritySidebar';
import FirewallDashboard from './FirewallDashboard';
import IDSIPSDashboard from './IDSIPSDashboard';
import VPNDashboard from './VPNDashboard';
import NACDashboard from './NACDashboard';
import NetworkSecurityOverview from './NetworkSecurityOverview';
import SecurityAlerts from './SecurityAlerts';
import NetworkDevices from './NetworkDevices';

const NetworkSecurityDashboard: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('overview');
  const [selectedProvider, setSelectedProvider] = useState<string>('');

  const handleCategorySelect = (category: string) => {
    setSelectedCategory(category);
    setSelectedProvider('');
  };

  const handleProviderSelect = (category: string, provider: string) => {
    setSelectedCategory(category);
    setSelectedProvider(provider);
  };

  const handleQuickActionSelect = (action: string) => {
    setSelectedCategory(action);
    setSelectedProvider('');
  };

  const renderContent = () => {
    switch (selectedCategory) {
      case 'firewalls':
        if (selectedProvider) {
          return <FirewallDashboard provider={selectedProvider} />;
        }
        return <div className="p-6">Select a firewall provider from the sidebar</div>;
      
      case 'idsips':
        if (selectedProvider) {
          return <IDSIPSDashboard provider={selectedProvider} />;
        }
        return <div className="p-6">Select an IDS/IPS provider from the sidebar</div>;
      
      case 'vpns':
        if (selectedProvider) {
          return <VPNDashboard provider={selectedProvider} />;
        }
        return <div className="p-6">Select a VPN provider from the sidebar</div>;
      
      case 'nac':
        if (selectedProvider) {
          return <NACDashboard provider={selectedProvider} />;
        }
        return <div className="p-6">Select a NAC provider from the sidebar</div>;
      
      case 'overview':
        return <NetworkSecurityOverview />;
      
      case 'alerts':
        return <SecurityAlerts />;
      
      case 'devices':
        return <NetworkDevices />;
      
      default:
        return <NetworkSecurityOverview />;
    }
  };

  return (
    <div className="flex h-screen bg-gray-100">
      <NetworkSecuritySidebar
        onCategorySelect={handleCategorySelect}
        onProviderSelect={handleProviderSelect}
        onQuickActionSelect={handleQuickActionSelect}
      />
      <div className="flex-1 overflow-auto">
        <div className="bg-white shadow-sm border-b border-gray-200">
          <div className="px-6 py-4">
            <h1 className="text-2xl font-bold text-gray-900">
              Network Security Dashboard
            </h1>
            <p className="text-gray-600 mt-1">
              Monitor and manage your network security infrastructure
            </p>
          </div>
        </div>
        <div className="flex-1">
          {renderContent()}
        </div>
      </div>
    </div>
  );
};

export default NetworkSecurityDashboard; 