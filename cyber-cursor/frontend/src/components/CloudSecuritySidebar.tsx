import React, { useState } from 'react';
import { 
  ChevronDownIcon, 
  ChevronRightIcon,
  CloudIcon,
  ShieldCheckIcon,
  EyeIcon,
  ServerIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  CogIcon
} from '@heroicons/react/24/outline';

interface CloudSecuritySidebarProps {
  onCategorySelect: (category: string) => void;
  onProviderSelect: (category: string, provider: string) => void;
  selectedCategory: string;
  selectedProvider: string;
}

const CloudSecuritySidebar: React.FC<CloudSecuritySidebarProps> = ({
  onCategorySelect,
  onProviderSelect,
  selectedCategory,
  selectedProvider
}) => {
  const [cspmOpen, setCspmOpen] = useState(false);
  const [casbOpen, setCasbOpen] = useState(false);
  const [cloudNativeOpen, setCloudNativeOpen] = useState(false);

  const cspmProviders = [
    { name: 'Prisma Cloud', icon: ShieldCheckIcon },
    { name: 'Dome9', icon: EyeIcon },
    { name: 'Wiz', icon: ChartBarIcon }
  ];

  const casbProviders = [
    { name: 'Netskope', icon: CloudIcon },
    { name: 'McAfee MVISION', icon: ShieldCheckIcon },
    { name: 'Microsoft Defender for Cloud Apps', icon: ServerIcon }
  ];

  const cloudNativeProviders = [
    { name: 'AWS Shield', icon: CloudIcon },
    { name: 'Azure Security Center', icon: ServerIcon },
    { name: 'GCP Security Command Center', icon: ChartBarIcon }
  ];

  const handleCategoryClick = (category: string) => {
    onCategorySelect(category);
    onProviderSelect(category, '');
  };

  const handleProviderClick = (category: string, provider: string) => {
    onCategorySelect(category);
    onProviderSelect(category, provider);
  };

  return (
    <div className="w-64 bg-gray-900 border-r border-gray-700 h-full overflow-y-auto">
      <div className="p-4">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <CloudIcon className="h-5 w-5 mr-2 text-blue-400" />
          Cloud Security
        </h2>
        
        {/* CSPM Section */}
        <div className="mb-4">
          <button
            onClick={() => setCspmOpen(!cspmOpen)}
            className={`w-full flex items-center justify-between p-2 rounded-lg transition-colors ${
              selectedCategory === 'cspm' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-700'
            }`}
          >
            <div className="flex items-center">
              <ShieldCheckIcon className="h-4 w-4 mr-2" />
              <span className="text-sm font-medium">CSPM</span>
            </div>
            {cspmOpen ? (
              <ChevronDownIcon className="h-4 w-4" />
            ) : (
              <ChevronRightIcon className="h-4 w-4" />
            )}
          </button>
          
          {cspmOpen && (
            <div className="ml-6 mt-2 space-y-1">
              {cspmProviders.map((provider) => {
                const Icon = provider.icon;
                return (
                  <button
                    key={provider.name}
                    onClick={() => handleProviderClick('cspm', provider.name)}
                    className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                      selectedCategory === 'cspm' && selectedProvider === provider.name
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-400 hover:text-white hover:bg-gray-700'
                    }`}
                  >
                    <Icon className="h-3 w-3 mr-2" />
                    {provider.name}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* CASB Section */}
        <div className="mb-4">
          <button
            onClick={() => setCasbOpen(!casbOpen)}
            className={`w-full flex items-center justify-between p-2 rounded-lg transition-colors ${
              selectedCategory === 'casb' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-700'
            }`}
          >
            <div className="flex items-center">
              <EyeIcon className="h-4 w-4 mr-2" />
              <span className="text-sm font-medium">CASB</span>
            </div>
            {casbOpen ? (
              <ChevronDownIcon className="h-4 w-4" />
            ) : (
              <ChevronRightIcon className="h-4 w-4" />
            )}
          </button>
          
          {casbOpen && (
            <div className="ml-6 mt-2 space-y-1">
              {casbProviders.map((provider) => {
                const Icon = provider.icon;
                return (
                  <button
                    key={provider.name}
                    onClick={() => handleProviderClick('casb', provider.name)}
                    className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                      selectedCategory === 'casb' && selectedProvider === provider.name
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-400 hover:text-white hover:bg-gray-700'
                    }`}
                  >
                    <Icon className="h-3 w-3 mr-2" />
                    {provider.name}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Cloud-Native Security Section */}
        <div className="mb-4">
          <button
            onClick={() => setCloudNativeOpen(!cloudNativeOpen)}
            className={`w-full flex items-center justify-between p-2 rounded-lg transition-colors ${
              selectedCategory === 'cloud-native' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-700'
            }`}
          >
            <div className="flex items-center">
              <ServerIcon className="h-4 w-4 mr-2" />
              <span className="text-sm font-medium">Cloud-Native Security</span>
            </div>
            {cloudNativeOpen ? (
              <ChevronDownIcon className="h-4 w-4" />
            ) : (
              <ChevronRightIcon className="h-4 w-4" />
            )}
          </button>
          
          {cloudNativeOpen && (
            <div className="ml-6 mt-2 space-y-1">
              {cloudNativeProviders.map((provider) => {
                const Icon = provider.icon;
                return (
                  <button
                    key={provider.name}
                    onClick={() => handleProviderClick('cloud-native', provider.name)}
                    className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                      selectedCategory === 'cloud-native' && selectedProvider === provider.name
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-400 hover:text-white hover:bg-gray-700'
                    }`}
                  >
                    <Icon className="h-3 w-3 mr-2" />
                    {provider.name}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div className="border-t border-gray-700 pt-4">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Quick Actions
          </h3>
          <div className="space-y-1">
            <button
              onClick={() => handleCategoryClick('overview')}
              className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                selectedCategory === 'overview'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              <ChartBarIcon className="h-3 w-3 mr-2" />
              Security Overview
            </button>
            <button
              onClick={() => handleCategoryClick('findings')}
              className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                selectedCategory === 'findings'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              <ExclamationTriangleIcon className="h-3 w-3 mr-2" />
              Security Findings
            </button>
            <button
              onClick={() => handleCategoryClick('settings')}
              className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                selectedCategory === 'settings'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              <CogIcon className="h-3 w-3 mr-2" />
              Settings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CloudSecuritySidebar; 