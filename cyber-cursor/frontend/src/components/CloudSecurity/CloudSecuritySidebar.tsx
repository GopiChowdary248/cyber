import React, { useState } from 'react';
import { 
  ChevronDownIcon, 
  ChevronRightIcon,
  CloudIcon,
  ShieldCheckIcon,
  LockClosedIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';

interface CloudSecuritySidebarProps {
  onProviderSelect: (category: string, provider: string) => void;
  selectedCategory?: string;
  selectedProvider?: string;
}

const CloudSecuritySidebar: React.FC<CloudSecuritySidebarProps> = ({
  onProviderSelect,
  selectedCategory,
  selectedProvider
}) => {
  const [cspmOpen, setCspmOpen] = useState(false);
  const [casbOpen, setCasbOpen] = useState(false);
  const [cloudNativeOpen, setCloudNativeOpen] = useState(false);

  const cspmProviders = [
    { id: 'prisma_cloud', name: 'Prisma Cloud', status: 'active' },
    { id: 'dome9', name: 'Dome9', status: 'active' },
    { id: 'wiz', name: 'Wiz', status: 'active' }
  ];

  const casbProviders = [
    { id: 'netskope', name: 'Netskope', status: 'active' },
    { id: 'mcafee_mvision', name: 'McAfee MVISION', status: 'active' },
    { id: 'microsoft_defender', name: 'Microsoft Defender for Cloud Apps', status: 'active' }
  ];

  const cloudNativeProviders = [
    { id: 'aws_shield', name: 'AWS Shield', status: 'active' },
    { id: 'azure_security_center', name: 'Azure Security Center', status: 'active' },
    { id: 'gcp_security_command_center', name: 'GCP Security Command Center', status: 'active' }
  ];

  const handleProviderClick = (category: string, provider: string) => {
    onProviderSelect(category, provider);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircleIcon className="w-4 h-4 text-green-500" />;
      case 'inactive':
        return <XCircleIcon className="w-4 h-4 text-red-500" />;
      case 'warning':
        return <ExclamationTriangleIcon className="w-4 h-4 text-yellow-500" />;
      default:
        return <CheckCircleIcon className="w-4 h-4 text-gray-500" />;
    }
  };

  return (
    <div className="w-64 bg-gray-900 text-white h-full overflow-y-auto">
      <div className="p-4 border-b border-gray-700">
        <h2 className="text-lg font-semibold flex items-center">
          <CloudIcon className="w-5 h-5 mr-2" />
          Cloud Security
        </h2>
      </div>

      <nav className="p-2">
        {/* CSPM Section */}
        <div className="mb-4">
          <button
            onClick={() => setCspmOpen(!cspmOpen)}
            className="w-full flex items-center justify-between p-2 rounded hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center">
              <ShieldCheckIcon className="w-4 h-4 mr-2" />
              <span className="text-sm font-medium">CSPM</span>
              <span className="ml-2 text-xs text-gray-400">(Cloud Security Posture Management)</span>
            </div>
            {cspmOpen ? (
              <ChevronDownIcon className="w-4 h-4" />
            ) : (
              <ChevronRightIcon className="w-4 h-4" />
            )}
          </button>
          
          {cspmOpen && (
            <div className="ml-6 mt-2 space-y-1">
              {cspmProviders.map((provider) => (
                <button
                  key={provider.id}
                  onClick={() => handleProviderClick('cspm', provider.id)}
                  className={`w-full flex items-center justify-between p-2 rounded text-sm transition-colors ${
                    selectedCategory === 'cspm' && selectedProvider === provider.id
                      ? 'bg-blue-600 text-white'
                      : 'hover:bg-gray-800 text-gray-300'
                  }`}
                >
                  <span>{provider.name}</span>
                  {getStatusIcon(provider.status)}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* CASB Section */}
        <div className="mb-4">
          <button
            onClick={() => setCasbOpen(!casbOpen)}
            className="w-full flex items-center justify-between p-2 rounded hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center">
              <LockClosedIcon className="w-4 h-4 mr-2" />
              <span className="text-sm font-medium">CASB</span>
              <span className="ml-2 text-xs text-gray-400">(Cloud Access Security Broker)</span>
            </div>
            {casbOpen ? (
              <ChevronDownIcon className="w-4 h-4" />
            ) : (
              <ChevronRightIcon className="w-4 h-4" />
            )}
          </button>
          
          {casbOpen && (
            <div className="ml-6 mt-2 space-y-1">
              {casbProviders.map((provider) => (
                <button
                  key={provider.id}
                  onClick={() => handleProviderClick('casb', provider.id)}
                  className={`w-full flex items-center justify-between p-2 rounded text-sm transition-colors ${
                    selectedCategory === 'casb' && selectedProvider === provider.id
                      ? 'bg-blue-600 text-white'
                      : 'hover:bg-gray-800 text-gray-300'
                  }`}
                >
                  <span>{provider.name}</span>
                  {getStatusIcon(provider.status)}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Cloud-Native Security Section */}
        <div className="mb-4">
          <button
            onClick={() => setCloudNativeOpen(!cloudNativeOpen)}
            className="w-full flex items-center justify-between p-2 rounded hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center">
              <CloudIcon className="w-4 h-4 mr-2" />
              <span className="text-sm font-medium">Cloud-Native Security</span>
            </div>
            {cloudNativeOpen ? (
              <ChevronDownIcon className="w-4 h-4" />
            ) : (
              <ChevronRightIcon className="w-4 h-4" />
            )}
          </button>
          
          {cloudNativeOpen && (
            <div className="ml-6 mt-2 space-y-1">
              {cloudNativeProviders.map((provider) => (
                <button
                  key={provider.id}
                  onClick={() => handleProviderClick('cloud_native', provider.id)}
                  className={`w-full flex items-center justify-between p-2 rounded text-sm transition-colors ${
                    selectedCategory === 'cloud_native' && selectedProvider === provider.id
                      ? 'bg-blue-600 text-white'
                      : 'hover:bg-gray-800 text-gray-300'
                  }`}
                >
                  <span>{provider.name}</span>
                  {getStatusIcon(provider.status)}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div className="mt-6 pt-4 border-t border-gray-700">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 px-2">
            Quick Actions
          </h3>
          <div className="space-y-1">
            <button
              onClick={() => handleProviderClick('overview', 'dashboard')}
              className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                selectedCategory === 'overview' && selectedProvider === 'dashboard'
                  ? 'bg-blue-600 text-white'
                  : 'hover:bg-gray-800 text-gray-300'
              }`}
            >
              <ShieldCheckIcon className="w-4 h-4 mr-2" />
              Security Dashboard
            </button>
            <button
              onClick={() => handleProviderClick('overview', 'findings')}
              className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                selectedCategory === 'overview' && selectedProvider === 'findings'
                  ? 'bg-blue-600 text-white'
                  : 'hover:bg-gray-800 text-gray-300'
              }`}
            >
              <ExclamationTriangleIcon className="w-4 h-4 mr-2" />
              Security Findings
            </button>
            <button
              onClick={() => handleProviderClick('overview', 'apps')}
              className={`w-full flex items-center p-2 rounded text-sm transition-colors ${
                selectedCategory === 'overview' && selectedProvider === 'apps'
                  ? 'bg-blue-600 text-white'
                  : 'hover:bg-gray-800 text-gray-300'
              }`}
            >
              <CloudIcon className="w-4 h-4 mr-2" />
              Cloud Applications
            </button>
          </div>
        </div>
      </nav>
    </div>
  );
};

export default CloudSecuritySidebar; 