import React, { useState } from 'react';
import { 
  ShieldCheckIcon, 
  FireIcon, 
  EyeIcon, 
  LockClosedIcon, 
  UserGroupIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  ComputerDesktopIcon
} from '@heroicons/react/24/outline';

interface NetworkSecuritySidebarProps {
  onCategorySelect: (category: string) => void;
  onProviderSelect: (category: string, provider: string) => void;
  onQuickActionSelect: (action: string) => void;
}

const NetworkSecuritySidebar: React.FC<NetworkSecuritySidebarProps> = ({
  onCategorySelect,
  onProviderSelect,
  onQuickActionSelect
}) => {
  const [firewallOpen, setFirewallOpen] = useState(false);
  const [idsipsOpen, setIdsipsOpen] = useState(false);
  const [vpnOpen, setVpnOpen] = useState(false);
  const [nacOpen, setNacOpen] = useState(false);

  const handleCategoryClick = (category: string) => {
    onCategorySelect(category);
  };

  const handleProviderClick = (category: string, provider: string) => {
    onProviderSelect(category, provider);
  };

  const handleQuickActionClick = (action: string) => {
    onQuickActionSelect(action);
  };

  return (
    <div className="w-64 bg-gray-900 text-white h-full overflow-y-auto">
      <div className="p-4">
        <div className="flex items-center space-x-2 mb-6">
          <ShieldCheckIcon className="h-6 w-6 text-blue-400" />
          <h2 className="text-lg font-semibold">Network Security</h2>
        </div>

        {/* Firewalls Section */}
        <div className="mb-4">
          <button
            onClick={() => {
              setFirewallOpen(!firewallOpen);
              handleCategoryClick('firewalls');
            }}
            className="flex items-center justify-between w-full p-2 rounded hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center space-x-2">
              <FireIcon className="h-5 w-5 text-red-400" />
              <span>Firewalls</span>
            </div>
            <svg
              className={`h-4 w-4 transform transition-transform ${firewallOpen ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {firewallOpen && (
            <div className="ml-6 mt-2 space-y-1">
              <button
                onClick={() => handleProviderClick('firewalls', 'cisco-asa')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Cisco ASA
              </button>
              <button
                onClick={() => handleProviderClick('firewalls', 'palo-alto')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Palo Alto
              </button>
              <button
                onClick={() => handleProviderClick('firewalls', 'fortinet')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Fortinet
              </button>
            </div>
          )}
        </div>

        {/* IDS/IPS Section */}
        <div className="mb-4">
          <button
            onClick={() => {
              setIdsipsOpen(!idsipsOpen);
              handleCategoryClick('idsips');
            }}
            className="flex items-center justify-between w-full p-2 rounded hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center space-x-2">
              <EyeIcon className="h-5 w-5 text-yellow-400" />
              <span>IDS/IPS</span>
            </div>
            <svg
              className={`h-4 w-4 transform transition-transform ${idsipsOpen ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {idsipsOpen && (
            <div className="ml-6 mt-2 space-y-1">
              <button
                onClick={() => handleProviderClick('idsips', 'snort')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Snort
              </button>
              <button
                onClick={() => handleProviderClick('idsips', 'suricata')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Suricata
              </button>
              <button
                onClick={() => handleProviderClick('idsips', 'bro-zeek')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Bro/Zeek
              </button>
            </div>
          )}
        </div>

        {/* VPNs Section */}
        <div className="mb-4">
          <button
            onClick={() => {
              setVpnOpen(!vpnOpen);
              handleCategoryClick('vpns');
            }}
            className="flex items-center justify-between w-full p-2 rounded hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center space-x-2">
              <LockClosedIcon className="h-5 w-5 text-green-400" />
              <span>VPNs</span>
            </div>
            <svg
              className={`h-4 w-4 transform transition-transform ${vpnOpen ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {vpnOpen && (
            <div className="ml-6 mt-2 space-y-1">
              <button
                onClick={() => handleProviderClick('vpns', 'openvpn')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                OpenVPN
              </button>
              <button
                onClick={() => handleProviderClick('vpns', 'ipsec')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                IPsec
              </button>
              <button
                onClick={() => handleProviderClick('vpns', 'wireguard')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                WireGuard
              </button>
            </div>
          )}
        </div>

        {/* NAC Section */}
        <div className="mb-4">
          <button
            onClick={() => {
              setNacOpen(!nacOpen);
              handleCategoryClick('nac');
            }}
            className="flex items-center justify-between w-full p-2 rounded hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center space-x-2">
              <UserGroupIcon className="h-5 w-5 text-purple-400" />
              <span>NAC</span>
            </div>
            <svg
              className={`h-4 w-4 transform transition-transform ${nacOpen ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {nacOpen && (
            <div className="ml-6 mt-2 space-y-1">
              <button
                onClick={() => handleProviderClick('nac', 'cisco-ise')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Cisco ISE
              </button>
              <button
                onClick={() => handleProviderClick('nac', 'aruba-clearpass')}
                className="block w-full text-left p-2 rounded hover:bg-gray-800 transition-colors text-sm"
              >
                Aruba ClearPass
              </button>
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div className="mt-8 pt-6 border-t border-gray-700">
          <h3 className="text-sm font-medium text-gray-400 mb-3">Quick Actions</h3>
          <div className="space-y-2">
            <button
              onClick={() => handleQuickActionClick('overview')}
              className="flex items-center space-x-2 w-full p-2 rounded hover:bg-gray-800 transition-colors text-sm"
            >
              <ChartBarIcon className="h-4 w-4 text-blue-400" />
              <span>Security Overview</span>
            </button>
            <button
              onClick={() => handleQuickActionClick('alerts')}
              className="flex items-center space-x-2 w-full p-2 rounded hover:bg-gray-800 transition-colors text-sm"
            >
              <ExclamationTriangleIcon className="h-4 w-4 text-red-400" />
              <span>Security Alerts</span>
            </button>
            <button
              onClick={() => handleQuickActionClick('devices')}
              className="flex items-center space-x-2 w-full p-2 rounded hover:bg-gray-800 transition-colors text-sm"
            >
              <ComputerDesktopIcon className="h-4 w-4 text-green-400" />
              <span>Network Devices</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkSecuritySidebar; 