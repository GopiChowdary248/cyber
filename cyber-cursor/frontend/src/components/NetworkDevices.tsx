import React, { useState, useEffect } from 'react';
import { 
  ComputerDesktopIcon, 
  FunnelIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  EyeIcon
} from '@heroicons/react/24/outline';

interface NetworkDevice {
  id: string;
  name: string;
  type: string;
  ip_address: string;
  status: string;
  last_seen: string;
  compliance_status: string;
}

const NetworkDevices: React.FC = () => {
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    type: '',
    status: '',
    compliance_status: ''
  });

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/network-security/devices');
      if (response.ok) {
        const data = await response.json();
        setDevices(data);
      } else {
        console.error('Failed to fetch network devices');
      }
    } catch (error) {
      console.error('Error fetching network devices:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (filterType: string, value: string) => {
    setFilters(prev => ({
      ...prev,
      [filterType]: value
    }));
  };

  const handleQuarantine = async (deviceId: string) => {
    try {
      const response = await fetch(`/api/v1/network-security/devices/${deviceId}/quarantine`, {
        method: 'POST',
      });
      if (response.ok) {
        // Refresh devices after quarantine
        fetchDevices();
      } else {
        console.error('Failed to quarantine device');
      }
    } catch (error) {
      console.error('Error quarantining device:', error);
    }
  };

  const handleRelease = async (deviceId: string) => {
    try {
      const response = await fetch(`/api/v1/network-security/devices/${deviceId}/release`, {
        method: 'POST',
      });
      if (response.ok) {
        // Refresh devices after release
        fetchDevices();
      } else {
        console.error('Failed to release device');
      }
    } catch (error) {
      console.error('Error releasing device:', error);
    }
  };

  const getFilteredDevices = () => {
    return devices.filter(device => {
      if (filters.type && device.type !== filters.type) return false;
      if (filters.status && device.status !== filters.status) return false;
      if (filters.compliance_status && device.compliance_status !== filters.compliance_status) return false;
      return true;
    });
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'compliant':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'quarantined':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'investigating':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'compliant':
        return <CheckCircleIcon className="h-4 w-4 text-green-500" />;
      case 'quarantined':
        return <XCircleIcon className="h-4 w-4 text-red-500" />;
      case 'investigating':
        return <ClockIcon className="h-4 w-4 text-yellow-500" />;
      default:
        return <EyeIcon className="h-4 w-4 text-gray-500" />;
    }
  };

  const getComplianceColor = (compliance: string) => {
    switch (compliance.toLowerCase()) {
      case 'compliant':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'non-compliant':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'pending':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getComplianceIcon = (compliance: string) => {
    switch (compliance.toLowerCase()) {
      case 'compliant':
        return <ShieldCheckIcon className="h-4 w-4 text-green-500" />;
      case 'non-compliant':
        return <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />;
      case 'pending':
        return <ClockIcon className="h-4 w-4 text-yellow-500" />;
      default:
        return <EyeIcon className="h-4 w-4 text-gray-500" />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes} minutes ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)} hours ago`;
    return `${Math.floor(diffInMinutes / 1440)} days ago`;
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const filteredDevices = getFilteredDevices();

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Network Devices</h2>
          <p className="text-gray-600">Monitor and manage network devices and their compliance status</p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-600">
            {filteredDevices.length} of {devices.length} devices
          </span>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200 mb-6">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <FunnelIcon className="h-4 w-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700">Filters:</span>
          </div>
          
          {/* Type Filter */}
          <select
            value={filters.type}
            onChange={(e) => handleFilterChange('type', e.target.value)}
            className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Types</option>
            <option value="endpoint">Endpoint</option>
            <option value="server">Server</option>
            <option value="mobile">Mobile</option>
            <option value="network">Network</option>
          </select>

          {/* Status Filter */}
          <select
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
            className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Statuses</option>
            <option value="compliant">Compliant</option>
            <option value="quarantined">Quarantined</option>
            <option value="investigating">Investigating</option>
          </select>

          {/* Compliance Status Filter */}
          <select
            value={filters.compliance_status}
            onChange={(e) => handleFilterChange('compliance_status', e.target.value)}
            className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Compliance</option>
            <option value="compliant">Compliant</option>
            <option value="non-compliant">Non-Compliant</option>
            <option value="pending">Pending</option>
          </select>

          {/* Clear Filters */}
          <button
            onClick={() => setFilters({ type: '', status: '', compliance_status: '' })}
            className="px-3 py-1 text-sm text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-md transition-colors"
          >
            Clear All
          </button>
        </div>
      </div>

      {/* Devices List */}
      <div className="space-y-4">
        {filteredDevices.length === 0 ? (
          <div className="text-center py-12">
            <ComputerDesktopIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No Devices Found</h3>
            <p className="text-gray-600">No network devices match the current filters.</p>
          </div>
        ) : (
          filteredDevices.map((device) => (
            <div
              key={device.id}
              className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="flex-shrink-0">
                    <ComputerDesktopIcon className="h-8 w-8 text-blue-500" />
                  </div>
                  
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-semibold text-gray-900">{device.name}</h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(device.status)}`}>
                        {device.status.charAt(0).toUpperCase() + device.status.slice(1)}
                      </span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getComplianceColor(device.compliance_status)}`}>
                        {device.compliance_status.charAt(0).toUpperCase() + device.compliance_status.slice(1)}
                      </span>
                    </div>
                    
                    <div className="flex items-center space-x-6 text-sm text-gray-500">
                      <div className="flex items-center space-x-1">
                        <span className="font-medium">Type:</span>
                        <span className="capitalize">{device.type}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <span className="font-medium">IP:</span>
                        <span>{device.ip_address}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <ClockIcon className="h-4 w-4" />
                        <span>Last seen {formatTimestamp(device.last_seen)}</span>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md transition-colors">
                    <EyeIcon className="h-4 w-4" />
                  </button>
                  
                  {device.status === 'compliant' && (
                    <button
                      onClick={() => handleQuarantine(device.id)}
                      className="p-2 text-red-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                      title="Quarantine Device"
                    >
                      <XCircleIcon className="h-4 w-4" />
                    </button>
                  )}
                  
                  {device.status === 'quarantined' && (
                    <button
                      onClick={() => handleRelease(device.id)}
                      className="p-2 text-green-400 hover:text-green-600 hover:bg-green-50 rounded-md transition-colors"
                      title="Release Device"
                    >
                      <CheckCircleIcon className="h-4 w-4" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Device Statistics */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mt-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Device Statistics</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <div className="text-2xl font-bold text-green-600">
              {devices.filter(d => d.status === 'compliant').length}
            </div>
            <div className="text-sm text-gray-600">Compliant</div>
          </div>
          <div className="text-center p-4 bg-red-50 rounded-lg">
            <div className="text-2xl font-bold text-red-600">
              {devices.filter(d => d.status === 'quarantined').length}
            </div>
            <div className="text-sm text-gray-600">Quarantined</div>
          </div>
          <div className="text-center p-4 bg-yellow-50 rounded-lg">
            <div className="text-2xl font-bold text-yellow-600">
              {devices.filter(d => d.status === 'investigating').length}
            </div>
            <div className="text-sm text-gray-600">Investigating</div>
          </div>
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="text-2xl font-bold text-blue-600">
              {devices.filter(d => d.compliance_status === 'non-compliant').length}
            </div>
            <div className="text-sm text-gray-600">Non-Compliant</div>
          </div>
        </div>
      </div>

      {/* Device Types Breakdown */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mt-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Device Types</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="text-2xl font-bold text-blue-600">
              {devices.filter(d => d.type === 'endpoint').length}
            </div>
            <div className="text-sm text-gray-600">Endpoints</div>
          </div>
          <div className="text-center p-4 bg-purple-50 rounded-lg">
            <div className="text-2xl font-bold text-purple-600">
              {devices.filter(d => d.type === 'server').length}
            </div>
            <div className="text-sm text-gray-600">Servers</div>
          </div>
          <div className="text-center p-4 bg-orange-50 rounded-lg">
            <div className="text-2xl font-bold text-orange-600">
              {devices.filter(d => d.type === 'mobile').length}
            </div>
            <div className="text-sm text-gray-600">Mobile</div>
          </div>
          <div className="text-center p-4 bg-indigo-50 rounded-lg">
            <div className="text-2xl font-bold text-indigo-600">
              {devices.filter(d => d.type === 'network').length}
            </div>
            <div className="text-sm text-gray-600">Network</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkDevices; 