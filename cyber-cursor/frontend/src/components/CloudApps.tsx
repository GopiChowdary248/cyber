import React, { useState, useEffect } from 'react';
import { 
  CloudIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon,
  EyeIcon,
  ShieldCheckIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

interface CloudApp {
  id: string;
  name: string;
  category: string;
  risk_level: string;
  users_count: number;
  data_volume: string;
  last_activity: string;
  status: string;
}

const CloudApps: React.FC = () => {
  const [apps, setApps] = useState<CloudApp[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCloudApps();
  }, []);

  const fetchCloudApps = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/cloud-security/casb/apps');
      if (response.ok) {
        const data = await response.json();
        setApps(data);
      } else {
        console.error('Failed to fetch cloud apps');
      }
    } catch (error) {
      console.error('Error fetching cloud apps:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'high':
        return 'text-red-500 bg-red-900/20';
      case 'medium':
        return 'text-yellow-500 bg-yellow-900/20';
      case 'low':
        return 'text-green-500 bg-green-900/20';
      default:
        return 'text-gray-500 bg-gray-900/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'monitored':
        return 'text-blue-500';
      case 'allowed':
        return 'text-green-500';
      case 'blocked':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-2">Cloud Applications</h1>
        <p className="text-gray-400">Monitor and manage cloud applications across all CASB providers</p>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Apps</p>
              <p className="text-2xl font-bold text-blue-500">{apps.length}</p>
            </div>
            <CloudIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">High Risk</p>
              <p className="text-2xl font-bold text-red-500">
                {apps.filter(app => app.risk_level === 'high').length}
              </p>
            </div>
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Monitored</p>
              <p className="text-2xl font-bold text-yellow-500">
                {apps.filter(app => app.status === 'monitored').length}
              </p>
            </div>
            <EyeIcon className="h-8 w-8 text-yellow-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Allowed</p>
              <p className="text-2xl font-bold text-green-500">
                {apps.filter(app => app.status === 'allowed').length}
              </p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>
      </div>

      {/* Apps List */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
          <CloudIcon className="h-5 w-5 mr-2 text-blue-400" />
          Monitored Applications ({apps.length})
        </h3>

        {apps.length === 0 ? (
          <div className="text-center py-12">
            <ShieldCheckIcon className="h-12 w-12 text-green-500 mx-auto mb-4" />
            <p className="text-gray-400">No cloud applications found.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {apps.map((app) => (
              <div key={app.id} className="bg-gray-700 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center mb-2">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskColor(app.risk_level)}`}>
                        {app.risk_level.toUpperCase()}
                      </span>
                      <span className={`ml-3 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(app.status)}`}>
                        {app.status.toUpperCase()}
                      </span>
                    </div>
                    
                    <h4 className="text-lg font-semibold text-white mb-2">{app.name}</h4>
                    
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-gray-400">Category:</span>
                        <span className="text-white ml-2">{app.category}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Users:</span>
                        <span className="text-white ml-2">{app.users_count}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Data Volume:</span>
                        <span className="text-white ml-2">{app.data_volume}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Last Activity:</span>
                        <span className="text-white ml-2">
                          {new Date(app.last_activity).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="ml-4 flex flex-col space-y-2">
                    <button className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700">
                      View Details
                    </button>
                    <button className="px-3 py-1 bg-gray-600 text-white rounded text-sm hover:bg-gray-700">
                      Manage Access
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Risk Analysis */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Risk Analysis</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">High Risk Apps</span>
              <span className="text-red-400 font-bold">
                {apps.filter(app => app.risk_level === 'high').length}
              </span>
            </div>
            <p className="text-sm text-gray-400">Applications with significant security risks that require immediate attention</p>
          </div>
          
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">Medium Risk Apps</span>
              <span className="text-yellow-400 font-bold">
                {apps.filter(app => app.risk_level === 'medium').length}
              </span>
            </div>
            <p className="text-sm text-gray-400">Applications with moderate security risks that should be monitored closely</p>
          </div>
          
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">Low Risk Apps</span>
              <span className="text-green-400 font-bold">
                {apps.filter(app => app.risk_level === 'low').length}
              </span>
            </div>
            <p className="text-sm text-gray-400">Applications with minimal security risks that are generally safe to use</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CloudApps; 