import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheckIcon,
  UserGroupIcon,
  CogIcon,
  ChartBarIcon,
  ServerIcon,
  KeyIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  EyeIcon,
  LockClosedIcon,
  GlobeAltIcon,
  BellIcon,
  CpuChipIcon,
  WifiIcon,
  CloudIcon,
  DocumentTextIcon,
  CreditCardIcon,
  Cog6ToothIcon,
  UsersIcon,
  ChartPieIcon
} from '@heroicons/react/24/outline';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface SystemHealth {
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  status: 'healthy' | 'warning' | 'critical';
}

interface LicenseInfo {
  product: string;
  status: 'active' | 'expired' | 'trial';
  expiryDate: string;
  users: number;
  maxUsers: number;
}

interface UserStats {
  total: number;
  active: number;
  inactive: number;
  newThisMonth: number;
}

const AdminDashboard: React.FC = () => {
  const [systemHealth, setSystemHealth] = useState<SystemHealth>({
    cpu: 45,
    memory: 62,
    disk: 78,
    network: 23,
    status: 'healthy'
  });

  const [licenses, setLicenses] = useState<LicenseInfo[]>([
    { product: 'Threat Intelligence', status: 'active', expiryDate: '2024-12-31', users: 45, maxUsers: 50 },
    { product: 'Vulnerability Scanner', status: 'active', expiryDate: '2024-11-15', users: 38, maxUsers: 40 },
    { product: 'SIEM Platform', status: 'trial', expiryDate: '2024-10-20', users: 12, maxUsers: 25 },
    { product: 'Cloud Security', status: 'expired', expiryDate: '2024-09-01', users: 0, maxUsers: 30 }
  ]);

  const [userStats, setUserStats] = useState<UserStats>({
    total: 156,
    active: 142,
    inactive: 14,
    newThisMonth: 23
  });

  const [isLoading, setIsLoading] = useState(false);

  // Chart data
  const systemUsageData = {
    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'],
    datasets: [
      {
        label: 'CPU Usage',
        data: [35, 42, 38, 55, 48, 52, 45],
        borderColor: 'rgb(59, 130, 246)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',

        fill: true
      },
      {
        label: 'Memory Usage',
        data: [45, 52, 48, 65, 58, 62, 55],
        borderColor: 'rgb(168, 85, 247)',
        backgroundColor: 'rgba(168, 85, 247, 0.1)',

        fill: true
      }
    ]
  };

  const securityEventsData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [
      {
        label: 'Security Events',
        data: [12, 19, 15, 25, 22, 18, 14],
        backgroundColor: 'rgba(239, 68, 68, 0.8)',
        borderColor: 'rgb(239, 68, 68)',
        borderWidth: 1
      }
    ]
  };

  const userDistributionData = {
    labels: ['Active Users', 'Inactive Users', 'New Users'],
    datasets: [
      {
        data: [userStats.active, userStats.inactive, userStats.newThisMonth],
        backgroundColor: [
          'rgba(34, 197, 94, 0.8)',
          'rgba(156, 163, 175, 0.8)',
          'rgba(59, 130, 246, 0.8)'
        ],
        borderColor: [
          'rgb(34, 197, 94)',
          'rgb(156, 163, 175)',
          'rgb(59, 130, 246)'
        ],
        borderWidth: 2
      }
    ]
  };

  const handleRefresh = async () => {
    setIsLoading(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    setIsLoading(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-400';
      case 'trial': return 'text-yellow-400';
      case 'expired': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircleIcon className="w-5 h-5 text-green-400" />;
      case 'trial': return <ClockIcon className="w-5 h-5 text-yellow-400" />;
      case 'expired': return <ExclamationTriangleIcon className="w-5 h-5 text-red-400" />;
      default: return <ExclamationTriangleIcon className="w-5 h-5 text-gray-400" />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">Admin Dashboard</h1>
              <p className="text-gray-400">System administration and monitoring</p>
            </div>
            <button
              onClick={handleRefresh}
              disabled={isLoading}
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors disabled:opacity-50"
            >
              <CogIcon className={`w-5 h-5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </motion.div>

        {/* System Health Overview */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
        >
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <CpuChipIcon className="w-6 h-6 text-blue-400" />
              </div>
              <span className="text-sm text-gray-400">CPU</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{systemHealth.cpu}%</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingUpIcon className="w-4 h-4 text-green-400 mr-1" />
              <span className="text-green-400">+2.5%</span>
              <span className="text-gray-400 ml-1">from last hour</span>
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <ServerIcon className="w-6 h-6 text-purple-400" />
              </div>
              <span className="text-sm text-gray-400">Memory</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{systemHealth.memory}%</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingDownIcon className="w-4 h-4 text-red-400 mr-1" />
              <span className="text-red-400">-1.2%</span>
              <span className="text-gray-400 ml-1">from last hour</span>
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <ServerIcon className="w-6 h-6 text-green-400" />
              </div>
              <span className="text-sm text-gray-400">Disk</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{systemHealth.disk}%</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingUpIcon className="w-4 h-4 text-yellow-400 mr-1" />
              <span className="text-yellow-400">+0.8%</span>
              <span className="text-gray-400 ml-1">from last hour</span>
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-orange-500/20 rounded-lg">
                <WifiIcon className="w-6 h-6 text-orange-400" />
              </div>
              <span className="text-sm text-gray-400">Network</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{systemHealth.network}%</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingUpIcon className="w-4 h-4 text-green-400 mr-1" />
              <span className="text-green-400">+5.3%</span>
              <span className="text-gray-400 ml-1">from last hour</span>
            </div>
          </div>
        </motion.div>

        {/* Charts Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8"
        >
          {/* System Usage Chart */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-lg font-semibold text-white mb-4">System Usage (24h)</h3>
            <Line 
              data={systemUsageData}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    labels: { color: 'white' }
                  }
                },
                scales: {
                  x: {
                    ticks: { color: 'white' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                  },
                  y: {
                    ticks: { color: 'white' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                  }
                }
              }}
            />
          </div>

          {/* Security Events Chart */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-lg font-semibold text-white mb-4">Security Events (Weekly)</h3>
            <Bar 
              data={securityEventsData}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    labels: { color: 'white' }
                  }
                },
                scales: {
                  x: {
                    ticks: { color: 'white' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                  },
                  y: {
                    ticks: { color: 'white' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                  }
                }
              }}
            />
          </div>
        </motion.div>

        {/* License Management */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20 mb-8"
        >
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold text-white">License Management</h3>
            <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors">
              <KeyIcon className="w-5 h-5" />
              <span>Manage Licenses</span>
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {licenses.map((license, index) => (
              <div key={index} className="bg-white/5 rounded-lg p-4 border border-white/10">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-medium text-white">{license.product}</h4>
                  {getStatusIcon(license.status)}
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Status:</span>
                    <span className={getStatusColor(license.status)}>{license.status}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Expires:</span>
                    <span className="text-white">{license.expiryDate}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Users:</span>
                    <span className="text-white">{license.users}/{license.maxUsers}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* User Management and Analytics */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="grid grid-cols-1 lg:grid-cols-3 gap-6"
        >
          {/* User Statistics */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-white">User Statistics</h3>
              <UsersIcon className="w-6 h-6 text-blue-400" />
            </div>
            
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Total Users</span>
                <span className="text-2xl font-bold text-white">{userStats.total}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Active Users</span>
                <span className="text-xl font-semibold text-green-400">{userStats.active}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Inactive Users</span>
                <span className="text-xl font-semibold text-gray-400">{userStats.inactive}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">New This Month</span>
                <span className="text-xl font-semibold text-blue-400">{userStats.newThisMonth}</span>
              </div>
            </div>
          </div>

          {/* User Distribution Chart */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-lg font-semibold text-white mb-4">User Distribution</h3>
            <Doughnut 
              data={userDistributionData}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    position: 'bottom',
                    labels: { color: 'white' }
                  }
                }
              }}
            />
          </div>

          {/* Quick Actions */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-lg font-semibold text-white mb-6">Quick Actions</h3>
            
            <div className="space-y-3">
              <button className="w-full bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-lg flex items-center justify-between transition-colors">
                <span>Add New User</span>
                <UserGroupIcon className="w-5 h-5" />
              </button>
              
              <button className="w-full bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg flex items-center justify-between transition-colors">
                <span>System Health</span>
                <ChartBarIcon className="w-5 h-5" />
              </button>
              
              <button className="w-full bg-purple-600 hover:bg-purple-700 text-white p-3 rounded-lg flex items-center justify-between transition-colors">
                <span>Security Logs</span>
                <DocumentTextIcon className="w-5 h-5" />
              </button>
              
              <button className="w-full bg-orange-600 hover:bg-orange-700 text-white p-3 rounded-lg flex items-center justify-between transition-colors">
                <span>Billing & Usage</span>
                <CreditCardIcon className="w-5 h-5" />
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default AdminDashboard; 