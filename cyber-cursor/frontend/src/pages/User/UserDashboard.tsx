import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  ShieldCheckIcon,
  EyeIcon,
  LockClosedIcon,
  ServerIcon,
  UserGroupIcon,
  GlobeAltIcon,
  BellIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  ArrowUpIcon,
  ArrowDownIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  CpuChipIcon,
  WifiIcon,
  CloudIcon,
  DocumentTextIcon,
  MagnifyingGlassIcon,
  ChartBarIcon,
  CogIcon,
  ArrowPathIcon,
  FireIcon,
  BugAntIcon,
  ShieldExclamationIcon,
  ComputerDesktopIcon,
  KeyIcon,
  DocumentMagnifyingGlassIcon
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

interface SecurityMetrics {
  threatsBlocked: number;
  vulnerabilitiesFound: number;
  incidentsResolved: number;
  securityScore: number;
}

interface ToolStatus {
  name: string;
  status: 'active' | 'warning' | 'error' | 'inactive';
  lastScan: string;
  description: string;
  icon: React.ReactNode;
  route: string;
}

const UserDashboard: React.FC = () => {
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics>({
    threatsBlocked: 1247,
    vulnerabilitiesFound: 23,
    incidentsResolved: 8,
    securityScore: 94
  });

  const [isLoading, setIsLoading] = useState(false);

  // Chart data
  const threatTrendData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [
      {
        label: 'Threats Detected',
        data: [45, 52, 38, 67, 42, 35, 28],
        borderColor: 'rgb(239, 68, 68)',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        fill: true
      },
      {
        label: 'Threats Blocked',
        data: [42, 48, 35, 62, 38, 32, 25],
        borderColor: 'rgb(34, 197, 94)',
        backgroundColor: 'rgba(34, 197, 94, 0.1)',
        fill: true
      }
    ]
  };

  const securityScoreData = {
    labels: ['Network', 'Endpoint', 'Application', 'Data', 'Cloud'],
    datasets: [
      {
        data: [92, 88, 95, 89, 87],
        backgroundColor: [
          'rgba(59, 130, 246, 0.8)',
          'rgba(168, 85, 247, 0.8)',
          'rgba(34, 197, 94, 0.8)',
          'rgba(251, 146, 60, 0.8)',
          'rgba(239, 68, 68, 0.8)'
        ],
        borderColor: [
          'rgb(59, 130, 246)',
          'rgb(168, 85, 247)',
          'rgb(34, 197, 94)',
          'rgb(251, 146, 60)',
          'rgb(239, 68, 68)'
        ],
        borderWidth: 2
      }
    ]
  };

  const incidentData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        label: 'Incidents by Severity',
        data: [2, 5, 12, 8],
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(251, 146, 60, 0.8)',
          'rgba(251, 191, 36, 0.8)',
          'rgba(34, 197, 94, 0.8)'
        ],
        borderColor: [
          'rgb(239, 68, 68)',
          'rgb(251, 146, 60)',
          'rgb(251, 191, 36)',
          'rgb(34, 197, 94)'
        ],
        borderWidth: 1
      }
    ]
  };

  const cybersecurityTools: ToolStatus[] = [
    {
      name: 'Threat Intelligence',
      status: 'active',
      lastScan: '2 minutes ago',
      description: 'Real-time threat detection and analysis',
      icon: <FireIcon className="w-6 h-6" />,
      route: '/threat-intelligence'
    },
    {
      name: 'Vulnerability Scanner',
      status: 'active',
      lastScan: '1 hour ago',
      description: 'Automated vulnerability assessment',
      icon: <BugAntIcon className="w-6 h-6" />,
      route: '/vulnerability-scanner'
    },
    {
      name: 'SIEM Monitoring',
      status: 'active',
      lastScan: 'Real-time',
      description: 'Security information and event management',
      icon: <ShieldExclamationIcon className="w-6 h-6" />,
      route: '/siem-monitoring'
    },
    {
      name: 'Network Security',
      status: 'warning',
      lastScan: '30 minutes ago',
      description: 'Network traffic analysis and protection',
      icon: <WifiIcon className="w-6 h-6" />,
      route: '/network-security'
    },
    {
      name: 'Endpoint Security',
      status: 'active',
      lastScan: '15 minutes ago',
      description: 'Device-level security monitoring',
      icon: <ComputerDesktopIcon className="w-6 h-6" />,
      route: '/endpoint-security'
    },
    {
      name: 'Cloud Security',
      status: 'active',
      lastScan: '45 minutes ago',
      description: 'Cloud infrastructure security',
      icon: <CloudIcon className="w-6 h-6" />,
      route: '/cloud-security'
    },
    {
      name: 'Data Protection',
      status: 'active',
      lastScan: '1 hour ago',
      description: 'Data encryption and privacy controls',
      icon: <LockClosedIcon className="w-6 h-6" />,
      route: '/data-protection'
    },
    {
      name: 'Application Security',
      status: 'active',
      lastScan: '2 hours ago',
      description: 'Application vulnerability testing',
      icon: <DocumentMagnifyingGlassIcon className="w-6 h-6" />,
      route: '/application-security'
    }
  ];

  const handleRefresh = async () => {
    setIsLoading(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    setIsLoading(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-400';
      case 'warning': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      case 'inactive': return 'text-gray-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircleIcon className="w-4 h-4 text-green-400" />;
      case 'warning': return <ExclamationTriangleIcon className="w-4 h-4 text-yellow-400" />;
      case 'error': return <ExclamationTriangleIcon className="w-4 h-4 text-red-400" />;
      case 'inactive': return <ClockIcon className="w-4 h-4 text-gray-400" />;
      default: return <ClockIcon className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusBgColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-500/20 border-green-500/30';
      case 'warning': return 'bg-yellow-500/20 border-yellow-500/30';
      case 'error': return 'bg-red-500/20 border-red-500/30';
      case 'inactive': return 'bg-gray-500/20 border-gray-500/30';
      default: return 'bg-gray-500/20 border-gray-500/30';
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
              <h1 className="text-3xl font-bold text-white mb-2">Security Dashboard</h1>
              <p className="text-gray-400">Comprehensive cybersecurity monitoring and tools</p>
            </div>
            <button
              onClick={handleRefresh}
              disabled={isLoading}
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors disabled:opacity-50"
            >
              <ArrowPathIcon className={`w-5 h-5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </motion.div>

        {/* Security Metrics Overview */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
        >
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-red-500/20 rounded-lg">
                <ShieldCheckIcon className="w-6 h-6 text-red-400" />
              </div>
              <span className="text-sm text-gray-400">Threats Blocked</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{securityMetrics.threatsBlocked}</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingUpIcon className="w-4 h-4 text-green-400 mr-1" />
              <span className="text-green-400">+12%</span>
              <span className="text-gray-400 ml-1">from yesterday</span>
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-yellow-500/20 rounded-lg">
                <BugAntIcon className="w-6 h-6 text-yellow-400" />
              </div>
              <span className="text-sm text-gray-400">Vulnerabilities</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{securityMetrics.vulnerabilitiesFound}</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingDownIcon className="w-4 h-4 text-red-400 mr-1" />
              <span className="text-red-400">-3</span>
              <span className="text-gray-400 ml-1">from last scan</span>
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <CheckCircleIcon className="w-6 h-6 text-green-400" />
              </div>
              <span className="text-sm text-gray-400">Incidents Resolved</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{securityMetrics.incidentsResolved}</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingUpIcon className="w-4 h-4 text-green-400 mr-1" />
              <span className="text-green-400">+2</span>
              <span className="text-gray-400 ml-1">this week</span>
            </div>
          </div>

          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-4">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <ChartBarIcon className="w-6 h-6 text-blue-400" />
              </div>
              <span className="text-sm text-gray-400">Security Score</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{securityMetrics.securityScore}/100</div>
            <div className="flex items-center text-sm">
              <ArrowTrendingUpIcon className="w-4 h-4 text-green-400 mr-1" />
              <span className="text-green-400">+2</span>
              <span className="text-gray-400 ml-1">from last week</span>
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
          {/* Threat Trends Chart */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-lg font-semibold text-white mb-4">Threat Trends (Weekly)</h3>
            <Line 
              data={threatTrendData}
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

          {/* Security Score Breakdown */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-lg font-semibold text-white mb-4">Security Score Breakdown</h3>
            <Doughnut 
              data={securityScoreData}
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
        </motion.div>

        {/* Cybersecurity Tools Grid */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="mb-8"
        >
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold text-white">Cybersecurity Tools</h3>
            <span className="text-gray-400 text-sm">All tools are actively monitoring your security</span>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {cybersecurityTools.map((tool, index) => (
              <Link
                key={index}
                to={tool.route}
                className="group"
              >
                <motion.div
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className={`bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20 hover:bg-white/15 transition-all duration-200 cursor-pointer ${getStatusBgColor(tool.status)}`}
                >
                  <div className="flex items-center justify-between mb-4">
                    <div className="p-2 bg-blue-500/20 rounded-lg group-hover:bg-blue-500/30 transition-colors">
                      {tool.icon}
                    </div>
                    {getStatusIcon(tool.status)}
                  </div>
                  
                  <h4 className="font-semibold text-white mb-2 group-hover:text-blue-300 transition-colors">
                    {tool.name}
                  </h4>
                  
                  <p className="text-gray-400 text-sm mb-3">
                    {tool.description}
                  </p>
                  
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>Last scan:</span>
                    <span className="text-gray-300">{tool.lastScan}</span>
                  </div>
                </motion.div>
              </Link>
            ))}
          </div>
        </motion.div>

        {/* Recent Incidents and Alerts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="grid grid-cols-1 lg:grid-cols-2 gap-6"
        >
          {/* Recent Incidents */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-white">Recent Incidents</h3>
              <Link to="/incidents" className="text-blue-400 hover:text-blue-300 text-sm">
                View All
              </Link>
            </div>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 bg-red-500/10 rounded-lg border border-red-500/20">
                <div className="flex items-center space-x-3">
                  <ExclamationTriangleIcon className="w-5 h-5 text-red-400" />
                  <div>
                    <p className="text-white font-medium">Suspicious Login Attempt</p>
                    <p className="text-gray-400 text-sm">Multiple failed login attempts detected</p>
                  </div>
                </div>
                <span className="text-xs text-gray-400">2 min ago</span>
              </div>
              
              <div className="flex items-center justify-between p-3 bg-yellow-500/10 rounded-lg border border-yellow-500/20">
                <div className="flex items-center space-x-3">
                  <BugAntIcon className="w-5 h-5 text-yellow-400" />
                  <div>
                    <p className="text-white font-medium">Vulnerability Detected</p>
                    <p className="text-gray-400 text-sm">SQL injection vulnerability found</p>
                  </div>
                </div>
                <span className="text-xs text-gray-400">1 hour ago</span>
              </div>
              
              <div className="flex items-center justify-between p-3 bg-green-500/10 rounded-lg border border-green-500/20">
                <div className="flex items-center space-x-3">
                  <CheckCircleIcon className="w-5 h-5 text-green-400" />
                  <div>
                    <p className="text-white font-medium">Threat Blocked</p>
                    <p className="text-gray-400 text-sm">Malware attempt successfully blocked</p>
                  </div>
                </div>
                <span className="text-xs text-gray-400">3 hours ago</span>
              </div>
            </div>
          </div>

          {/* Incident Severity Chart */}
          <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20">
            <h3 className="text-lg font-semibold text-white mb-4">Incidents by Severity</h3>
            <Bar 
              data={incidentData}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    display: false
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
      </div>
    </div>
  );
};

export default UserDashboard; 