import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ChartBarIcon, 
  ShieldCheckIcon, 
  ExclamationTriangleIcon, 
  ServerIcon,
  ArrowUpIcon,
  ArrowDownIcon
} from '@heroicons/react/24/outline';
import { Line, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
);

interface RASPDashboardData {
  overview: {
    apps_count: number;
    agents_count: number;
    attacks_last_24h: number;
    blocked_last_24h: number;
    top_apps: Array<{
      id: string;
      name: string;
      risk_score: number;
    }>;
  };
  recent_incidents: Array<{
    id: string;
    signature: string;
    severity: string;
    app_name: string;
    timestamp: string;
    action_taken: string;
  }>;
  metrics: {
    attacks_timeline: Array<{ timestamp: string; value: number }>;
    severity_distribution: Array<{ severity: string; count: number }>;
  };
}

const RASPDashboard: React.FC = () => {
  const [data, setData] = useState<RASPDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('24h');

  useEffect(() => {
    fetchDashboardData();
  }, [timeRange]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      // TODO: Replace with actual API calls
      const mockData: RASPDashboardData = {
        overview: {
          apps_count: 12,
          agents_count: 24,
          attacks_last_24h: 156,
          blocked_last_24h: 142,
          top_apps: [
            { id: '1', name: 'Web Portal', risk_score: 8.5 },
            { id: '2', name: 'API Gateway', risk_score: 7.2 },
            { id: '3', name: 'Admin Panel', risk_score: 6.8 },
          ]
        },
        recent_incidents: [
          {
            id: '1',
            signature: 'SQL Injection Attempt',
            severity: 'high',
            app_name: 'Web Portal',
            timestamp: '2024-01-15T10:30:00Z',
            action_taken: 'blocked'
          },
          {
            id: '2',
            signature: 'XSS Payload Detected',
            severity: 'medium',
            app_name: 'API Gateway',
            timestamp: '2024-01-15T10:25:00Z',
            action_taken: 'monitored'
          }
        ],
        metrics: {
          attacks_timeline: [
            { timestamp: '00:00', value: 5 },
            { timestamp: '04:00', value: 3 },
            { timestamp: '08:00', value: 12 },
            { timestamp: '12:00', value: 18 },
            { timestamp: '16:00', value: 15 },
            { timestamp: '20:00', value: 8 }
          ],
          severity_distribution: [
            { severity: 'Critical', count: 5 },
            { severity: 'High', count: 23 },
            { severity: 'Medium', count: 67 },
            { severity: 'Low', count: 45 }
          ]
        }
      };
      
      setData(mockData);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getActionColor = (action: string) => {
    switch (action.toLowerCase()) {
      case 'blocked': return 'text-green-600 bg-green-100';
      case 'monitored': return 'text-blue-600 bg-blue-100';
      case 'allowed': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Failed to load dashboard data</p>
      </div>
    );
  }

  const attacksChartData = {
    labels: data.metrics.attacks_timeline.map(m => m.timestamp),
    datasets: [
      {
        label: 'Attacks',
        data: data.metrics.attacks_timeline.map(m => m.value),
        borderColor: 'rgb(59, 130, 246)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        tension: 0.4,
      },
    ],
  };

  const severityChartData = {
    labels: data.metrics.severity_distribution.map(m => m.severity),
    datasets: [
      {
        label: 'Incidents',
        data: data.metrics.severity_distribution.map(m => m.count),
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(234, 179, 8, 0.8)',
          'rgba(59, 130, 246, 0.8)',
        ],
      },
    ],
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">RASP Dashboard</h1>
          <p className="text-gray-600">Runtime Application Self-Protection Overview</p>
        </div>
        <div className="flex items-center space-x-2">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-2 text-sm"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <ServerIcon className="w-6 h-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Applications</p>
              <p className="text-2xl font-bold text-gray-900">{data.overview.apps_count}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <ChartBarIcon className="w-6 h-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Active Agents</p>
              <p className="text-2xl font-bold text-gray-900">{data.overview.agents_count}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <ExclamationTriangleIcon className="w-6 h-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Attacks (24h)</p>
              <p className="text-2xl font-bold text-gray-900">{data.overview.attacks_last_24h}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 rounded-lg">
              <ShieldCheckIcon className="w-6 h-6 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Blocked (24h)</p>
              <p className="text-2xl font-bold text-gray-900">{data.overview.blocked_last_24h}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attacks Timeline */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.4 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <h3 className="text-lg font-medium text-gray-900 mb-4">Attack Volume Timeline</h3>
          <div className="h-64">
            <Line
              data={attacksChartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    display: false,
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                    ticks: {
                      stepSize: 5,
                    },
                  },
                },
              }}
            />
          </div>
        </motion.div>

        {/* Severity Distribution */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="bg-white p-6 rounded-lg shadow-sm border border-gray-200"
        >
          <h3 className="text-lg font-medium text-gray-900 mb-4">Incident Severity Distribution</h3>
          <div className="h-64">
            <Bar
              data={severityChartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    display: false,
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                  },
                },
              }}
            />
          </div>
        </motion.div>
      </div>

      {/* Top Applications and Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Applications */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200"
        >
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Top Applications by Risk</h3>
          </div>
          <div className="divide-y divide-gray-200">
            {data.overview.top_apps.map((app, index) => (
              <div key={app.id} className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <span className="text-sm font-medium text-gray-900 mr-2">#{index + 1}</span>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{app.name}</p>
                      <p className="text-sm text-gray-500">Risk Score: {app.risk_score}</p>
                    </div>
                  </div>
                  <div className="flex items-center">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      app.risk_score >= 8 ? 'bg-red-100 text-red-800' :
                      app.risk_score >= 6 ? 'bg-orange-100 text-orange-800' :
                      app.risk_score >= 4 ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {app.risk_score >= 8 ? 'High' :
                       app.risk_score >= 6 ? 'Medium' :
                       app.risk_score >= 4 ? 'Low' : 'Very Low'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Recent Incidents */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          className="bg-white rounded-lg shadow-sm border border-gray-200"
        >
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Recent Incidents</h3>
          </div>
          <div className="divide-y divide-gray-200">
            {data.recent_incidents.map((incident) => (
              <div key={incident.id} className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(incident.severity)}`}>
                        {incident.severity}
                      </span>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getActionColor(incident.action_taken)}`}>
                        {incident.action_taken}
                      </span>
                    </div>
                    <p className="text-sm font-medium text-gray-900">{incident.signature}</p>
                    <p className="text-sm text-gray-500">{incident.app_name}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-500">
                      {new Date(incident.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default RASPDashboard;
