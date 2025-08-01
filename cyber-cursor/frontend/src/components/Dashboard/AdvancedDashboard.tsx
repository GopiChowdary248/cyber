import React, { useState, useEffect, useRef } from 'react';
import { 
  ChartBarIcon, 
  ClockIcon, 
  ExclamationTriangleIcon, 
  ShieldCheckIcon,
  UserGroupIcon,
  AcademicCapIcon,
  CloudIcon,
  EyeIcon
} from '@heroicons/react/24/outline';
import { Line, Bar, Doughnut, Radar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface DashboardMetric {
  id: string;
  title: string;
  value: number | string;
  change: number;
  changeType: 'increase' | 'decrease' | 'neutral';
  icon: React.ComponentType<any>;
  color: string;
  format?: 'number' | 'percentage' | 'currency' | 'time';
}

interface TrendData {
  labels: string[];
  datasets: {
    label: string;
    data: number[];
    borderColor?: string;
    backgroundColor?: string;
    fill?: boolean;
  }[];
}

interface DashboardWidget {
  id: string;
  type: 'metric' | 'chart' | 'table' | 'list';
  title: string;
  size: 'small' | 'medium' | 'large';
  config: any;
  data?: any;
}

interface DashboardConfig {
  id: string;
  name: string;
  description: string;
  widgets: DashboardWidget[];
  layout: 'grid' | 'flexible';
  refreshInterval: number;
}

const AdvancedDashboard: React.FC = () => {
  const [dashboardData, setDashboardData] = useState<any>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTimeRange, setSelectedTimeRange] = useState('7d');
  const [customDashboard, setCustomDashboard] = useState<DashboardConfig | null>(null);
  const [showCustomizeModal, setShowCustomizeModal] = useState(false);
  const [availableWidgets, setAvailableWidgets] = useState<DashboardWidget[]>([]);
  
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    loadDashboardData();
    loadCustomDashboard();
    setupAutoRefresh();

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [selectedTimeRange]);

  const setupAutoRefresh = () => {
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
    }
    
    refreshIntervalRef.current = setInterval(() => {
      loadDashboardData();
    }, 30000); // Refresh every 30 seconds
  };

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      const response = await fetch(
        `${process.env.REACT_APP_API_URL}/api/v1/analytics/dashboard?time_range=${selectedTimeRange}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      if (response.ok) {
        const data = await response.json();
        setDashboardData(data);
        setError(null);
      } else {
        throw new Error('Failed to load dashboard data');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const loadCustomDashboard = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(
        `${process.env.REACT_APP_API_URL}/api/v1/analytics/custom-dashboard`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      if (response.ok) {
        const data = await response.json();
        setCustomDashboard(data);
      }
    } catch (err) {
      console.error('Failed to load custom dashboard:', err);
    }
  };

  const getMetrics = (): DashboardMetric[] => {
    const { incidents, security, user_activity, compliance, training, cloud_security, phishing } = dashboardData;
    
    return [
      {
        id: 'total_incidents',
        title: 'Total Incidents',
        value: incidents?.total_incidents || 0,
        change: incidents?.incidents_7d || 0,
        changeType: incidents?.incidents_7d > 0 ? 'increase' : 'decrease',
        icon: ExclamationTriangleIcon,
        color: 'bg-red-500',
        format: 'number'
      },
      {
        id: 'security_score',
        title: 'Security Score',
        value: security?.security_score || 0,
        change: 2.5,
        changeType: 'increase',
        icon: ShieldCheckIcon,
        color: 'bg-green-500',
        format: 'percentage'
      },
      {
        id: 'active_users',
        title: 'Active Users',
        value: user_activity?.active_users || 0,
        change: 5,
        changeType: 'increase',
        icon: UserGroupIcon,
        color: 'bg-blue-500',
        format: 'number'
      },
      {
        id: 'training_completion',
        title: 'Training Completion',
        value: training?.completion_rate || 0,
        change: -1.2,
        changeType: 'decrease',
        icon: AcademicCapIcon,
        color: 'bg-purple-500',
        format: 'percentage'
      },
      {
        id: 'cloud_security',
        title: 'Cloud Security',
        value: cloud_security?.security_posture || 0,
        change: 3.1,
        changeType: 'increase',
        icon: CloudIcon,
        color: 'bg-indigo-500',
        format: 'percentage'
      },
      {
        id: 'phishing_detection',
        title: 'Phishing Detection',
        value: phishing?.detection_accuracy || 0,
        change: 1.8,
        changeType: 'increase',
        icon: EyeIcon,
        color: 'bg-yellow-500',
        format: 'percentage'
      }
    ];
  };

  const getIncidentTrendData = (): TrendData => {
    const trendData = dashboardData.incidents?.daily_trend || [];
    
    return {
      labels: trendData.map((item: any) => item.date),
      datasets: [
        {
          label: 'Incidents',
          data: trendData.map((item: any) => item.count),
          borderColor: 'rgb(239, 68, 68)',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true
        }
      ]
    };
  };

  const getSecurityScoreData = (): TrendData => {
    // Mock data for security score trend
    const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const data = [82, 85, 87, 84, 89, 86, 88];
    
    return {
      labels,
      datasets: [
        {
          label: 'Security Score',
          data,
          borderColor: 'rgb(34, 197, 94)',
          backgroundColor: 'rgba(34, 197, 94, 0.1)',
          fill: true
        }
      ]
    };
  };

  const getSeverityDistributionData = () => {
    const severityData = dashboardData.incidents?.severity_distribution || {};
    
    return {
      labels: Object.keys(severityData),
      datasets: [
        {
          data: Object.values(severityData),
          backgroundColor: [
            'rgba(239, 68, 68, 0.8)',   // Critical - Red
            'rgba(249, 115, 22, 0.8)',  // High - Orange
            'rgba(234, 179, 8, 0.8)',   // Medium - Yellow
            'rgba(59, 130, 246, 0.8)',  // Low - Blue
          ],
          borderWidth: 2,
          borderColor: '#ffffff'
        }
      ]
    };
  };

  const getComplianceData = () => {
    const complianceData = dashboardData.compliance || {};
    
    return {
      labels: ['Compliant', 'Non-Compliant', 'Pending Review'],
      datasets: [
        {
          data: [
            complianceData.compliant_count || 85,
            complianceData.non_compliant_count || 10,
            complianceData.pending_count || 5
          ],
          backgroundColor: [
            'rgba(34, 197, 94, 0.8)',   // Green
            'rgba(239, 68, 68, 0.8)',   // Red
            'rgba(234, 179, 8, 0.8)',   // Yellow
          ],
          borderWidth: 2,
          borderColor: '#ffffff'
        }
      ]
    };
  };

  const formatValue = (value: number, format: string = 'number') => {
    switch (format) {
      case 'percentage':
        return `${value.toFixed(1)}%`;
      case 'currency':
        return `$${value.toLocaleString()}`;
      case 'time':
        return `${value}h`;
      default:
        return value.toLocaleString();
    }
  };

  const getChangeColor = (changeType: string) => {
    switch (changeType) {
      case 'increase':
        return 'text-green-600';
      case 'decrease':
        return 'text-red-600';
      default:
        return 'text-gray-600';
    }
  };

  const getChangeIcon = (changeType: string) => {
    switch (changeType) {
      case 'increase':
        return '↗';
      case 'decrease':
        return '↘';
      default:
        return '→';
    }
  };

  const renderMetricCard = (metric: DashboardMetric) => {
    const IconComponent = metric.icon;
    
    return (
      <div key={metric.id} className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-600">{metric.title}</p>
            <p className="text-2xl font-bold text-gray-900">
              {formatValue(metric.value as number, metric.format)}
            </p>
          </div>
          <div className={`p-3 rounded-full ${metric.color}`}>
            <IconComponent className="h-6 w-6 text-white" />
          </div>
        </div>
        <div className="mt-4 flex items-center">
          <span className={`text-sm font-medium ${getChangeColor(metric.changeType)}`}>
            {getChangeIcon(metric.changeType)} {Math.abs(metric.change)}%
          </span>
          <span className="text-sm text-gray-500 ml-2">vs last period</span>
        </div>
      </div>
    );
  };

  const renderChartWidget = (widget: DashboardWidget) => {
    const { chartType, data } = widget.config;
    
    const chartData = data || {};
    const options = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom' as const,
        },
      },
    };

    switch (chartType) {
      case 'line':
        return <Line data={chartData} options={options} />;
      case 'bar':
        return <Bar data={chartData} options={options} />;
      case 'doughnut':
        return <Doughnut data={chartData} options={options} />;
      case 'radar':
        return <Radar data={chartData} options={options} />;
      default:
        return <div>Unsupported chart type</div>;
    }
  };

  const renderWidget = (widget: DashboardWidget) => {
    return (
      <div key={widget.id} className={`bg-white rounded-lg shadow p-6 ${
        widget.size === 'large' ? 'col-span-2' : ''
      }`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium text-gray-900">{widget.title}</h3>
          <button className="text-gray-400 hover:text-gray-600">
            <ChartBarIcon className="h-5 w-5" />
          </button>
        </div>
        
        <div className="h-64">
          {widget.type === 'chart' && renderChartWidget(widget)}
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex">
          <ExclamationTriangleIcon className="h-5 w-5 text-red-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error loading dashboard</h3>
            <p className="text-sm text-red-700 mt-1">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Advanced Dashboard</h1>
          <p className="text-gray-600">Real-time security analytics and insights</p>
        </div>
        <div className="flex items-center space-x-4">
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-2 text-sm"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
          </select>
          <button
            onClick={() => setShowCustomizeModal(true)}
            className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700"
          >
            Customize Dashboard
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {getMetrics().map(renderMetricCard)}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Incident Trend */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium text-gray-900">Incident Trend</h3>
            <button className="text-gray-400 hover:text-gray-600">
              <ChartBarIcon className="h-5 w-5" />
            </button>
          </div>
          <div className="h-64">
            <Line data={getIncidentTrendData()} options={{
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
            }} />
          </div>
        </div>

        {/* Security Score Trend */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium text-gray-900">Security Score Trend</h3>
            <button className="text-gray-400 hover:text-gray-600">
              <ChartBarIcon className="h-5 w-5" />
            </button>
          </div>
          <div className="h-64">
            <Line data={getSecurityScoreData()} options={{
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
                  max: 100,
                },
              },
            }} />
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium text-gray-900">Incident Severity Distribution</h3>
            <button className="text-gray-400 hover:text-gray-600">
              <ChartBarIcon className="h-5 w-5" />
            </button>
          </div>
          <div className="h-64">
            <Doughnut data={getSeverityDistributionData()} options={{
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'bottom',
                },
              },
            }} />
          </div>
        </div>

        {/* Compliance Status */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium text-gray-900">Compliance Status</h3>
            <button className="text-gray-400 hover:text-gray-600">
              <ChartBarIcon className="h-5 w-5" />
            </button>
          </div>
          <div className="h-64">
            <Doughnut data={getComplianceData()} options={{
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'bottom',
                },
              },
            }} />
          </div>
        </div>
      </div>

      {/* Custom Dashboard Widgets */}
      {customDashboard && (
        <div className="space-y-6">
          <h2 className="text-xl font-bold text-gray-900">{customDashboard.name}</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {customDashboard.widgets.map(renderWidget)}
          </div>
        </div>
      )}

      {/* Customize Modal */}
      {showCustomizeModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-medium text-gray-900">Customize Dashboard</h3>
              <button
                onClick={() => setShowCustomizeModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4">
              <p className="text-gray-600">
                Drag and drop widgets to customize your dashboard layout.
              </p>
              
              {/* Widget Library */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {availableWidgets.map((widget) => (
                  <div
                    key={widget.id}
                    className="border border-gray-200 rounded-lg p-4 cursor-move hover:border-indigo-300"
                  >
                    <h4 className="font-medium text-gray-900">{widget.title}</h4>
                    <p className="text-sm text-gray-600 mt-1">{widget.config.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdvancedDashboard; 