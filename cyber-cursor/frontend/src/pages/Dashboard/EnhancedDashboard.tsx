import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  CloudIcon, 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ChartBarIcon,
  CogIcon,
  ArrowPathIcon,
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
  ArrowDownIcon
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

// Import enhanced UI components
import { PageContainer, GridLayout, LoadingSpinner, SearchInput, FilterBar } from '../../components/UI/DesignSystem';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedBadge from '../../components/UI/EnhancedBadge';

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

// Mock data
const mockData = {
  securityMetrics: {
    totalResources: 1247,
    secureResources: 1189,
    vulnerableResources: 58,
    complianceScore: 94.2,
    threatLevel: 'Low',
    lastScan: '2024-01-15T10:30:00Z'
  },
  cloudProviders: {
    aws: { resources: 456, issues: 12, status: 'healthy' },
    azure: { resources: 389, issues: 8, status: 'healthy' },
    gcp: { resources: 402, issues: 15, status: 'warning' }
  },
  recentIncidents: [
    { id: 1, title: 'Suspicious IAM Activity', severity: 'high', provider: 'AWS', time: '2 hours ago' },
    { id: 2, title: 'Unusual Network Traffic', severity: 'medium', provider: 'Azure', time: '4 hours ago' },
    { id: 3, title: 'Failed Login Attempts', severity: 'low', provider: 'GCP', time: '6 hours ago' }
  ],
  securityTrends: {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
    datasets: [
      {
        label: 'Security Score',
        data: [85, 87, 89, 91, 93, 92, 94, 95, 93, 96, 94, 97],
        borderColor: '#3B82F6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',

        fill: true
      }
    ]
  },
  threatDistribution: {
    labels: ['Malware', 'Phishing', 'DDoS', 'Data Breach', 'Insider Threat'],
    datasets: [{
      data: [30, 25, 20, 15, 10],
      backgroundColor: [
        '#EF4444',
        '#F59E0B',
        '#3B82F6',
        '#10B981',
        '#8B5CF6'
      ],
      borderWidth: 2,
      borderColor: '#1f2937'
    }]
  },
  resourceUsage: {
    labels: ['AWS', 'Azure', 'GCP'],
    datasets: [{
      data: [456, 389, 402],
      backgroundColor: [
        '#FF9900',
        '#0078D4',
        '#4285F4'
      ],
      borderWidth: 2,
      borderColor: '#1f2937'
    }]
  }
};

const EnhancedDashboard: React.FC = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('all');
  const [selectedTimeframe, setSelectedTimeframe] = useState('7d');

  const handleRefresh = () => {
    setIsLoading(true);
    setTimeout(() => setIsLoading(false), 2000);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return 'danger';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'warning': return <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" />;
      case 'critical': return <XCircleIcon className="w-5 h-5 text-red-500" />;
      default: return <ClockIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { 
          color: '#9ca3af',
          usePointStyle: true,
          padding: 20
        }
      },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.95)',
        titleColor: '#f8fafc',
        bodyColor: '#cbd5e1',
        borderColor: '#374151',
        borderWidth: 1,
        cornerRadius: 8,
        displayColors: true
      }
    },
    scales: {
      x: { 
        ticks: { color: '#9ca3af' },
        grid: { color: '#374151' }
      },
      y: { 
        ticks: { color: '#9ca3af' },
        grid: { color: '#374151' }
      }
    }
  };

  const filters = [
    {
      key: 'provider',
      label: 'Provider',
      options: [
        { value: 'all', label: 'All Providers' },
        { value: 'aws', label: 'AWS' },
        { value: 'azure', label: 'Azure' },
        { value: 'gcp', label: 'GCP' }
      ],
      value: selectedProvider,
      onChange: setSelectedProvider
    },
    {
      key: 'timeframe',
      label: 'Timeframe',
      options: [
        { value: '24h', label: 'Last 24 Hours' },
        { value: '7d', label: 'Last 7 Days' },
        { value: '30d', label: 'Last 30 Days' },
        { value: '90d', label: 'Last 90 Days' }
      ],
      value: selectedTimeframe,
      onChange: setSelectedTimeframe
    }
  ];

  return (
    <PageContainer
      title="Security Dashboard"
      subtitle="Comprehensive overview of your cloud security posture"
      actions={
        <div className="flex items-center gap-3">
          <SearchInput
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search resources, incidents..."
            className="w-64"
          />
          <EnhancedButton
            variant="primary"
                            icon={<ArrowPathIcon className="w-4 h-4" />}
            onClick={handleRefresh}
            loading={isLoading}
          >
            Refresh
          </EnhancedButton>
        </div>
      }
      loading={isLoading}
    >
      {/* Filters */}
      <div className="mb-6">
        <FilterBar filters={filters} />
      </div>

      {/* Key Metrics */}
      <GridLayout cols={4} gap="lg" className="mb-8">
        <EnhancedCard
          variant="gradient"
          title="Total Resources"
          subtitle="Across all providers"
          icon={<ServerIcon className="w-6 h-6 text-blue-500" />}
        >
          <div className="flex items-center justify-between">
            <div className="text-3xl font-bold text-white">
              {mockData.securityMetrics.totalResources.toLocaleString()}
            </div>
            <div className="flex items-center gap-1 text-green-400">
              <ArrowUpIcon className="w-4 h-4" />
              <span className="text-sm">+12%</span>
            </div>
          </div>
        </EnhancedCard>

        <EnhancedCard
          variant="elevated"
          title="Security Score"
          subtitle="Overall compliance"
          icon={<ShieldCheckIcon className="w-6 h-6 text-green-500" />}
        >
          <div className="flex items-center justify-between">
            <div className="text-3xl font-bold text-white">
              {mockData.securityMetrics.complianceScore}%
            </div>
            <div className="flex items-center gap-1 text-green-400">
              <ArrowUpIcon className="w-4 h-4" />
              <span className="text-sm">+2.1%</span>
            </div>
          </div>
        </EnhancedCard>

        <EnhancedCard
          variant="glass"
          title="Active Threats"
          subtitle="Current risk level"
          icon={<ExclamationTriangleIcon className="w-6 h-6 text-yellow-500" />}
        >
          <div className="flex items-center justify-between">
            <div className="text-3xl font-bold text-white">
              {mockData.securityMetrics.vulnerableResources}
            </div>
            <EnhancedBadge variant="warning" withDot>
              {mockData.securityMetrics.threatLevel}
            </EnhancedBadge>
          </div>
        </EnhancedCard>

        <EnhancedCard
          variant="default"
          title="Last Scan"
          subtitle="Security assessment"
          icon={<ClockIcon className="w-6 h-6 text-purple-500" />}
        >
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-300">
              {new Date(mockData.securityMetrics.lastScan).toLocaleDateString()}
            </div>
            <EnhancedBadge variant="success" withDot>
              Recent
            </EnhancedBadge>
          </div>
        </EnhancedCard>
      </GridLayout>

      {/* Cloud Provider Status */}
      <GridLayout cols={3} gap="lg" className="mb-8">
        {Object.entries(mockData.cloudProviders).map(([provider, data]) => (
          <EnhancedCard
            key={provider}
            variant="elevated"
            title={provider.toUpperCase()}
            subtitle={`${data.resources} resources`}
            icon={getStatusIcon(data.status)}
            badge={
              <EnhancedBadge 
                variant={data.status === 'healthy' ? 'success' : 'warning'} 
                withDot
              >
                {data.issues} issues
              </EnhancedBadge>
            }
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Resources</span>
                <span className="text-white font-semibold">{data.resources}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Issues</span>
                <span className="text-white font-semibold">{data.issues}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${((data.resources - data.issues) / data.resources) * 100}%` }}
                />
              </div>
            </div>
          </EnhancedCard>
        ))}
      </GridLayout>

      {/* Charts Section */}
      <GridLayout cols={2} gap="lg" className="mb-8">
        <EnhancedCard
          title="Security Trends"
          subtitle="Monthly security score progression"
          variant="elevated"
        >
          <div className="h-64">
            <Line data={mockData.securityTrends} options={chartOptions} />
          </div>
        </EnhancedCard>

        <EnhancedCard
          title="Threat Distribution"
          subtitle="Types of security threats detected"
          variant="elevated"
        >
          <div className="h-64">
            <Doughnut data={mockData.threatDistribution} options={chartOptions} />
          </div>
        </EnhancedCard>
      </GridLayout>

      {/* Recent Incidents */}
      <EnhancedCard
        title="Recent Security Incidents"
        subtitle="Latest alerts and notifications"
        variant="elevated"
        actions={
          <EnhancedButton variant="outline" size="sm">
            View All
          </EnhancedButton>
        }
      >
        <div className="space-y-4">
          {mockData.recentIncidents.map((incident) => (
            <motion.div
              key={incident.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg border border-gray-700"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 bg-gray-700 rounded-lg flex items-center justify-center">
                  <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" />
                </div>
                <div>
                  <h4 className="text-white font-medium">{incident.title}</h4>
                  <p className="text-gray-400 text-sm">{incident.provider} • {incident.time}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <EnhancedBadge variant={getSeverityColor(incident.severity)}>
                  {incident.severity}
                </EnhancedBadge>
                <EnhancedButton variant="ghost" size="sm">
                  <EyeIcon className="w-4 h-4" />
                </EnhancedButton>
              </div>
            </motion.div>
          ))}
        </div>
      </EnhancedCard>

      {/* Resource Usage by Provider */}
      <EnhancedCard
        title="Resource Distribution"
        subtitle="Resources across cloud providers"
        variant="elevated"
        className="mt-8"
      >
        <div className="h-64">
          <Bar data={mockData.resourceUsage} options={chartOptions} />
        </div>
      </EnhancedCard>
    </PageContainer>
  );
};

export default EnhancedDashboard; 