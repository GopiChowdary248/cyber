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
  ArrowTrendingDownIcon
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
} from 'chart.js';

// Import enhanced UI components
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedTabs from '../../components/UI/EnhancedTabs';
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
  Legend
);

interface CloudProvider {
  name: string;
  icon: string;
  color: string;
  status: 'healthy' | 'warning' | 'critical';
  resources: number;
  misconfigurations: number;
  compliance: number;
  lastScan: string;
}

interface SecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  provider: string;
  service: string;
  timestamp: string;
  status: 'open' | 'resolved' | 'in_progress';
}

const EnhancedCloudSecurity: React.FC = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [isLoading, setIsLoading] = useState(false);
  const [lastScan, setLastScan] = useState<string>('2024-01-15T10:30:00Z');

  // Mock data - in real implementation, this would come from API
  const cloudProviders: CloudProvider[] = [
    {
      name: 'AWS',
      icon: '☁️',
      color: 'bg-orange-500',
      status: 'healthy',
      resources: 45,
      misconfigurations: 3,
      compliance: 95,
      lastScan: '2024-01-15T09:30:00Z'
    },
    {
      name: 'Azure',
      icon: '☁️',
      color: 'bg-blue-500',
      status: 'warning',
      resources: 23,
      misconfigurations: 7,
      compliance: 88,
      lastScan: '2024-01-15T08:45:00Z'
    },
    {
      name: 'GCP',
      icon: '☁️',
      color: 'bg-green-500',
      status: 'healthy',
      resources: 21,
      misconfigurations: 2,
      compliance: 91,
      lastScan: '2024-01-15T10:15:00Z'
    }
  ];

  const securityFindings: SecurityFinding[] = [
    {
      id: '1',
      title: 'S3 Bucket Public Access Enabled',
      description: 'S3 bucket has public read access enabled',
      severity: 'high',
      provider: 'AWS',
      service: 'S3',
      timestamp: '2024-01-15T09:15:00Z',
      status: 'open'
    },
    {
      id: '2',
      title: 'IAM User with Excessive Permissions',
      description: 'IAM user has admin privileges',
      severity: 'critical',
      provider: 'AWS',
      service: 'IAM',
      timestamp: '2024-01-15T08:45:00Z',
      status: 'in_progress'
    },
    {
      id: '3',
      title: 'Network Security Group Misconfiguration',
      description: 'NSG allows unrestricted access',
      severity: 'medium',
      provider: 'Azure',
      service: 'Network',
      timestamp: '2024-01-15T07:30:00Z',
      status: 'open'
    }
  ];

  const chartData = {
    threatTrends: {
      labels: ['Jan 1', 'Jan 2', 'Jan 3', 'Jan 4', 'Jan 5', 'Jan 6', 'Jan 7'],
      datasets: [
        {
          label: 'Security Threats',
          data: [12, 19, 15, 25, 22, 18, 24],
          borderColor: 'rgb(239, 68, 68)',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          tension: 0.4
        },
        {
          label: 'Resolved Issues',
          data: [8, 15, 12, 20, 18, 14, 19],
          borderColor: 'rgb(34, 197, 94)',
          backgroundColor: 'rgba(34, 197, 94, 0.1)',
          tension: 0.4
        }
      ]
    },
    compliance: {
      labels: ['SOC 2', 'ISO 27001', 'PCI DSS', 'HIPAA', 'GDPR', 'NIST'],
      datasets: [
        {
          label: 'Compliance Score',
          data: [92, 88, 95, 85, 90, 87],
          backgroundColor: [
            'rgba(34, 197, 94, 0.8)',
            'rgba(59, 130, 246, 0.8)',
            'rgba(168, 85, 247, 0.8)',
            'rgba(239, 68, 68, 0.8)',
            'rgba(245, 158, 11, 0.8)',
            'rgba(6, 182, 212, 0.8)'
          ],
          borderColor: [
            'rgb(34, 197, 94)',
            'rgb(59, 130, 246)',
            'rgb(168, 85, 247)',
            'rgb(239, 68, 68)',
            'rgb(245, 158, 11)',
            'rgb(6, 182, 212)'
          ],
          borderWidth: 2
        }
      ]
    },
    resourceDistribution: {
      labels: ['Compute', 'Storage', 'Database', 'Network', 'Security', 'Monitoring'],
      datasets: [
        {
          data: [30, 25, 20, 15, 5, 5],
          backgroundColor: [
            'rgba(59, 130, 246, 0.8)',
            'rgba(168, 85, 247, 0.8)',
            'rgba(34, 197, 94, 0.8)',
            'rgba(245, 158, 11, 0.8)',
            'rgba(239, 68, 68, 0.8)',
            'rgba(6, 182, 212, 0.8)'
          ],
          borderWidth: 2,
          borderColor: '#1f2937'
        }
      ]
    }
  };

  const chartOptions = {
    responsive: true,
    plugins: {
      legend: {
        labels: { color: '#9ca3af' }
      }
    },
    scales: {
      x: { ticks: { color: '#9ca3af' } },
      y: { ticks: { color: '#9ca3af' } }
    }
  };

  const handleScan = async () => {
    setIsLoading(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000));
    setLastScan(new Date().toISOString());
    setIsLoading(false);
  };

  const getSeverityVariant = (severity: string) => {
    switch (severity) {
      case 'critical': return 'danger';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'default';
      default: return 'default';
    }
  };

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'healthy': return 'success';
      case 'warning': return 'warning';
      case 'critical': return 'danger';
      default: return 'default';
    }
  };

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <ChartBarIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <EnhancedCard
              variant="gradient"
              icon={<CloudIcon className="w-8 h-8 text-blue-500" />}
              title="Total Resources"
              subtitle="Across all providers"
            >
              <div className="text-3xl font-bold text-white">89</div>
              <div className="flex items-center text-green-400 text-sm">
                <ArrowTrendingUpIcon className="w-4 h-4 mr-1" />
                +12% from last month
              </div>
            </EnhancedCard>

            <EnhancedCard
              variant="gradient"
              icon={<ExclamationTriangleIcon className="w-8 h-8 text-yellow-500" />}
              title="Misconfigurations"
              subtitle="Security issues found"
            >
              <div className="text-3xl font-bold text-white">12</div>
              <div className="flex items-center text-red-400 text-sm">
                <ArrowTrendingDownIcon className="w-4 h-4 mr-1" />
                -3 from last scan
              </div>
            </EnhancedCard>

            <EnhancedCard
              variant="gradient"
              icon={<XCircleIcon className="w-8 h-8 text-red-500" />}
              title="Critical Findings"
              subtitle="High priority issues"
            >
              <div className="text-3xl font-bold text-white">3</div>
              <div className="flex items-center text-yellow-400 text-sm">
                <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
                Requires attention
              </div>
            </EnhancedCard>

            <EnhancedCard
              variant="gradient"
              icon={<ShieldCheckIcon className="w-8 h-8 text-green-500" />}
              title="Compliance Score"
              subtitle="Overall security rating"
            >
              <div className="text-3xl font-bold text-white">91%</div>
              <div className="flex items-center text-green-400 text-sm">
                <ArrowTrendingUpIcon className="w-4 h-4 mr-1" />
                +2% improvement
              </div>
            </EnhancedCard>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <EnhancedCard
              title="Threat Trends"
              subtitle="7-day security activity"
              variant="elevated"
            >
              <Line data={chartData.threatTrends} options={chartOptions} />
            </EnhancedCard>

            <EnhancedCard
              title="Resource Distribution"
              subtitle="By service type"
              variant="elevated"
            >
              <Doughnut data={chartData.resourceDistribution} options={chartOptions} />
            </EnhancedCard>
          </div>

          <EnhancedCard
            title="Compliance Overview"
            subtitle="Framework compliance scores"
            variant="elevated"
          >
            <Bar data={chartData.compliance} options={chartOptions} />
          </EnhancedCard>
        </div>
      )
    },
    {
      id: 'providers',
      label: 'Cloud Providers',
      icon: <GlobeAltIcon className="w-4 h-4" />,
      content: (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {cloudProviders.map((provider) => (
            <EnhancedCard
              key={provider.name}
              variant="glass"
              icon={<span className="text-2xl">{provider.icon}</span>}
              title={provider.name}
              badge={
                <EnhancedBadge
                  variant={getStatusVariant(provider.status)}
                  withDot
                >
                  {provider.status}
                </EnhancedBadge>
              }
            >
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-gray-400 text-sm">Resources</p>
                    <p className="text-2xl font-bold text-white">{provider.resources}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Issues</p>
                    <p className="text-2xl font-bold text-white">{provider.misconfigurations}</p>
                  </div>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Compliance</p>
                  <div className="flex items-center">
                    <div className="flex-1 bg-gray-700 rounded-full h-2 mr-3">
                      <div
                        className="bg-green-500 h-2 rounded-full"
                        style={{ width: `${provider.compliance}%` }}
                      />
                    </div>
                    <span className="text-white font-medium">{provider.compliance}%</span>
                  </div>
                </div>
                <div className="flex items-center text-gray-400 text-sm">
                  <ClockIcon className="w-4 h-4 mr-1" />
                  Last scan: {new Date(provider.lastScan).toLocaleDateString()}
                </div>
              </div>
            </EnhancedCard>
          ))}
        </div>
      )
    },
    {
      id: 'findings',
      label: 'Security Findings',
      icon: <EyeIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-4">
          {securityFindings.map((finding) => (
            <EnhancedCard
              key={finding.id}
              variant="default"
              title={finding.title}
              subtitle={`${finding.provider} - ${finding.service}`}
              badge={
                <EnhancedBadge
                  variant={getSeverityVariant(finding.severity)}
                  withDot
                >
                  {finding.severity}
                </EnhancedBadge>
              }
            >
              <p className="text-gray-400 mb-3">{finding.description}</p>
              <div className="flex items-center justify-between text-sm text-gray-500">
                <span>{new Date(finding.timestamp).toLocaleString()}</span>
                <EnhancedBadge variant="info" size="sm">
                  {finding.status}
                </EnhancedBadge>
              </div>
            </EnhancedCard>
          ))}
        </div>
      )
    },
    {
      id: 'cspm',
      label: 'CSPM',
      icon: <ShieldCheckIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <EnhancedCard
            title="Cloud Security Posture Management"
            subtitle="Security configuration monitoring"
            variant="elevated"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {['AWS Security Hub', 'Azure Security Center', 'GCP Security Command Center'].map((service) => (
                <div key={service} className="p-4 border border-gray-700 rounded-lg">
                  <h4 className="text-white font-medium mb-2">{service}</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Status</span>
                      <EnhancedBadge variant="success" size="sm">Active</EnhancedBadge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Findings</span>
                      <span className="text-white">12</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Last Scan</span>
                      <span className="text-white">2 hours ago</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </EnhancedCard>
        </div>
      )
    },
    {
      id: 'cwp',
      label: 'CWP',
      icon: <ServerIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <EnhancedCard
            title="Cloud Workload Protection"
            subtitle="Runtime security and threat detection"
            variant="elevated"
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="text-white font-medium mb-4">Protected Workloads</h4>
                <div className="space-y-3">
                  {['EC2 Instances', 'Azure VMs', 'GCP Compute', 'Containers'].map((workload) => (
                    <div key={workload} className="flex justify-between items-center p-3 border border-gray-700 rounded-lg">
                      <span className="text-white">{workload}</span>
                      <div className="flex items-center space-x-2">
                        <CheckCircleIcon className="w-5 h-5 text-green-400" />
                        <span className="text-green-400 text-sm">Protected</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <h4 className="text-white font-medium mb-4">Threat Detection</h4>
                <div className="space-y-3">
                  {['Malware Detection', 'Anomaly Detection', 'Vulnerability Scanning', 'Runtime Protection'].map((detection) => (
                    <div key={detection} className="flex justify-between items-center p-3 border border-gray-700 rounded-lg">
                      <span className="text-white">{detection}</span>
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                        <span className="text-green-400 text-sm">Active</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </EnhancedCard>
        </div>
      )
    },
    {
      id: 'monitoring',
      label: 'Monitoring',
      icon: <BellIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <EnhancedCard
            title="Security Monitoring & Alerting"
            subtitle="Real-time security event monitoring"
            variant="elevated"
          >
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h4 className="text-white font-medium mb-4">Monitoring Services</h4>
                <div className="space-y-3">
                  {['AWS CloudTrail', 'Azure Monitor', 'GCP Cloud Logging', 'Splunk Cloud', 'Datadog'].map((service) => (
                    <div key={service} className="flex justify-between items-center p-3 border border-gray-700 rounded-lg">
                      <span className="text-white">{service}</span>
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                        <span className="text-green-400 text-sm">Connected</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <h4 className="text-white font-medium mb-4">Recent Alerts</h4>
                <div className="space-y-3">
                  {[
                    'Suspicious login attempt detected',
                    'Unusual API activity in us-east-1',
                    'New security group created',
                    'IAM policy modified'
                  ].map((alert, index) => (
                    <div key={index} className="p-3 border border-gray-700 rounded-lg">
                      <p className="text-white text-sm">{alert}</p>
                      <p className="text-gray-400 text-xs mt-1">2 minutes ago</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </EnhancedCard>
        </div>
      )
    }
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Cloud Security</h1>
          <p className="text-gray-400">Multi-cloud security monitoring and compliance management</p>
        </div>
        <div className="flex items-center space-x-3">
          <EnhancedButton
            variant="outline"
            icon={<CogIcon className="w-4 h-4" />}
          >
            Settings
          </EnhancedButton>
          <EnhancedButton
            variant="primary"
            loading={isLoading}
                            icon={<ArrowPathIcon className="w-4 h-4" />}
            onClick={handleScan}
          >
            {isLoading ? 'Scanning...' : 'Run Security Scan'}
          </EnhancedButton>
        </div>
      </motion.div>

      {/* Enhanced Tabs */}
      <EnhancedTabs
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        variant="default"
        size="lg"
      />

      {/* Last Scan Info */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="text-center text-gray-400 text-sm"
      >
        Last security scan: {new Date(lastScan).toLocaleString()}
      </motion.div>
    </div>
  );
};

export default EnhancedCloudSecurity; 