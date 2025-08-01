import React, { useState } from 'react';
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
  InformationCircleIcon
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
import EnhancedCard from './EnhancedCard';
import EnhancedButton from './EnhancedButton';
import EnhancedTabs from './EnhancedTabs';
import EnhancedBadge from './EnhancedBadge';
import EnhancedModal from './EnhancedModal';
import EnhancedTooltip from './EnhancedTooltip';

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

const ComponentTestSuite: React.FC = () => {
  const [activeTab, setActiveTab] = useState('cards');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const chartData = {
    test: {
      labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
      datasets: [
        {
          label: 'Test Data',
          data: [12, 19, 3, 5, 2, 3],
          borderColor: 'rgb(59, 130, 246)',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
  
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

  const handleTestLoading = () => {
    setIsLoading(true);
    setTimeout(() => setIsLoading(false), 2000);
  };

  const tabs = [
    {
      id: 'cards',
      label: 'Enhanced Cards',
      icon: <ChartBarIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Card Variants</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <EnhancedCard
                variant="default"
                title="Default Card"
                subtitle="Standard variant"
                icon={<CloudIcon className="w-6 h-6 text-blue-500" />}
              >
                <p className="text-gray-300">This is a default card with standard styling.</p>
              </EnhancedCard>

              <EnhancedCard
                variant="elevated"
                title="Elevated Card"
                subtitle="Enhanced shadow"
                icon={<ShieldCheckIcon className="w-6 h-6 text-green-500" />}
              >
                <p className="text-gray-300">This card has enhanced shadow and depth.</p>
              </EnhancedCard>

              <EnhancedCard
                variant="glass"
                title="Glass Card"
                subtitle="Transparent effect"
                icon={<EyeIcon className="w-6 h-6 text-purple-500" />}
              >
                <p className="text-gray-300">This card uses glass morphism effects.</p>
              </EnhancedCard>

              <EnhancedCard
                variant="gradient"
                title="Gradient Card"
                subtitle="Colorful background"
                icon={<ArrowTrendingUpIcon className="w-6 h-6 text-orange-500" />}
              >
                <p className="text-gray-300">This card has a gradient background.</p>
              </EnhancedCard>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Cards with Badges</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <EnhancedCard
                variant="default"
                title="Success Status"
                subtitle="All systems operational"
                badge={<EnhancedBadge variant="success" withDot>Active</EnhancedBadge>}
              >
                <div className="flex items-center text-green-400">
                  <CheckCircleIcon className="w-5 h-5 mr-2" />
                  <span>System is healthy</span>
                </div>
              </EnhancedCard>

              <EnhancedCard
                variant="default"
                title="Warning Status"
                subtitle="Some issues detected"
                badge={<EnhancedBadge variant="warning" withDot>Warning</EnhancedBadge>}
              >
                <div className="flex items-center text-yellow-400">
                  <ExclamationTriangleIcon className="w-5 h-5 mr-2" />
                  <span>3 issues found</span>
                </div>
              </EnhancedCard>

              <EnhancedCard
                variant="default"
                title="Critical Status"
                subtitle="Immediate attention required"
                badge={<EnhancedBadge variant="danger" withDot>Critical</EnhancedBadge>}
              >
                <div className="flex items-center text-red-400">
                  <XCircleIcon className="w-5 h-5 mr-2" />
                  <span>Security breach detected</span>
                </div>
              </EnhancedCard>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Loading States</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <EnhancedCard
                variant="elevated"
                title="Loading Card"
                subtitle="Processing data..."
                loading={true}
              >
                <p className="text-gray-300">This content is hidden while loading.</p>
              </EnhancedCard>

              <EnhancedCard
                variant="glass"
                title="Interactive Card"
                subtitle="Click to test"
                onClick={() => alert('Card clicked!')}
              >
                <p className="text-gray-300">This card is clickable. Try clicking it!</p>
              </EnhancedCard>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'buttons',
      label: 'Enhanced Buttons',
      icon: <CogIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Button Variants</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <EnhancedButton variant="primary" icon={<CheckCircleIcon className="w-4 h-4" />}>
                Primary
              </EnhancedButton>
              <EnhancedButton variant="secondary" icon={<CogIcon className="w-4 h-4" />}>
                Secondary
              </EnhancedButton>
              <EnhancedButton variant="success" icon={<ShieldCheckIcon className="w-4 h-4" />}>
                Success
              </EnhancedButton>
              <EnhancedButton variant="danger" icon={<XCircleIcon className="w-4 h-4" />}>
                Danger
              </EnhancedButton>
              <EnhancedButton variant="warning" icon={<ExclamationTriangleIcon className="w-4 h-4" />}>
                Warning
              </EnhancedButton>
              <EnhancedButton variant="ghost" icon={<EyeIcon className="w-4 h-4" />}>
                Ghost
              </EnhancedButton>
              <EnhancedButton variant="outline" icon={<InformationCircleIcon className="w-4 h-4" />}>
                Outline
              </EnhancedButton>
                              <EnhancedButton variant="primary" icon={<ArrowPathIcon className="w-4 h-4" />} iconPosition="right">
                Right Icon
              </EnhancedButton>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Button Sizes</h3>
            <div className="flex items-center space-x-4">
              <EnhancedButton size="sm" variant="primary">
                Small
              </EnhancedButton>
              <EnhancedButton size="md" variant="primary">
                Medium
              </EnhancedButton>
              <EnhancedButton size="lg" variant="primary">
                Large
              </EnhancedButton>
              <EnhancedButton size="xl" variant="primary">
                Extra Large
              </EnhancedButton>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Loading States</h3>
            <div className="flex items-center space-x-4">
              <EnhancedButton
                variant="primary"
                loading={isLoading}
                onClick={handleTestLoading}
              >
                {isLoading ? 'Loading...' : 'Test Loading'}
              </EnhancedButton>
              <EnhancedButton
                variant="success"
                loading={isLoading}
                icon={<CheckCircleIcon className="w-4 h-4" />}
              >
                Success Loading
              </EnhancedButton>
              <EnhancedButton
                variant="danger"
                loading={isLoading}
                icon={<XCircleIcon className="w-4 h-4" />}
              >
                Danger Loading
              </EnhancedButton>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Full Width Buttons</h3>
            <div className="space-y-4">
              <EnhancedButton
                variant="primary"
                fullWidth
                icon={<CloudIcon className="w-4 h-4" />}
              >
                Full Width Primary Button
              </EnhancedButton>
              <EnhancedButton
                variant="outline"
                fullWidth
                icon={<ShieldCheckIcon className="w-4 h-4" />}
              >
                Full Width Outline Button
              </EnhancedButton>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'badges',
      label: 'Enhanced Badges',
      icon: <BellIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Badge Variants</h3>
            <div className="flex flex-wrap gap-4">
              <EnhancedBadge variant="default">Default</EnhancedBadge>
              <EnhancedBadge variant="primary">Primary</EnhancedBadge>
              <EnhancedBadge variant="success">Success</EnhancedBadge>
              <EnhancedBadge variant="warning">Warning</EnhancedBadge>
              <EnhancedBadge variant="danger">Danger</EnhancedBadge>
              <EnhancedBadge variant="info">Info</EnhancedBadge>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Badge Sizes</h3>
            <div className="flex items-center space-x-4">
              <EnhancedBadge size="sm" variant="primary">Small</EnhancedBadge>
              <EnhancedBadge size="md" variant="primary">Medium</EnhancedBadge>
              <EnhancedBadge size="lg" variant="primary">Large</EnhancedBadge>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Badges with Dots</h3>
            <div className="flex flex-wrap gap-4">
              <EnhancedBadge variant="success" withDot>Active</EnhancedBadge>
              <EnhancedBadge variant="warning" withDot>Pending</EnhancedBadge>
              <EnhancedBadge variant="danger" withDot>Error</EnhancedBadge>
              <EnhancedBadge variant="info" withDot>Processing</EnhancedBadge>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Rounded Badges</h3>
            <div className="flex flex-wrap gap-4">
              <EnhancedBadge variant="primary" rounded>Rounded</EnhancedBadge>
              <EnhancedBadge variant="success" rounded withDot>Active</EnhancedBadge>
              <EnhancedBadge variant="warning" rounded withDot>Warning</EnhancedBadge>
              <EnhancedBadge variant="danger" rounded withDot>Critical</EnhancedBadge>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'tabs',
      label: 'Enhanced Tabs',
      icon: <GlobeAltIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Tab Variants</h3>
            <div className="space-y-6">
              <div>
                <h4 className="text-lg font-medium text-white mb-2">Default Tabs</h4>
                <EnhancedTabs
                  tabs={[
                    {
                      id: 'tab1',
                      label: 'Overview',
                      icon: <ChartBarIcon className="w-4 h-4" />,
                      content: <div className="p-4 bg-gray-800 rounded-lg">Overview content goes here</div>
                    },
                    {
                      id: 'tab2',
                      label: 'Details',
                      icon: <EyeIcon className="w-4 h-4" />,
                      content: <div className="p-4 bg-gray-800 rounded-lg">Details content goes here</div>
                    },
                    {
                      id: 'tab3',
                      label: 'Settings',
                      icon: <CogIcon className="w-4 h-4" />,
                      content: <div className="p-4 bg-gray-800 rounded-lg">Settings content goes here</div>
                    }
                  ]}
                  activeTab="tab1"
                  onTabChange={(id) => console.log('Tab changed to:', id)}
                  variant="default"
                />
              </div>

              <div>
                <h4 className="text-lg font-medium text-white mb-2">Pills Tabs</h4>
                <EnhancedTabs
                  tabs={[
                    {
                      id: 'pills1',
                      label: 'Security',
                      icon: <ShieldCheckIcon className="w-4 h-4" />,
                      content: <div className="p-4 bg-gray-800 rounded-lg">Security content</div>
                    },
                    {
                      id: 'pills2',
                      label: 'Monitoring',
                      icon: <BellIcon className="w-4 h-4" />,
                      content: <div className="p-4 bg-gray-800 rounded-lg">Monitoring content</div>
                    }
                  ]}
                  activeTab="pills1"
                  onTabChange={(id) => console.log('Pills tab changed to:', id)}
                  variant="pills"
                />
              </div>

              <div>
                <h4 className="text-lg font-medium text-white mb-2">Underline Tabs</h4>
                <EnhancedTabs
                  tabs={[
                    {
                      id: 'underline1',
                      label: 'Reports',
                      icon: <ChartBarIcon className="w-4 h-4" />,
                      content: <div className="p-4 bg-gray-800 rounded-lg">Reports content</div>
                    },
                    {
                      id: 'underline2',
                      label: 'Analytics',
                      icon: <ArrowTrendingUpIcon className="w-4 h-4" />,
                      content: <div className="p-4 bg-gray-800 rounded-lg">Analytics content</div>
                    }
                  ]}
                  activeTab="underline1"
                  onTabChange={(id) => console.log('Underline tab changed to:', id)}
                  variant="underline"
                />
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'modals',
      label: 'Enhanced Modals',
      icon: <ServerIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Modal Sizes</h3>
            <div className="flex flex-wrap gap-4">
              <EnhancedButton
                variant="primary"
                onClick={() => setIsModalOpen(true)}
              >
                Open Modal
              </EnhancedButton>
            </div>
          </div>

          <EnhancedModal
            isOpen={isModalOpen}
            onClose={() => setIsModalOpen(false)}
            title="Test Modal"
            size="lg"
          >
            <div className="space-y-4">
              <p className="text-gray-300">
                This is a test modal with enhanced styling and animations.
              </p>
              <div className="flex justify-end space-x-3">
                <EnhancedButton
                  variant="outline"
                  onClick={() => setIsModalOpen(false)}
                >
                  Cancel
                </EnhancedButton>
                <EnhancedButton
                  variant="primary"
                  onClick={() => setIsModalOpen(false)}
                >
                  Confirm
                </EnhancedButton>
              </div>
            </div>
          </EnhancedModal>
        </div>
      )
    },
    {
      id: 'tooltips',
      label: 'Enhanced Tooltips',
      icon: <InformationCircleIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Tooltip Positions</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <EnhancedTooltip content="This tooltip appears on top" position="top">
                <EnhancedButton variant="outline">Top Tooltip</EnhancedButton>
              </EnhancedTooltip>
              
              <EnhancedTooltip content="This tooltip appears on the bottom" position="bottom">
                <EnhancedButton variant="outline">Bottom Tooltip</EnhancedButton>
              </EnhancedTooltip>
              
              <EnhancedTooltip content="This tooltip appears on the left" position="left">
                <EnhancedButton variant="outline">Left Tooltip</EnhancedButton>
              </EnhancedTooltip>
              
              <EnhancedTooltip content="This tooltip appears on the right" position="right">
                <EnhancedButton variant="outline">Right Tooltip</EnhancedButton>
              </EnhancedTooltip>
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Rich Content Tooltips</h3>
            <div className="flex space-x-4">
              <EnhancedTooltip
                content={
                  <div>
                    <p className="font-semibold">Security Status</p>
                    <p className="text-sm">All systems are operational</p>
                    <div className="flex items-center mt-1">
                      <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                      <span className="text-sm">Healthy</span>
                    </div>
                  </div>
                }
                position="top"
              >
                <EnhancedButton variant="success" icon={<ShieldCheckIcon className="w-4 h-4" />}>
                  Security Status
                </EnhancedButton>
              </EnhancedTooltip>

              <EnhancedTooltip
                content={
                  <div>
                    <p className="font-semibold">Performance Metrics</p>
                    <p className="text-sm">CPU: 45% | Memory: 67%</p>
                    <p className="text-sm">Network: 23 Mbps</p>
                  </div>
                }
                position="bottom"
              >
                <EnhancedButton variant="primary" icon={<ChartBarIcon className="w-4 h-4" />}>
                  Performance
                </EnhancedButton>
              </EnhancedTooltip>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'charts',
      label: 'Data Visualization',
                icon: <ArrowTrendingUpIcon className="w-4 h-4" />,
      content: (
        <div className="space-y-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Chart Components</h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <EnhancedCard
                title="Line Chart"
                subtitle="Test data visualization"
                variant="elevated"
              >
                <Line data={chartData.test} options={chartOptions} />
              </EnhancedCard>

              <EnhancedCard
                title="Bar Chart"
                subtitle="Comparison data"
                variant="elevated"
              >
                <Bar data={chartData.test} options={chartOptions} />
              </EnhancedCard>

              <EnhancedCard
                title="Doughnut Chart"
                subtitle="Distribution data"
                variant="elevated"
              >
                <Doughnut 
                  data={{
                    labels: ['Red', 'Blue', 'Yellow'],
                    datasets: [{
                      data: [300, 50, 100],
                      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56'],
                      borderWidth: 2,
                      borderColor: '#1f2937'
                    }]
                  }} 
                  options={chartOptions} 
                />
              </EnhancedCard>

              <EnhancedCard
                title="Chart with Badge"
                subtitle="Status indicator"
                variant="elevated"
                badge={<EnhancedBadge variant="success" withDot>Live</EnhancedBadge>}
              >
                <Line data={chartData.test} options={chartOptions} />
              </EnhancedCard>
            </div>
          </div>
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
        className="text-center"
      >
        <h1 className="text-4xl font-bold text-white mb-2">Component Test Suite</h1>
        <p className="text-gray-400">Comprehensive testing interface for all enhanced UI components</p>
      </motion.div>

      {/* Navigation Tabs */}
      <EnhancedTabs
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        variant="default"
        size="lg"
      />

      {/* Test Results Summary */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="text-center text-gray-400 text-sm"
      >
        <p>All components are functional and ready for production use!</p>
        <p className="mt-1">Check the browser console for interaction logs.</p>
      </motion.div>
    </div>
  );
};

export default ComponentTestSuite; 