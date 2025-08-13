import React, { useState } from 'react';
import { Shield, Settings, Code, FileText, BarChart3, TrendingUp } from 'lucide-react';
import QualityRules from '../../components/SAST/QualityRules';
import QualityProfiles from '../../components/SAST/QualityProfiles';

const QualityManagement: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'rules' | 'profiles' | 'overview'>('overview');

  const tabs = [
    {
      id: 'overview',
      name: 'Overview',
      icon: BarChart3,
      description: 'Quality metrics and summary'
    },
    {
      id: 'rules',
      name: 'Quality Rules',
      icon: Code,
      description: 'Manage detection rules and configurations'
    },
    {
      id: 'profiles',
      name: 'Quality Profiles',
      icon: FileText,
      description: 'Create and manage quality profiles'
    }
  ];

  const renderOverview = () => (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Quality Management Overview</h2>
        <p className="text-gray-600">Monitor and manage SAST quality rules and profiles</p>
      </div>

      {/* Quality Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-blue-100 rounded-md flex items-center justify-center">
                <Code className="w-5 h-5 text-blue-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Rules</p>
              <p className="text-2xl font-semibold text-gray-900">156</p>
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-gray-600">
              <TrendingUp className="w-4 h-4 text-green-500 mr-1" />
              <span>+12 from last month</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-green-100 rounded-md flex items-center justify-center">
                <FileText className="w-5 h-5 text-green-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Active Profiles</p>
              <p className="text-2xl font-semibold text-gray-900">8</p>
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-gray-600">
              <TrendingUp className="w-4 h-4 text-green-500 mr-1" />
              <span>+2 from last month</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-yellow-100 rounded-md flex items-center justify-center">
                <Shield className="w-5 h-5 text-yellow-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Coverage</p>
              <p className="text-2xl font-semibold text-gray-900">78.5%</p>
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-gray-600">
              <TrendingUp className="w-4 h-4 text-green-500 mr-1" />
              <span>+2.3% from last scan</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-purple-100 rounded-md flex items-center justify-center">
                <Settings className="w-5 h-5 text-purple-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Languages</p>
              <p className="text-2xl font-semibold text-gray-900">6</p>
            </div>
          </div>
          <div className="mt-4">
            <div className="text-sm text-gray-600">
              <span>Java, Python, JS, TS, C#, PHP</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quality Status */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Quality Status by Language</h3>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {[
              { language: 'Java', rules: 156, coverage: 82.3, rating: 'A' },
              { language: 'Python', rules: 78, coverage: 75.8, rating: 'B' },
              { language: 'JavaScript', rules: 92, coverage: 68.2, rating: 'C' },
              { language: 'TypeScript', rules: 89, coverage: 71.5, rating: 'B' },
              { language: 'C#', rules: 134, coverage: 79.1, rating: 'B' },
              { language: 'PHP', rules: 67, coverage: 62.4, rating: 'C' }
            ].map((lang) => (
              <div key={lang.language} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                    <span className="text-lg font-semibold text-blue-600">{lang.language[0]}</span>
                  </div>
                  <div>
                    <h4 className="text-lg font-medium text-gray-900">{lang.language}</h4>
                    <p className="text-sm text-gray-500">{lang.rules} rules available</p>
                  </div>
                </div>
                <div className="flex items-center space-x-6">
                  <div className="text-center">
                    <p className="text-sm text-gray-500">Coverage</p>
                    <p className="text-lg font-semibold text-gray-900">{lang.coverage}%</p>
                  </div>
                  <div className="text-center">
                    <p className="text-sm text-gray-500">Rating</p>
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                      lang.rating === 'A' ? 'bg-green-100 text-green-800' :
                      lang.rating === 'B' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-red-100 text-red-800'
                    }`}>
                      {lang.rating}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Recent Quality Activity</h3>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {[
              { action: 'Profile Updated', profile: 'Security Profile', language: 'Java', time: '2 hours ago' },
              { action: 'Rule Enabled', rule: 'S1488', profile: 'Sonar way', time: '4 hours ago' },
              { action: 'New Profile Created', profile: 'Python Best Practices', language: 'Python', time: '1 day ago' },
              { action: 'Quality Gate Passed', project: 'Web Application', profile: 'Sonar way', time: '2 days ago' },
              { action: 'Rule Disabled', rule: 'S1135', profile: 'JavaScript ES6+', time: '3 days ago' }
            ].map((activity, index) => (
              <div key={index} className="flex items-center space-x-4 p-3 hover:bg-gray-50 rounded-lg">
                <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                <div className="flex-1">
                  <p className="text-sm text-gray-900">
                    <span className="font-medium">{activity.action}</span>
                    {activity.profile && ` in ${activity.profile}`}
                    {activity.rule && `: ${activity.rule}`}
                    {activity.project && ` for ${activity.project}`}
                    {activity.language && ` (${activity.language})`}
                  </p>
                </div>
                <span className="text-sm text-gray-500">{activity.time}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Quality Management</h1>
          <p className="text-gray-600">Configure and monitor SAST quality rules and profiles</p>
        </div>
        <div className="flex items-center space-x-2">
          <button className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
            <Settings className="w-4 h-4 mr-2" />
            Settings
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as 'rules' | 'profiles' | 'overview')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center space-x-2">
                  <Icon className="w-4 h-4" />
                  <span>{tab.name}</span>
                </div>
                <p className="text-xs mt-1 text-gray-400">{tab.description}</p>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'rules' && <QualityRules />}
        {activeTab === 'profiles' && <QualityProfiles />}
      </div>
    </div>
  );
};

export default QualityManagement;
