import React, { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Http, 
  Target, 
  Spider, 
  Shield, 
  Zap, 
  Repeat, 
  Hash, 
  Code, 
  BarChart3, 
  FileText,
  Settings,
  Play,
  Square,
  RefreshCw
} from 'lucide-react';
import DASTProxyEngine from './Proxy/DASTProxyEngine';
import DASTScanner from './Scanner/DASTScanner';
import DASTCrawler from './Crawler/DASTCrawler';
import DASTMatchReplaceRules from './Rules/DASTMatchReplaceRules';
import DASTHttpHistory from './Traffic/DASTHttpHistory';
import DASTRepeater from './Tools/DASTRepeater';
import DASTIntruder from './Tools/DASTIntruder';
import DASTTarget from './Target/DASTTarget';
import DASTScannerIntegration from './Scanner/DASTScannerIntegration';

interface DASTApplicationProps {
  projectId: string;
}

interface Tab {
  id: string;
  label: string;
  icon: React.ReactNode;
  component: React.ComponentType<{ projectId: string }>;
  description: string;
  badge?: number;
}

const DASTApplication: React.FC<DASTApplicationProps> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState('proxy');
  const [proxyStatus, setProxyStatus] = useState<'stopped' | 'running'>('stopped');
  const [globalSettings, setGlobalSettings] = useState({
    interceptEnabled: false,
    autoScanEnabled: false,
    realTimeUpdates: true
  });

  const tabs: Tab[] = [
    {
      id: 'proxy',
      label: 'Proxy',
      icon: <Http className="w-4 h-4" />,
      component: DASTProxyEngine,
      description: 'Intercept and modify HTTP traffic'
    },
    {
      id: 'target',
      label: 'Target',
      icon: <Target className="w-4 h-4" />,
      component: DASTTarget,
      description: 'Site map and scope management'
    },
    {
      id: 'spider',
      label: 'Spider',
      icon: <Spider className="w-4 h-4" />,
      component: DASTCrawler,
      description: 'Automated web crawling'
    },
    {
      id: 'scanner',
      label: 'Scanner',
      icon: <Shield className="w-4 h-4" />,
      component: DASTScannerIntegration,
      description: 'Active and passive vulnerability scanning'
    },
    {
      id: 'intruder',
      label: 'Intruder',
      icon: <Zap className="w-4 h-4" />,
      component: DASTIntruder,
      description: 'Automated parameter testing'
    },
    {
      id: 'repeater',
      label: 'Repeater',
      icon: <Repeat className="w-4 h-4" />,
      component: DASTRepeater,
      description: 'Manual request manipulation'
    },
    {
      id: 'history',
      label: 'HTTP History',
      icon: <FileText className="w-4 h-4" />,
      component: DASTHttpHistory,
      description: 'Complete traffic analysis',
      badge: 0 // Will be updated with actual count
    },
    {
      id: 'rules',
      label: 'Match & Replace',
      icon: <Code className="w-4 h-4" />,
      component: DASTMatchReplaceRules,
      description: 'Traffic modification rules'
    },
    {
      id: 'sequencer',
      label: 'Sequencer',
      icon: <Hash className="w-4 h-4" />,
      component: () => <div className="p-6 text-center text-gray-500">Sequencer Tool - Coming Soon</div>,
      description: 'Randomness analysis'
    },
    {
      id: 'decoder',
      label: 'Decoder',
      icon: <BarChart3 className="w-4 h-4" />,
      component: () => <div className="p-6 text-center text-gray-500">Decoder Tool - Coming Soon</div>,
      description: 'Data encoding/decoding'
    }
  ];

  const handleTabChange = useCallback((tabId: string) => {
    setActiveTab(tabId);
  }, []);

  const handleProxyStatusChange = useCallback((status: 'stopped' | 'running') => {
    setProxyStatus(status);
  }, []);

  const handleGlobalSettingChange = useCallback((setting: keyof typeof globalSettings, value: boolean) => {
    setGlobalSettings(prev => ({ ...prev, [setting]: value }));
  }, []);

  const renderActiveTab = () => {
    const activeTabData = tabs.find(tab => tab.id === activeTab);
    if (!activeTabData) return null;

    const TabComponent = activeTabData.component;
    return (
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: -20 }}
        transition={{ duration: 0.2 }}
        className="flex-1 overflow-hidden"
      >
        <TabComponent projectId={projectId} />
      </motion.div>
    );
  };

  return (
    <div className="h-screen flex flex-col bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Shield className="w-8 h-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">DAST Security Suite</h1>
            </div>
            <div className="text-sm text-gray-500">Project: {projectId}</div>
          </div>
          
          <div className="flex items-center space-x-4">
            {/* Global Controls */}
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2 text-sm">
                <input
                  type="checkbox"
                  checked={globalSettings.interceptEnabled}
                  onChange={(e) => handleGlobalSettingChange('interceptEnabled', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span>Intercept</span>
              </label>
              
              <label className="flex items-center space-x-2 text-sm">
                <input
                  type="checkbox"
                  checked={globalSettings.autoScanEnabled}
                  onChange={(e) => handleGlobalSettingChange('autoScanEnabled', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span>Auto Scan</span>
              </label>
              
              <label className="flex items-center space-x-2 text-sm">
                <input
                  type="checkbox"
                  checked={globalSettings.realTimeUpdates}
                  onChange={(e) => handleGlobalSettingChange('realTimeUpdates', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span>Real-time</span>
              </label>
            </div>
            
            {/* Proxy Status */}
            <div className="flex items-center space-x-2">
              <div className={`w-3 h-3 rounded-full ${
                proxyStatus === 'running' ? 'bg-green-500' : 'bg-gray-400'
              }`} />
              <span className="text-sm text-gray-600">
                Proxy {proxyStatus === 'running' ? 'Running' : 'Stopped'}
              </span>
            </div>
            
            <button className="p-2 text-gray-400 hover:text-gray-600">
              <Settings className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Navigation */}
        <div className="w-64 bg-white border-r border-gray-200 overflow-y-auto">
          <nav className="p-4 space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                className={`w-full flex items-center space-x-3 px-3 py-3 text-left rounded-lg transition-colors ${
                  activeTab === tab.id
                    ? 'bg-blue-50 text-blue-700 border border-blue-200'
                    : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900'
                }`}
              >
                <div className="flex-shrink-0">
                  {tab.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium truncate">{tab.label}</span>
                    {tab.badge !== undefined && tab.badge > 0 && (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        {tab.badge}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-500 truncate">{tab.description}</p>
                </div>
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-hidden">
          <AnimatePresence mode="wait">
            {renderActiveTab()}
          </AnimatePresence>
        </div>
      </div>

      {/* Status Bar */}
      <div className="bg-white border-t border-gray-200 px-6 py-2">
        <div className="flex items-center justify-between text-sm text-gray-600">
          <div className="flex items-center space-x-4">
            <span>Ready</span>
            <span>•</span>
            <span>Project: {projectId}</span>
            <span>•</span>
            <span>Active Tab: {tabs.find(t => t.id === activeTab)?.label}</span>
          </div>
          
          <div className="flex items-center space-x-4">
            <span>Proxy: {proxyStatus}</span>
            <span>•</span>
            <span>Intercept: {globalSettings.interceptEnabled ? 'ON' : 'OFF'}</span>
            <span>•</span>
            <span>Auto Scan: {globalSettings.autoScanEnabled ? 'ON' : 'OFF'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DASTApplication;
