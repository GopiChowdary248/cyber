import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  BugAntIcon,
  PlayIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  InformationCircleIcon,
  ChartBarIcon,
  GlobeAltIcon,
  ArrowPathIcon,
  PlusIcon
} from '@heroicons/react/24/outline';
import DASTProjects from './DASTProjects';
import DASTDashboard from '../../components/DAST/DASTDashboard';
import { dastService } from '../../services/dastService';
import toast from 'react-hot-toast';

interface DASTData {
  overview: {
    totalProjects: number;
    totalScans: number;
    activeScans: number;
    totalVulnerabilities: number;
    securityScore: number;
  };
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  scanTypes: {
    full: number;
    passive: number;
    active: number;
    custom: number;
  };
  recentScans: Array<{
    id: string;
    projectName: string;
    status: string;
    vulnerabilities: number;
    duration: string;
    timestamp: string;
  }>;
}

const DAST: React.FC = () => {
  const [data, setData] = useState<DASTData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  const handleNewProject = () => {
    // Switch to projects tab when creating new project
    setActiveTab('projects');
    // You can also open a modal or navigate to a create project form
    toast.success('Switched to Projects tab. Use the form below to create a new DAST project.');
  };

  useEffect(() => {
    const fetchDASTData = async () => {
      try {
        setLoading(true);
        
        // Fetch DAST overview from the service
        const overview = await dastService.getOverview();
        
        // Fetch recent scans
        const scans = await dastService.getScans();
        
        // Transform the data to match our interface
        const transformedData: DASTData = {
          overview: {
            totalProjects: overview.total_projects || 0,
            totalScans: overview.total_scans || 0,
            activeScans: overview.active_scans || 0,
            totalVulnerabilities: 0, // Will be calculated from vulnerabilities
            securityScore: 85 // Default score, can be enhanced later
          },
          vulnerabilities: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            total: 0
          },
          scanTypes: {
            full: 45,
            passive: 32,
            active: 28,
            custom: 15
          },
          recentScans: scans.slice(0, 5).map(scan => ({
            id: scan.id.toString(),
            projectName: `Project ${scan.project_id}`,
            status: scan.status,
            vulnerabilities: scan.findings_count || 0,
            duration: '2m 30s', // Can be calculated from timestamps
            timestamp: scan.started_at
          }))
        };
        
        setData(transformedData);
      } catch (error) {
        console.error('Failed to fetch DAST data:', error);
        toast.error('Failed to load DAST data. Please try again.');
        
        // Fallback to mock data if service fails
        setData({
          overview: {
            totalProjects: 5,
            totalScans: 23,
            activeScans: 2,
            totalVulnerabilities: 47,
            securityScore: 78.5
          },
          vulnerabilities: {
            critical: 8,
            high: 15,
            medium: 18,
            low: 6,
            total: 47
          },
          scanTypes: {
            full: 45,
            passive: 32,
            active: 28,
            custom: 15
          },
          recentScans: [
            {
              id: 'scan-001',
              projectName: 'E-commerce Web App',
              status: 'completed',
              vulnerabilities: 3,
              duration: '3m 45s',
              timestamp: '2025-08-02T18:00:00Z'
            },
            {
              id: 'scan-002',
              projectName: 'Admin Portal',
              status: 'running',
              vulnerabilities: 0,
              duration: '1m 23s',
              timestamp: '2025-08-02T17:45:00Z'
            },
            {
              id: 'scan-003',
              projectName: 'API Gateway',
              status: 'completed',
              vulnerabilities: 1,
              duration: '2m 12s',
              timestamp: '2025-08-02T17:30:00Z'
            }
          ]
        });
      } finally {
        setLoading(false);
      }
    };

    fetchDASTData();
  }, []);

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" /> },
    { id: 'projects', label: 'Projects', icon: <GlobeAltIcon className="w-4 h-4" /> }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dynamic Application Security Testing (DAST)</h1>
          <p className="text-gray-600">Scan web applications for vulnerabilities in real-time</p>
        </div>
        <button 
          onClick={handleNewProject}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700"
        >
          <PlusIcon className="w-4 h-4 mr-2" />
          New Project
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span className="ml-2">{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'overview' && <DASTDashboard />}
        {activeTab === 'projects' && <DASTProjects />}
      </div>
    </div>
  );
};

export default DAST; 