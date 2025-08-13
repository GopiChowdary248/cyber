import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Lock,
  User,
  Users,
  Key,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Plus,
  Search,
  Filter,
  Download,
  Upload,
  Eye,
  EyeOff,
  Settings,
  Zap
} from 'lucide-react';

interface IAMSecurityData {
  overview: {
    totalUsers: number;
    activeUsers: number;
    privilegedUsers: number;
    securityScore: number;
  };
  identityManagement: {
    totalIdentities: number;
    activeIdentities: number;
    pendingApprovals: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  ssoMfa: {
    ssoEnabled: number;
    mfaEnabled: number;
    failedLogins: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  pam: {
    privilegedSessions: number;
    activeSessions: number;
    vaultedCredentials: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  rbac: {
    totalRoles: number;
    activeRoles: number;
    roleViolations: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  auditCompliance: {
    totalEvents: number;
    criticalEvents: number;
    complianceScore: number;
    status: 'healthy' | 'warning' | 'critical';
  };
}

const IAMSecurity: React.FC = () => {
  const [data, setData] = useState<IAMSecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Simulate API call
    const fetchData = async () => {
      try {
        // Mock data - in real app, this would be an API call
        const mockData: IAMSecurityData = {
          overview: {
            totalUsers: 1250,
            activeUsers: 1180,
            privilegedUsers: 45,
            securityScore: 96
          },
          identityManagement: {
            totalIdentities: 1250,
            activeIdentities: 1180,
            pendingApprovals: 12,
            status: 'healthy'
          },
          ssoMfa: {
            ssoEnabled: 1180,
            mfaEnabled: 1150,
            failedLogins: 23,
            status: 'warning'
          },
          pam: {
            privilegedSessions: 67,
            activeSessions: 23,
            vaultedCredentials: 234,
            status: 'healthy'
          },
          rbac: {
            totalRoles: 89,
            activeRoles: 85,
            roleViolations: 3,
            status: 'healthy'
          },
          auditCompliance: {
            totalEvents: 15420,
            criticalEvents: 12,
            complianceScore: 94,
            status: 'healthy'
          }
        };
        
        setData(mockData);
      } catch (error) {
        console.error('Error fetching IAM security data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-500 bg-green-100';
      case 'warning':
        return 'text-yellow-500 bg-yellow-100';
      case 'critical':
        return 'text-red-500 bg-red-100';
      default:
        return 'text-gray-500 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-5 h-5" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5" />;
      case 'critical':
        return <AlertTriangle className="w-5 h-5" />;
      default:
        return <TrendingUp className="w-5 h-5" />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <TrendingUp className="w-4 h-4" /> },
    { id: 'identity-management', label: 'Identity Management', icon: <User className="w-4 h-4" /> },
    { id: 'sso-mfa', label: 'SSO & MFA', icon: <Lock className="w-4 h-4" /> },
    { id: 'pam', label: 'PAM', icon: <Key className="w-4 h-4" /> },
    { id: 'rbac', label: 'RBAC', icon: <Shield className="w-4 h-4" /> },
    { id: 'audit-compliance', label: 'Audit & Compliance', icon: <Zap className="w-4 h-4" /> }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900">Error Loading Data</h3>
          <p className="text-gray-600">Unable to load IAM security data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">IAM Security</h1>
          <p className="text-gray-600">Identity & Access Management with SSO, MFA, PAM, and RBAC</p>
        </div>
        <div className="flex items-center space-x-2">
          <Key className="w-8 h-8 text-blue-600" />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-6"
      >
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Users</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.totalUsers.toLocaleString()}</p>
                </div>
                <Users className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Active Users</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.activeUsers.toLocaleString()}</p>
                </div>
                <CheckCircle className="w-8 h-8 text-green-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Privileged Users</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.privilegedUsers}</p>
                </div>
                <Key className="w-8 h-8 text-red-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.securityScore}%</p>
                </div>
                <TrendingUp className="w-8 h-8 text-purple-600" />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'identity-management' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Identity Management Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.identityManagement.status)}`}>
                  {getStatusIcon(data.identityManagement.status)}
                  <span className="capitalize">{data.identityManagement.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Identities</p>
                  <p className="text-xl font-semibold text-gray-900">{data.identityManagement.totalIdentities.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Identities</p>
                  <p className="text-xl font-semibold text-gray-900">{data.identityManagement.activeIdentities.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Pending Approvals</p>
                  <p className="text-xl font-semibold text-yellow-600">{data.identityManagement.pendingApprovals}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'sso-mfa' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">SSO & MFA Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.ssoMfa.status)}`}>
                  {getStatusIcon(data.ssoMfa.status)}
                  <span className="capitalize">{data.ssoMfa.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">SSO Enabled</p>
                  <p className="text-xl font-semibold text-gray-900">{data.ssoMfa.ssoEnabled.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">MFA Enabled</p>
                  <p className="text-xl font-semibold text-gray-900">{data.ssoMfa.mfaEnabled.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Failed Logins</p>
                  <p className="text-xl font-semibold text-red-600">{data.ssoMfa.failedLogins}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'pam' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">PAM Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.pam.status)}`}>
                  {getStatusIcon(data.pam.status)}
                  <span className="capitalize">{data.pam.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Privileged Sessions</p>
                  <p className="text-xl font-semibold text-gray-900">{data.pam.privilegedSessions}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Sessions</p>
                  <p className="text-xl font-semibold text-blue-600">{data.pam.activeSessions}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Vaulted Credentials</p>
                  <p className="text-xl font-semibold text-gray-900">{data.pam.vaultedCredentials}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'rbac' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">RBAC Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.rbac.status)}`}>
                  {getStatusIcon(data.rbac.status)}
                  <span className="capitalize">{data.rbac.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Roles</p>
                  <p className="text-xl font-semibold text-gray-900">{data.rbac.totalRoles}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Roles</p>
                  <p className="text-xl font-semibold text-gray-900">{data.rbac.activeRoles}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Role Violations</p>
                  <p className="text-xl font-semibold text-red-600">{data.rbac.roleViolations}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'audit-compliance' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Audit & Compliance Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.auditCompliance.status)}`}>
                  {getStatusIcon(data.auditCompliance.status)}
                  <span className="capitalize">{data.auditCompliance.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Events</p>
                  <p className="text-xl font-semibold text-gray-900">{data.auditCompliance.totalEvents.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Critical Events</p>
                  <p className="text-xl font-semibold text-red-600">{data.auditCompliance.criticalEvents}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Compliance Score</p>
                  <p className="text-xl font-semibold text-gray-900">{data.auditCompliance.complianceScore}%</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default IAMSecurity; 