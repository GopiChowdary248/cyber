import React, { useState, useEffect } from 'react';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ChartBarIcon,
  ClockIcon,
  CloudIcon,
  ServerIcon,
  DocumentTextIcon,
  CogIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  LinkIcon,
  PlayIcon,
  StopIcon,
  EyeIcon,
  PencilIcon,
  TrashIcon,
  DocumentDuplicateIcon,
  ShieldExclamationIcon,
  CheckBadgeIcon,
  ExclamationCircleIcon
} from '@heroicons/react/24/outline';
import { Tab } from '@headlessui/react';

interface CSPMDashboardProps {
  projectId?: string;
}

interface DashboardSummary {
  total_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  compliance_score: number;
  last_sync?: string;
}

interface RiskHeatmapItem {
  asset_id: string;
  asset_name: string;
  resource_type: string;
  risk_score: number;
  findings_count: number;
  critical_findings: number;
}

interface FindingSummary {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  asset_name: string;
  resource_type: string;
  created_at: string;
  status: string;
}

interface Connector {
  id: string;
  name: string;
  type: 'aws' | 'azure' | 'gcp' | 'oci' | 'kubernetes';
  status: 'pending' | 'connecting' | 'connected' | 'disconnected' | 'error' | 'syncing';
  last_synced?: string;
  project_id: string;
}

interface Asset {
  id: string;
  name?: string;
  resource_type: string;
  cloud?: string;
  region?: string;
  risk_score: number;
  tags?: Record<string, any>;
  last_seen: string;
}

interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  asset_name: string;
  resource_type: string;
  created_at: string;
  description?: string;
}

interface Policy {
  id: string;
  name: string;
  description?: string;
  framework: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  enabled: boolean;
  category?: string;
}

interface AssetRelationship {
  id: string;
  parent_asset_id: string;
  child_asset_id: string;
  relationship_type: string;
  metadata: Record<string, any>;
  created_at: string;
}

interface PolicyEvaluationResult {
  id: string;
  asset_id: string;
  policy_id: string;
  result: boolean;
  evidence: Record<string, any>;
  execution_time_ms: number;
  evaluation_date: string;
}

interface ComplianceControl {
  id: string;
  framework_id: string;
  control_id: string;
  title: string;
  description?: string;
  category?: string;
  requirements: Record<string, any>[];
  policy_mappings: string[];
}

interface ScanTemplate {
  id: string;
  name: string;
  description?: string;
  scan_config: Record<string, any>;
  schedule?: string;
  enabled: boolean;
  created_at: string;
}

interface RemediationPlaybook {
  id: string;
  name: string;
  description?: string;
  category?: string;
  steps: Record<string, any>[];
  estimated_time?: number;
  risk_level: string;
  auto_approval: boolean;
  created_at: string;
}

interface RiskAssessment {
  id: string;
  asset_id: string;
  overall_score: number;
  factors: Record<string, any>;
  recommendations: Record<string, any>[];
  assessment_date: string;
  assessed_by?: string;
}

const EnhancedCSPMDashboard: React.FC<CSPMDashboardProps> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState(0);
  const [dashboardData, setDashboardData] = useState<DashboardSummary | null>(null);
  const [riskHeatmap, setRiskHeatmap] = useState<RiskHeatmapItem[]>([]);
  const [latestFindings, setLatestFindings] = useState<FindingSummary[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [assetRelationships, setAssetRelationships] = useState<AssetRelationship[]>([]);
  const [policyEvaluationResults, setPolicyEvaluationResults] = useState<PolicyEvaluationResult[]>([]);
  const [complianceControls, setComplianceControls] = useState<ComplianceControl[]>([]);
  const [scanTemplates, setScanTemplates] = useState<ScanTemplate[]>([]);
  const [remediationPlaybooks, setRemediationPlaybooks] = useState<RemediationPlaybook[]>([]);
  const [riskAssessments, setRiskAssessments] = useState<RiskAssessment[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [showAssetDetails, setShowAssetDetails] = useState(false);
  const [showPolicyEditor, setShowPolicyEditor] = useState(false);
  const [showScanTemplateEditor, setShowScanTemplateEditor] = useState(false);
  const [showRemediationEditor, setShowRemediationEditor] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    fetchDashboardData();
    fetchConnectors();
    fetchAssets();
    fetchFindings();
    fetchPolicies();
  }, [projectId]);

  const fetchDashboardData = async () => {
    try {
      const response = await fetch(`/api/v1/cspm/dashboard/summary${projectId ? `?project_id=${projectId}` : ''}`);
      if (response.ok) {
        const data = await response.json();
        setDashboardData(data.summary);
        setRiskHeatmap(data.risk_heatmap.items);
        setLatestFindings(data.latest_findings);
      }
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const fetchConnectors = async () => {
    try {
      const response = await fetch(`/api/v1/cspm/connectors${projectId ? `?project_id=${projectId}` : ''}`);
      if (response.ok) {
        const data = await response.json();
        setConnectors(data);
      }
    } catch (error) {
      console.error('Error fetching connectors:', error);
    }
  };

  const fetchAssets = async () => {
    try {
      const response = await fetch(`/api/v1/cspm/assets${projectId ? `?project_id=${projectId}` : ''}`);
      if (response.ok) {
        const data = await response.json();
        setAssets(data.items || []);
      }
    } catch (error) {
      console.error('Error fetching assets:', error);
    }
  };

  const fetchFindings = async () => {
    try {
      const response = await fetch(`/api/v1/cspm/findings${projectId ? `?project_id=${projectId}` : ''}`);
      if (response.ok) {
        const data = await response.json();
        setFindings(data.items || []);
      }
    } catch (error) {
      console.error('Error fetching findings:', error);
    }
  };

  const fetchPolicies = async () => {
    try {
      const response = await fetch('/api/v1/cspm/policies');
      if (response.ok) {
        const data = await response.json();
        setPolicies(data);
      }
    } catch (error) {
      console.error('Error fetching policies:', error);
    }
  };

  const handleSyncConnector = async (connectorId: string) => {
    setSyncing(true);
    try {
      const response = await fetch(`/api/v1/cspm/connectors/${connectorId}/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force: true })
      });
      
      if (response.ok) {
        // Wait a bit then refresh data
        setTimeout(() => {
          fetchDashboardData();
          fetchAssets();
          fetchFindings();
          setSyncing(false);
        }, 3000);
      }
    } catch (error) {
      console.error('Error syncing connector:', error);
      setSyncing(false);
    }
  };

  const handleAssetSelect = (asset: Asset) => {
    setSelectedAsset(asset);
    setShowAssetDetails(true);
  };

  const handlePolicyEvaluation = async (policyId: string, assetId: string) => {
    try {
      setLoading(true);
      // Call the policy evaluation API
      const result = await fetch(`/api/v1/cspm/policies/${policyId}/evaluate?asset_id=${assetId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (result.ok) {
        // Refresh evaluation results
        // You would typically update the UI here
        console.log('Policy evaluation completed');
      }
    } catch (error) {
      console.error('Policy evaluation failed:', error);
      setError('Policy evaluation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRemediationExecution = async (playbookId: string, findingId: string) => {
    try {
      setLoading(true);
      // Call the remediation execution API
      const result = await fetch(`/api/v1/cspm/remediation/playbooks/${playbookId}/execute?finding_id=${findingId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (result.ok) {
        // Refresh findings
        // You would typically update the UI here
        console.log('Remediation execution initiated');
      }
    } catch (error) {
      console.error('Remediation execution failed:', error);
      setError('Remediation execution failed');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'text-green-600 bg-green-100';
      case 'connecting':
      case 'syncing':
        return 'text-blue-600 bg-blue-100';
      case 'pending':
        return 'text-yellow-600 bg-yellow-100';
      case 'disconnected':
      case 'error':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-100';
      case 'high':
        return 'text-orange-600 bg-orange-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      case 'low':
        return 'text-blue-600 bg-blue-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getCloudIcon = (cloud: string) => {
    switch (cloud?.toLowerCase()) {
      case 'aws':
        return '☁️ AWS';
      case 'azure':
        return '☁️ Azure';
      case 'gcp':
        return '☁️ GCP';
      case 'oci':
        return '☁️ OCI';
      case 'kubernetes':
        return '⚙️ K8s';
      default:
        return '☁️ Cloud';
    }
  };

  const renderRiskAssessments = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <ExclamationCircleIcon className="h-5 w-5 mr-2" />
        Risk Assessments
      </h3>
      <div className="space-y-3">
        {riskAssessments.map((assessment) => (
          <div key={assessment.id} className="p-3 bg-gray-50 rounded">
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium">Asset {assessment.asset_id}</span>
              <span className={`text-sm font-semibold ${
                assessment.overall_score >= 70 ? 'text-red-600' :
                assessment.overall_score >= 40 ? 'text-yellow-600' :
                'text-green-600'
              }`}>
                Score: {assessment.overall_score}
              </span>
            </div>
            <div className="text-sm text-gray-600 mb-2">
              {assessment.recommendations.length} recommendations
            </div>
            <span className="text-xs text-gray-400">
              {new Date(assessment.assessment_date).toLocaleDateString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );

  const renderAssetRelationships = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <LinkIcon className="h-5 w-5 mr-2" />
        Asset Relationships
      </h3>
      <div className="space-y-3">
        {assetRelationships.map((relationship) => (
          <div key={relationship.id} className="flex items-center justify-between p-3 bg-gray-50 rounded">
            <div className="flex items-center space-x-3">
              <span className="text-sm font-medium">{relationship.relationship_type}</span>
              <span className="text-gray-500">→</span>
              <span className="text-sm">{relationship.child_asset_id}</span>
            </div>
            <span className="text-xs text-gray-400">
              {new Date(relationship.created_at).toLocaleDateString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );

  const renderPolicyEvaluation = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <CheckBadgeIcon className="h-5 w-5 mr-2" />
        Policy Evaluation Results
      </h3>
      <div className="space-y-3">
        {policyEvaluationResults.map((result) => (
          <div key={result.id} className="flex items-center justify-between p-3 bg-gray-50 rounded">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 rounded-full ${result.result ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm font-medium">Policy {result.policy_id}</span>
              <span className="text-sm text-gray-500">on Asset {result.asset_id}</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs text-gray-400">{result.execution_time_ms}ms</span>
              <span className="text-xs text-gray-400">
                {new Date(result.evaluation_date).toLocaleDateString()}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderComplianceControls = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <ShieldExclamationIcon className="h-5 w-5 mr-2" />
        Compliance Controls
      </h3>
      <div className="space-y-3">
        {complianceControls.map((control) => (
          <div key={control.id} className="p-3 bg-gray-50 rounded">
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium">{control.control_id}</span>
              <span className="text-sm text-gray-500">{control.category}</span>
            </div>
            <p className="text-sm text-gray-600 mb-2">{control.title}</p>
            <div className="flex items-center space-x-2">
              <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">
                {control.policy_mappings.length} policies
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderScanTemplates = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center">
          <DocumentDuplicateIcon className="h-5 w-5 mr-2" />
          Scan Templates
        </h3>
        <button
          onClick={() => setShowScanTemplateEditor(true)}
          className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
        >
          <PlusIcon className="h-4 w-4 inline mr-1" />
          New Template
        </button>
      </div>
      <div className="space-y-3">
        {scanTemplates.map((template) => (
          <div key={template.id} className="flex items-center justify-between p-3 bg-gray-50 rounded">
            <div>
              <h4 className="font-medium">{template.name}</h4>
              <p className="text-sm text-gray-600">{template.description}</p>
              {template.schedule && (
                <span className="text-xs text-gray-500">Schedule: {template.schedule}</span>
              )}
            </div>
            <div className="flex items-center space-x-2">
              <div className={`w-3 h-3 rounded-full ${template.enabled ? 'bg-green-500' : 'bg-gray-400'}`} />
              <button className="text-blue-600 hover:text-blue-800">
                <PencilIcon className="h-4 w-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderRemediationPlaybooks = () => (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center">
          <PlayIcon className="h-5 w-5 mr-2" />
          Remediation Playbooks
        </h3>
        <button
          onClick={() => setShowRemediationEditor(true)}
          className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700"
        >
          <PlusIcon className="h-4 w-4 inline mr-1" />
          New Playbook
        </button>
      </div>
      <div className="space-y-3">
        {remediationPlaybooks.map((playbook) => (
          <div key={playbook.id} className="p-3 bg-gray-50 rounded">
            <div className="flex items-center justify-between mb-2">
              <h4 className="font-medium">{playbook.name}</h4>
              <span className={`text-xs px-2 py-1 rounded ${
                playbook.risk_level === 'high' ? 'bg-red-100 text-red-800' :
                playbook.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                'bg-green-100 text-green-800'
              }`}>
                {playbook.risk_level}
              </span>
            </div>
            <p className="text-sm text-gray-600 mb-2">{playbook.description}</p>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="text-xs text-gray-500">{playbook.steps.length} steps</span>
                {playbook.estimated_time && (
                  <span className="text-xs text-gray-500">~{playbook.estimated_time} min</span>
                )}
              </div>
              <div className="flex items-center space-x-1">
                {playbook.auto_approval && (
                  <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded">Auto</span>
                )}
                <button className="text-blue-600 hover:text-blue-800">
                  <PencilIcon className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="flex">
          <ExclamationTriangleIcon className="h-5 w-5 text-red-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error</h3>
            <div className="mt-2 text-sm text-red-700">{error}</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Cloud Security Posture Management</h1>
          <p className="mt-2 text-gray-600">
            Comprehensive cloud security monitoring, compliance, and remediation
          </p>
        </div>

        {/* Main Dashboard */}
        <Tab.Group selectedIndex={activeTab} onChange={setActiveTab}>
          <Tab.List className="flex space-x-1 rounded-xl bg-blue-900/20 p-1 mb-6">
            <Tab className={({ selected }) =>
              `w-full rounded-lg py-2.5 text-sm font-medium leading-5 ${
                selected
                  ? 'bg-white text-blue-700 shadow'
                  : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
              }`
            }>
              Dashboard
            </Tab>
            <Tab className={({ selected }) =>
              `w-full rounded-lg py-2.5 text-sm font-medium leading-5 ${
                selected
                  ? 'bg-white text-blue-700 shadow'
                  : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
              }`
            }>
              Assets & Relationships
            </Tab>
            <Tab className={({ selected }) =>
              `w-full rounded-lg py-2.5 text-sm font-medium leading-5 ${
                selected
                  ? 'bg-white text-blue-700 shadow'
                  : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
              }`
            }>
              Policies & Evaluation
            </Tab>
            <Tab className={({ selected }) =>
              `w-full rounded-lg py-2.5 text-sm font-medium leading-5 ${
                selected
                  ? 'bg-white text-blue-700 shadow'
                  : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
              }`
            }>
              Compliance
            </Tab>
            <Tab className={({ selected }) =>
              `w-full rounded-lg py-2.5 text-sm font-medium leading-5 ${
                selected
                  ? 'bg-white text-blue-700 shadow'
                  : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
              }`
            }>
              Scans & Jobs
            </Tab>
            <Tab className={({ selected }) =>
              `w-full rounded-lg py-2.5 text-sm font-medium leading-5 ${
                selected
                  ? 'bg-white text-blue-700 shadow'
                  : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
              }`
            }>
              Remediation
            </Tab>
            <Tab className={({ selected }) =>
              `w-full rounded-lg py-2.5 text-sm font-medium leading-5 ${
                selected
                  ? 'bg-white text-blue-700 shadow'
                  : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
              }`
            }>
              Risk Assessment
            </Tab>
          </Tab.List>

          <Tab.Panels className="mt-2">
            {/* Dashboard Tab */}
            <Tab.Panel className="space-y-6">
              {/* Existing dashboard content */}
              {/* Dashboard Summary Cards */}
              {dashboardData && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="bg-white shadow rounded-lg p-6">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <ServerIcon className="h-8 w-8 text-blue-600" />
                      </div>
                      <div className="ml-4">
                        <p className="text-sm font-medium text-gray-500">Total Assets</p>
                        <p className="text-2xl font-semibold text-gray-900">{dashboardData.total_assets}</p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white shadow rounded-lg p-6">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
                      </div>
                      <div className="ml-4">
                        <p className="text-sm font-medium text-gray-500">Total Findings</p>
                        <p className="text-2xl font-semibold text-gray-900">{dashboardData.total_findings}</p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white shadow rounded-lg p-6">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <ShieldCheckIcon className="h-8 w-8 text-green-600" />
                      </div>
                      <div className="ml-4">
                        <p className="text-sm font-medium text-gray-500">Compliance Score</p>
                        <p className="text-2xl font-semibold text-gray-900">{dashboardData.compliance_score}%</p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white shadow rounded-lg p-6">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <ClockIcon className="h-8 w-8 text-gray-600" />
                      </div>
                      <div className="ml-4">
                        <p className="text-sm font-medium text-gray-500">Last Sync</p>
                        <p className="text-sm font-semibold text-gray-900">
                          {dashboardData.last_sync ? new Date(dashboardData.last_sync).toLocaleDateString() : 'Never'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Risk Distribution */}
              {dashboardData && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-white shadow rounded-lg p-6">
                    <h3 className="text-lg font-medium text-gray-900 mb-4">Risk Distribution</h3>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600">Critical</span>
                        <span className="text-sm font-medium text-red-600">{dashboardData.critical_findings}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600">High</span>
                        <span className="text-sm font-medium text-orange-600">{dashboardData.high_findings}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600">Medium</span>
                        <span className="text-sm font-medium text-yellow-600">{dashboardData.medium_findings}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600">Low</span>
                        <span className="text-sm font-medium text-blue-600">{dashboardData.low_findings}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white shadow rounded-lg p-6">
                    <h3 className="text-lg font-medium text-gray-900 mb-4">Top Misconfigurations</h3>
                    <div className="space-y-2">
                      {latestFindings.slice(0, 5).map((finding) => (
                        <div key={finding.id} className="flex items-center justify-between text-sm">
                          <span className="text-gray-600 truncate">{finding.title}</span>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(finding.severity || 'info')}`}>
                            {finding.severity}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </Tab.Panel>

            {/* Assets & Relationships Tab */}
            <Tab.Panel className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Assets List */}
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">Cloud Assets</h3>
                  <div className="space-y-3">
                    {assets.map((asset) => (
                      <div
                        key={asset.id}
                        onClick={() => handleAssetSelect(asset)}
                        className="p-3 bg-gray-50 rounded cursor-pointer hover:bg-gray-100"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <h4 className="font-medium">{asset.name || asset.resource_type}</h4>
                            <p className="text-sm text-gray-600">{asset.resource_type}</p>
                          </div>
                          <div className="text-right">
                            <span className={`text-sm font-semibold ${
                              asset.risk_score >= 70 ? 'text-red-600' :
                              asset.risk_score >= 40 ? 'text-yellow-600' :
                              'text-green-600'
                            }`}>
                              {asset.risk_score}
                            </span>
                            <p className="text-xs text-gray-500">{asset.cloud}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Asset Relationships */}
                {renderAssetRelationships()}
              </div>
            </Tab.Panel>

            {/* Policies & Evaluation Tab */}
            <Tab.Panel className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Policies List */}
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">Security Policies</h3>
                  <div className="space-y-3">
                    {policies.map((policy) => (
                      <div key={policy.id} className="p-3 bg-gray-50 rounded">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">{policy.name}</h4>
                          <span className={`text-xs px-2 py-1 rounded ${
                            policy.severity === 'critical' ? 'bg-red-100 text-red-800' :
                            policy.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            policy.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {policy.severity}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{policy.description}</p>
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-gray-500">{policy.framework}</span>
                          <div className="flex items-center space-x-2">
                            <button
                              onClick={() => handlePolicyEvaluation(policy.id, selectedAsset?.id || '')}
                              disabled={!selectedAsset}
                              className="text-blue-600 hover:text-blue-800 disabled:text-gray-400"
                            >
                              <CheckBadgeIcon className="h-4 w-4" />
                            </button>
                            <button className="text-blue-600 hover:text-blue-800">
                              <PencilIcon className="h-4 w-4" />
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Policy Evaluation Results */}
                {renderPolicyEvaluation()}
              </div>
            </Tab.Panel>

            {/* Compliance Tab */}
            <Tab.Panel className="space-y-6">
              {renderComplianceControls()}
            </Tab.Panel>

            {/* Scans & Jobs Tab */}
            <Tab.Panel className="space-y-6">
              {renderScanTemplates()}
            </Tab.Panel>

            {/* Remediation Tab */}
            <Tab.Panel className="space-y-6">
              {renderRemediationPlaybooks()}
            </Tab.Panel>

            {/* Risk Assessment Tab */}
            <Tab.Panel className="space-y-6">
              {renderRiskAssessments()}
            </Tab.Panel>
          </Tab.Panels>
        </Tab.Group>

        {/* Asset Details Modal */}
        {showAssetDetails && selectedAsset && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Asset Details</h3>
                <button
                  onClick={() => setShowAssetDetails(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <XCircleIcon className="h-6 w-6" />
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium">Basic Information</h4>
                  <div className="grid grid-cols-2 gap-4 mt-2">
                    <div>
                      <span className="text-sm text-gray-500">Name:</span>
                      <p className="font-medium">{selectedAsset.name || 'N/A'}</p>
                    </div>
                    <div>
                      <span className="text-sm text-gray-500">Type:</span>
                      <p className="font-medium">{selectedAsset.resource_type}</p>
                    </div>
                    <div>
                      <span className="text-sm text-gray-500">Cloud:</span>
                      <p className="font-medium">{selectedAsset.cloud || 'N/A'}</p>
                    </div>
                    <div>
                      <span className="text-sm text-gray-500">Risk Score:</span>
                      <p className={`font-medium ${
                        selectedAsset.risk_score >= 70 ? 'text-red-600' :
                        selectedAsset.risk_score >= 40 ? 'text-yellow-600' :
                        'text-green-600'
                      }`}>
                        {selectedAsset.risk_score}
                      </p>
                    </div>
                  </div>
                </div>

                {selectedAsset.tags && Object.keys(selectedAsset.tags).length > 0 && (
                  <div>
                    <h4 className="font-medium">Tags</h4>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {Object.entries(selectedAsset.tags).map(([key, value]) => (
                        <span key={key} className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">
                          {key}: {value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <h4 className="font-medium">Timeline</h4>
                  <div className="space-y-2 mt-2">
                    <div className="flex justify-between text-sm">
                      <span>First Seen:</span>
                      <span>{new Date(selectedAsset.last_seen).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Last Seen:</span>
                      <span>{new Date(selectedAsset.last_seen).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EnhancedCSPMDashboard;
