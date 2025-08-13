import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import EnhancedBadge from '../../components/UI/EnhancedBadge';
import EnhancedTabs from '../../components/UI/EnhancedTabs';
import {
  Shield,
  Lock,
  Eye,
  EyeOff,
  Database,
  FileText,
  Users,
  Settings,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Zap,
  Plus,
  Search,
  Filter,
  Download,
  Upload
} from 'lucide-react';

// Interfaces for TypeScript
interface DataClassification {
  id: string;
  name: string;
  description: string;
  sensitivity_level: string;
  retention_period: string;
  encryption_required: boolean;
  access_controls: string[];
  compliance_frameworks: string[];
  created_at: string;
  updated_at: string;
}

interface DataInventory {
  id: string;
  name: string;
  description: string;
  location: string;
  classification: string;
  data_type: string;
  size_gb: number;
  record_count: number;
  last_accessed: string;
  owner: string;
  status: string;
}

interface PrivacyRequest {
  id: string;
  type: string;
  requester_name: string;
  requester_email: string;
  status: string;
  created_at: string;
  completed_at?: string;
  description: string;
  data_subjects: string[];
  processing_basis: string;
}

interface DataBreach {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  discovered_at: string;
  reported_at: string;
  affected_records: number;
  affected_users: number;
  data_types: string[];
  root_cause: string;
  remediation_steps: string[];
}

interface ComplianceReport {
  id: string;
  framework: string;
  status: string;
  score: number;
  last_assessment: string;
  next_assessment: string;
  findings: string[];
  recommendations: string[];
  auditor: string;
}

interface DataProtectionSummary {
  total_datasets: number;
  sensitive_data: number;
  privacy_requests: number;
  active_breaches: number;
  compliance_score: number;
  encryption_coverage: number;
  last_audit: string;
}

const DataProtection: React.FC = () => {
  const [summary, setSummary] = useState<DataProtectionSummary | null>(null);
  const [classifications, setClassifications] = useState<DataClassification[]>([]);
  const [inventory, setInventory] = useState<DataInventory[]>([]);
  const [privacyRequests, setPrivacyRequests] = useState<PrivacyRequest[]>([]);
  const [breaches, setBreaches] = useState<DataBreach[]>([]);
  const [complianceReports, setComplianceReports] = useState<ComplianceReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  // Mock data for demonstration
  useEffect(() => {
    setSummary({
      total_datasets: 156,
      sensitive_data: 23,
      privacy_requests: 8,
      active_breaches: 1,
      compliance_score: 87,
      encryption_coverage: 94,
      last_audit: new Date().toISOString()
    });

    setClassifications([
      {
        id: '1',
        name: 'Personal Identifiable Information (PII)',
        description: 'Data that can be used to identify individuals',
        sensitivity_level: 'high',
        retention_period: '7 years',
        encryption_required: true,
        access_controls: ['role-based', 'multi-factor'],
        compliance_frameworks: ['GDPR', 'CCPA', 'HIPAA'],
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-15T00:00:00Z'
      }
    ]);

    setInventory([
      {
        id: '1',
        name: 'Customer Database',
        description: 'Primary customer information database',
        location: 'AWS RDS',
        classification: 'PII',
        data_type: 'structured',
        size_gb: 45.2,
        record_count: 125000,
        last_accessed: '2024-01-15T10:30:00Z',
        owner: 'Marketing Team',
        status: 'active'
      }
    ]);

    setLoading(false);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'danger';
      case 'high': return 'danger';
      case 'medium': return 'warning';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed': return 'success';
      case 'in_progress': return 'primary';
      case 'pending': return 'warning';
      case 'failed': return 'danger';
      default: return 'default';
    }
  };

  const getComplianceColor = (score: number) => {
    if (score >= 90) return 'success';
    if (score >= 70) return 'warning';
    return 'danger';
  };

  // Define tabs for EnhancedTabs component
  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      content: (
        <div className="space-y-6">
          {summary && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="p-6 border rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium">Total Datasets</h3>
                  <Database className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="text-2xl font-bold mt-2">{summary.total_datasets}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {summary.sensitive_data} sensitive datasets
                </p>
              </div>

              <div className="p-6 border rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium">Privacy Requests</h3>
                  <Users className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="text-2xl font-bold mt-2">{summary.privacy_requests}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {summary.active_breaches} active breaches
                </p>
              </div>

              <div className="p-6 border rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium">Compliance Score</h3>
                  <Shield className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="text-2xl font-bold mt-2">{summary.compliance_score}%</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {summary.encryption_coverage}% encryption coverage
                </p>
              </div>

              <div className="p-6 border rounded-lg shadow-sm">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium">Last Audit</h3>
                  <FileText className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="text-2xl font-bold mt-2">
                  {new Date(summary.last_audit).toLocaleDateString()}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Audit completed
                </p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="p-6 border rounded-lg shadow-sm">
              <h3 className="text-lg font-semibold mb-4">Data Classifications</h3>
              <div className="space-y-3">
                {classifications.slice(0, 5).map((classification) => (
                  <div key={classification.id} className="flex items-center justify-between p-3 border rounded">
                    <div>
                      <div className="font-medium">{classification.name}</div>
                      <p className="text-sm text-muted-foreground">{classification.description}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <EnhancedBadge variant={getSeverityColor(classification.sensitivity_level)}>
                        {classification.sensitivity_level}
                      </EnhancedBadge>
                      {classification.encryption_required && (
                        <Lock className="h-4 w-4 text-green-500" />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-6 border rounded-lg shadow-sm">
              <h3 className="text-lg font-semibold mb-4">Recent Data Inventory</h3>
              <div className="space-y-3">
                {inventory.slice(0, 5).map((item) => (
                  <div key={item.id} className="flex items-center justify-between p-3 border rounded">
                    <div>
                      <div className="font-medium">{item.name}</div>
                      <p className="text-sm text-muted-foreground">{item.location}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <EnhancedBadge variant="default">{item.classification}</EnhancedBadge>
                      <EnhancedBadge variant={getStatusColor(item.status)}>
                        {item.status}
                      </EnhancedBadge>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'classifications',
      label: 'Classifications',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Data Classifications</h3>
            <div className="space-y-3">
              {classifications.map((classification) => (
                <div key={classification.id} className="p-4 border rounded">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium">{classification.name}</div>
                    <div className="flex items-center gap-2">
                      <EnhancedBadge variant={getSeverityColor(classification.sensitivity_level)}>
                        {classification.sensitivity_level}
                      </EnhancedBadge>
                      {classification.encryption_required && (
                        <EnhancedBadge variant="success">Encrypted</EnhancedBadge>
                      )}
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    <p><strong>Description:</strong> {classification.description}</p>
                    <p><strong>Retention Period:</strong> {classification.retention_period}</p>
                    <p><strong>Access Controls:</strong> {classification.access_controls.join(', ')}</p>
                    <p><strong>Compliance:</strong> {classification.compliance_frameworks.join(', ')}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'inventory',
      label: 'Data Inventory',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Data Inventory</h3>
            <div className="space-y-3">
              {inventory.map((item) => (
                <div key={item.id} className="p-4 border rounded">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium">{item.name}</div>
                    <div className="flex items-center gap-2">
                      <EnhancedBadge variant="default">{item.classification}</EnhancedBadge>
                      <EnhancedBadge variant={getStatusColor(item.status)}>
                        {item.status}
                      </EnhancedBadge>
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    <p><strong>Description:</strong> {item.description}</p>
                    <p><strong>Location:</strong> {item.location}</p>
                    <p><strong>Data Type:</strong> {item.data_type}</p>
                    <p><strong>Size:</strong> {item.size_gb} GB ({item.record_count.toLocaleString()} records)</p>
                    <p><strong>Owner:</strong> {item.owner}</p>
                    <p><strong>Last Accessed:</strong> {new Date(item.last_accessed).toLocaleString()}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'privacy',
      label: 'Privacy Requests',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Privacy Requests</h3>
            <p className="text-muted-foreground">Privacy requests functionality coming soon...</p>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'breaches',
      label: 'Data Breaches',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Data Breaches</h3>
            <p className="text-muted-foreground">Data breach management functionality coming soon...</p>
          </div>
        </EnhancedCard>
      )
    },
    {
      id: 'compliance',
      label: 'Compliance',
      content: (
        <EnhancedCard>
          <div className="p-6">
            <h3 className="text-lg font-semibold mb-4">Compliance Reports</h3>
            <p className="text-muted-foreground">Compliance reporting functionality coming soon...</p>
          </div>
        </EnhancedCard>
      )
    }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading data protection information...</div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Data Protection & Privacy</h1>
          <p className="text-muted-foreground">
            Comprehensive data protection, privacy management, and compliance monitoring
          </p>
        </div>
        <EnhancedButton onClick={() => window.location.reload()} variant="outline">
          <Zap className="w-4 h-4 mr-2" />
          Refresh
        </EnhancedButton>
      </div>

      <EnhancedTabs
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        variant="default"
        size="md"
      />
    </div>
  );
};

export default DataProtection; 