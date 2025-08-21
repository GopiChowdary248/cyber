import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert,
  RefreshControl,
  ActivityIndicator,
  Modal,
} from 'react-native';
import { Card } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

interface CloudResource {
  id: string;
  name: string;
  type: 'ec2' | 's3' | 'rds' | 'lambda' | 'vpc' | 'iam';
  provider: 'aws' | 'azure' | 'gcp';
  region: string;
  status: 'secure' | 'warning' | 'critical' | 'unknown';
  created_at: string;
  last_scan: string;
  compliance_score: number;
  security_issues: number;
  cost: number;
  tags: Record<string, string>;
  risk_score: number;
}

interface SecurityFinding {
  id: string;
  resource_id: string;
  finding_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
  status: 'open' | 'resolved' | 'false_positive';
  created_at: string;
  updated_at: string;
  compliance_frameworks: string[];
  risk_score: number;
}

interface CloudMetrics {
  total_resources: number;
  secure_resources: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  compliance_score_avg: number;
  estimated_cost: number;
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

const CloudSecurityScreen: React.FC = () => {
  const [selectedResource, setSelectedResource] = useState<CloudResource | null>(null);
  const [showFindings, setShowFindings] = useState(false);
  const [showMetrics, setShowMetrics] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<string>('all');
  const [activeTab, setActiveTab] = useState(0);
  const [showAssetDetails, setShowAssetDetails] = useState(false);
  const [showPolicyEditor, setShowPolicyEditor] = useState(false);
  const [showScanTemplateEditor, setShowScanTemplateEditor] = useState(false);
  const [showRemediationEditor, setShowRemediationEditor] = useState(false);
  const [showRiskAssessment, setShowRiskAssessment] = useState(false);

  // Mock data for enhanced functionality
  const [assetRelationships] = useState<AssetRelationship[]>([
    {
      id: '1',
      parent_asset_id: 'ec2-1',
      child_asset_id: 'sg-1',
      relationship_type: 'contains',
      metadata: {},
      created_at: '2024-01-01T00:00:00Z'
    }
  ]);

  const [policyEvaluationResults] = useState<PolicyEvaluationResult[]>([
    {
      id: '1',
      asset_id: 'ec2-1',
      policy_id: 'policy-1',
      result: false,
      evidence: { field: 'security_groups', value: 'open' },
      execution_time_ms: 150,
      evaluation_date: '2024-01-01T00:00:00Z'
    }
  ]);

  const [complianceControls] = useState<ComplianceControl[]>([
    {
      id: '1',
      framework_id: 'cis-aws',
      control_id: 'CIS.1.1',
      title: 'Ensure no root account access key exists',
      description: 'Root account access keys should not exist',
      category: 'Identity and Access Management',
      requirements: [],
      policy_mappings: ['policy-1']
    }
  ]);

  const [scanTemplates] = useState<ScanTemplate[]>([
    {
      id: '1',
      name: 'Daily Security Scan',
      description: 'Comprehensive daily security scan',
      scan_config: { services: ['ec2', 's3', 'iam'] },
      schedule: '0 2 * * *',
      enabled: true,
      created_at: '2024-01-01T00:00:00Z'
    }
  ]);

  const [remediationPlaybooks] = useState<RemediationPlaybook[]>([
    {
      id: '1',
      name: 'S3 Bucket Security Fix',
      description: 'Fix public S3 bucket access',
      category: 'aws',
      steps: [
        { action: 'update_bucket_policy', description: 'Update bucket policy to deny public access' }
      ],
      estimated_time: 15,
      risk_level: 'medium',
      auto_approval: false,
      created_at: '2024-01-01T00:00:00Z'
    }
  ]);

  const [riskAssessments] = useState<RiskAssessment[]>([
    {
      id: '1',
      asset_id: 'ec2-1',
      overall_score: 75,
      factors: { public_exposure: 80, outdated_software: 70 },
      recommendations: [
        { action: 'restrict_access', description: 'Restrict public access' }
      ],
      assessment_date: '2024-01-01T00:00:00Z',
      assessed_by: 'system'
    }
  ]);

  const handleAssetSelect = (resource: CloudResource) => {
    setSelectedResource(resource);
    setShowAssetDetails(true);
  };

  const handleRemediationExecution = async (playbookId: string, findingId: string) => {
    try {
      // Call the remediation execution API
      console.log(`Executing playbook ${playbookId} on finding ${findingId}`);
      Alert.alert('Success', 'Remediation execution initiated');
    } catch (error) {
      Alert.alert('Error', 'Remediation execution failed');
    }
  };

  const renderAssetRelationships = () => (
    <Card style={styles.card}>
      <Card.Title title="Asset Relationships" />
      <Card.Content>
        <View style={styles.spaceY}>
          {assetRelationships.map((relationship) => (
            <View key={relationship.id} style={styles.relationshipItem}>
              <View style={styles.relationshipHeader}>
                <Text style={styles.relationshipType}>{relationship.relationship_type}</Text>
                <Icon name="arrow-right" size={16} color="#666666" />
              </View>
              <Text style={styles.relationshipDetails}>
                {relationship.parent_asset_id} → {relationship.child_asset_id}
              </Text>
              <Text style={styles.relationshipDate}>
                {new Date(relationship.created_at).toLocaleDateString()}
              </Text>
            </View>
          ))}
        </View>
      </Card.Content>
    </Card>
  );

  const renderPolicyEvaluation = () => (
    <Card style={styles.card}>
      <Card.Title title="Policy Evaluation Results" />
      <Card.Content>
        <View style={styles.spaceY}>
          {policyEvaluationResults.map((result) => (
            <View key={result.id} style={styles.evaluationItem}>
              <View style={styles.evaluationHeader}>
                <View style={[
                  styles.evaluationStatus,
                  { backgroundColor: result.result ? '#28a745' : '#dc3545' }
                ]} />
                <Text style={styles.evaluationTitle}>
                  Policy {result.policy_id} on Asset {result.asset_id}
                </Text>
              </View>
              <View style={styles.evaluationDetails}>
                <Text style={styles.evaluationTime}>{result.execution_time_ms}ms</Text>
                <Text style={styles.evaluationDate}>
                  {new Date(result.evaluation_date).toLocaleDateString()}
                </Text>
              </View>
            </View>
          ))}
        </View>
      </Card.Content>
    </Card>
  );

  const renderComplianceControls = () => (
    <Card style={styles.card}>
      <Card.Title title="Compliance Controls" />
      <Card.Content>
        <View style={styles.spaceY}>
          {complianceControls.map((control) => (
            <View key={control.id} style={styles.controlItem}>
              <View style={styles.controlHeader}>
                <Text style={styles.controlId}>{control.control_id}</Text>
                <Text style={styles.controlCategory}>{control.category}</Text>
              </View>
              <Text style={styles.controlTitle}>{control.title}</Text>
              <Text style={styles.controlDescription}>{control.description}</Text>
              <View style={styles.controlMappings}>
                <Text style={styles.mappingCount}>
                  {control.policy_mappings.length} policies mapped
                </Text>
              </View>
            </View>
          ))}
        </View>
      </Card.Content>
    </Card>
  );

  const renderScanTemplates = () => (
    <Card style={styles.card}>
      <Card.Title 
        title="Scan Templates" 
        right={(props) => (
          <TouchableOpacity onPress={() => setShowScanTemplateEditor(true)}>
            <Icon {...props} name="plus" size={24} color="#007AFF" />
          </TouchableOpacity>
        )}
      />
      <Card.Content>
        <View style={styles.spaceY}>
          {scanTemplates.map((template) => (
            <View key={template.id} style={styles.templateItem}>
              <View style={styles.templateHeader}>
                <Text style={styles.templateName}>{template.name}</Text>
                <View style={[
                  styles.templateStatus,
                  { backgroundColor: template.enabled ? '#28a745' : '#6c757d' }
                ]} />
              </View>
              <Text style={styles.templateDescription}>{template.description}</Text>
              {template.schedule && (
                <Text style={styles.templateSchedule}>Schedule: {template.schedule}</Text>
              )}
            </View>
          ))}
        </View>
      </Card.Content>
    </Card>
  );

  const renderRemediationPlaybooks = () => (
    <Card style={styles.card}>
      <Card.Title 
        title="Remediation Playbooks" 
        right={(props) => (
          <TouchableOpacity onPress={() => setShowRemediationEditor(true)}>
            <Icon {...props} name="plus" size={24} color="#28a745" />
          </TouchableOpacity>
        )}
      />
      <Card.Content>
        <View style={styles.spaceY}>
          {remediationPlaybooks.map((playbook) => (
            <View key={playbook.id} style={styles.playbookItem}>
              <View style={styles.playbookHeader}>
                <Text style={styles.playbookName}>{playbook.name}</Text>
                <View style={[
                  styles.riskLevel,
                  { 
                    backgroundColor: 
                      playbook.risk_level === 'high' ? '#dc3545' :
                      playbook.risk_level === 'medium' ? '#ffc107' :
                      '#28a745'
                  }
                ]}>
                  <Text style={styles.riskLevelText}>{playbook.risk_level}</Text>
                </View>
              </View>
              <Text style={styles.playbookDescription}>{playbook.description}</Text>
              <View style={styles.playbookDetails}>
                <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                  <Text style={styles.playbookSteps}>{playbook.steps.length} steps</Text>
                  {playbook.estimated_time && (
                    <Text style={styles.playbookTime}>~{playbook.estimated_time} min</Text>
                  )}
                </View>
                <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                  {playbook.auto_approval && (
                    <Text style={styles.autoApproval}>Auto-approval</Text>
                  )}
                  <TouchableOpacity>
                    <Icon name="pencil" size={16} color="#007AFF" />
                  </TouchableOpacity>
                </View>
              </View>
            </View>
          ))}
        </View>
      </Card.Content>
    </Card>
  );

  const renderRiskAssessments = () => (
    <Card style={styles.card}>
      <Card.Title title="Risk Assessments" />
      <Card.Content>
        <View style={styles.spaceY}>
          {riskAssessments.map((assessment) => (
            <View key={assessment.id} style={styles.assessmentItem}>
              <View style={styles.assessmentHeader}>
                <Text style={styles.assessmentAsset}>Asset {assessment.asset_id}</Text>
                <Text style={[
                  styles.assessmentScore,
                  { 
                    color: 
                      assessment.overall_score >= 70 ? '#dc3545' :
                      assessment.overall_score >= 40 ? '#ffc107' :
                      '#28a745'
                  }
                ]}>
                  Score: {assessment.overall_score}
                </Text>
              </View>
              <Text style={styles.assessmentRecommendations}>
                {assessment.recommendations.length} recommendations
              </Text>
              <Text style={styles.assessmentDate}>
                {new Date(assessment.assessment_date).toLocaleDateString()}
              </Text>
            </View>
          ))}
        </View>
      </Card.Content>
    </Card>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 0: // Overview
        return (
          <View style={styles.spaceY}>
            <Card style={styles.card}>
              <Card.Title title="Cloud Security Overview" />
              <Card.Content>
                <Text>Overview content here</Text>
              </Card.Content>
            </Card>
          </View>
        );
      case 1: // Assets & Relationships
        return (
          <View style={styles.spaceY}>
            {renderAssetRelationships()}
          </View>
        );
      case 2: // Policies & Evaluation
        return (
          <View style={styles.spaceY}>
            {renderPolicyEvaluation()}
          </View>
        );
      case 3: // Compliance
        return (
          <View style={styles.spaceY}>
            {renderComplianceControls()}
          </View>
        );
      case 4: // Scans & Jobs
        return (
          <View style={styles.spaceY}>
            {renderScanTemplates()}
          </View>
        );
      case 5: // Remediation
        return (
          <View style={styles.spaceY}>
            {renderRemediationPlaybooks()}
          </View>
        );
      case 6: // Risk Assessment
        return (
          <View style={styles.spaceY}>
            {renderRiskAssessments()}
          </View>
        );
      default:
        return null;
    }
  };

  return (
    <ScrollView 
      style={styles.container}
      refreshControl={
        <RefreshControl refreshing={false} onRefresh={() => {}} />
      }
    >
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Cloud Security</Text>
        <Text style={styles.headerSubtitle}>Comprehensive cloud security monitoring and remediation</Text>
      </View>

      {/* Tab Navigation */}
      <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.tabContainer}>
        {[
          'Overview',
          'Assets & Relationships',
          'Policies & Evaluation',
          'Compliance',
          'Scans & Jobs',
          'Remediation',
          'Risk Assessment'
        ].map((tab, index) => (
          <TouchableOpacity
            key={tab}
            style={[styles.tab, activeTab === index && styles.activeTab]}
            onPress={() => setActiveTab(index)}
          >
            <Text style={[styles.tabText, activeTab === index && styles.activeTabText]}>
              {tab}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* Tab Content */}
      <View style={styles.content}>
        {renderTabContent()}
      </View>

      {/* Asset Details Modal */}
      <Modal
        visible={showAssetDetails}
        animationType="slide"
        transparent={true}
        onRequestClose={() => setShowAssetDetails(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>Asset Details</Text>
              <TouchableOpacity onPress={() => setShowAssetDetails(false)}>
                <Icon name="close" size={24} color="#666666" />
              </TouchableOpacity>
            </View>
            {selectedResource && (
              <ScrollView style={styles.modalBody}>
                <View style={styles.assetInfo}>
                  <Text style={styles.assetLabel}>Name:</Text>
                  <Text style={styles.assetValue}>{selectedResource.name}</Text>
                  
                  <Text style={styles.assetLabel}>Type:</Text>
                  <Text style={styles.assetValue}>{selectedResource.type}</Text>
                  
                  <Text style={styles.assetLabel}>Provider:</Text>
                  <Text style={styles.assetValue}>{selectedResource.provider}</Text>
                  
                  <Text style={styles.assetLabel}>Risk Score:</Text>
                  <Text style={[
                    styles.assetValue,
                    { 
                      color: 
                        selectedResource.risk_score >= 70 ? '#dc3545' :
                        selectedResource.risk_score >= 40 ? '#ffc107' :
                        '#28a745'
                    }
                  ]}>
                    {selectedResource.risk_score}
                  </Text>
                </View>
              </ScrollView>
            )}
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    flexDirection: 'column',
    alignItems: 'center',
    padding: 16,
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333333',
  },
  headerSubtitle: {
    fontSize: 14,
    color: '#666666',
    marginTop: 4,
  },
  tabContainer: {
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  tab: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 2,
    borderBottomColor: 'transparent',
  },
  activeTab: {
    borderBottomColor: '#007AFF',
  },
  tabText: {
    fontSize: 14,
    color: '#666666',
  },
  activeTabText: {
    color: '#007AFF',
    fontWeight: '600',
  },
  content: {
    padding: 16,
  },
  spaceY: {
    gap: 16,
  },
  card: {
    marginBottom: 16,
  },
  relationshipItem: {
    padding: 12,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
  },
  relationshipHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  relationshipType: {
    fontSize: 14,
    fontWeight: '600',
    marginRight: 8,
  },
  relationshipDetails: {
    fontSize: 14,
    color: '#333333',
    marginBottom: 4,
  },
  relationshipDate: {
    fontSize: 12,
    color: '#666666',
  },
  evaluationItem: {
    padding: 12,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
  },
  evaluationHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  evaluationStatus: {
    width: 12,
    height: 12,
    borderRadius: 6,
    marginRight: 8,
  },
  evaluationTitle: {
    fontSize: 14,
    fontWeight: '600',
  },
  evaluationDetails: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  evaluationTime: {
    fontSize: 12,
    color: '#666666',
  },
  evaluationDate: {
    fontSize: 12,
    color: '#666666',
  },
  controlItem: {
    padding: 12,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
  },
  controlHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  controlId: {
    fontSize: 14,
    fontWeight: '600',
  },
  controlCategory: {
    fontSize: 12,
    color: '#666666',
  },
  controlTitle: {
    fontSize: 14,
    color: '#333333',
    marginBottom: 4,
  },
  controlDescription: {
    fontSize: 12,
    color: '#666666',
    marginBottom: 8,
  },
  controlMappings: {
    alignItems: 'flex-start',
  },
  mappingCount: {
    fontSize: 12,
    color: '#007AFF',
    backgroundColor: '#e3f2fd',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  templateItem: {
    padding: 12,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
  },
  templateHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  templateName: {
    fontSize: 14,
    fontWeight: '600',
  },
  templateStatus: {
    width: 12,
    height: 12,
    borderRadius: 6,
  },
  templateDescription: {
    fontSize: 12,
    color: '#666666',
    marginBottom: 4,
  },
  templateSchedule: {
    fontSize: 12,
    color: '#007AFF',
  },
  playbookItem: {
    padding: 12,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
  },
  playbookHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  playbookName: {
    fontSize: 14,
    fontWeight: '600',
  },
  riskLevel: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  riskLevelText: {
    fontSize: 12,
    color: '#ffffff',
    fontWeight: '600',
  },
  playbookDescription: {
    fontSize: 12,
    color: '#666666',
    marginBottom: 8,
  },
  playbookDetails: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  playbookSteps: {
    fontSize: 12,
    color: '#666666',
  },
  playbookTime: {
    fontSize: 12,
    color: '#666666',
  },
  autoApproval: {
    fontSize: 12,
    color: '#28a745',
    backgroundColor: '#d4edda',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  assessmentItem: {
    padding: 12,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
  },
  assessmentHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  assessmentAsset: {
    fontSize: 14,
    fontWeight: '600',
  },
  assessmentScore: {
    fontSize: 14,
    fontWeight: '600',
  },
  assessmentRecommendations: {
    fontSize: 12,
    color: '#666666',
    marginBottom: 4,
  },
  assessmentDate: {
    fontSize: 12,
    color: '#666666',
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  modalContent: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    width: '90%',
    maxHeight: '80%',
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#333333',
  },
  modalBody: {
    padding: 16,
  },
  assetInfo: {
    gap: 12,
  },
  assetLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#666666',
  },
  assetValue: {
    fontSize: 14,
    color: '#333333',
  },
});

export default CloudSecurityScreen; 