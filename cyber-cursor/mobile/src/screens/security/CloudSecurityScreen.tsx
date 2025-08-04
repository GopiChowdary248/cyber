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
} from 'react-native';
import { Card, Button, Chip, ProgressBar, Divider, Switch } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { COLORS, SIZES, FONTS } from '../../constants/theme';

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

const CloudSecurityScreen: React.FC = () => {
  const [selectedResource, setSelectedResource] = useState<CloudResource | null>(null);
  const [showFindings, setShowFindings] = useState(false);
  const [showMetrics, setShowMetrics] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<string>('all');
  const queryClient = useQueryClient();

  // Fetch cloud resources
  const { data: resources, isLoading: resourcesLoading, refetch: refetchResources } = useQuery({
    queryKey: ['cloud-resources', selectedProvider],
    queryFn: async () => {
      const url = selectedProvider === 'all' 
        ? 'http://localhost:8000/api/v1/cloud-security/resources'
        : `http://localhost:8000/api/v1/cloud-security/resources?provider=${selectedProvider}`;
      const response = await fetch(url);
      if (!response.ok) throw new Error('Failed to fetch resources');
      return response.json();
    },
  });

  // Fetch findings for selected resource
  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['cloud-findings', selectedResource?.id],
    queryFn: async () => {
      if (!selectedResource) return [];
      const response = await fetch(`http://localhost:8000/api/v1/cloud-security/resources/${selectedResource.id}/findings`);
      if (!response.ok) throw new Error('Failed to fetch findings');
      return response.json();
    },
    enabled: !!selectedResource,
  });

  // Fetch cloud security metrics
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['cloud-metrics'],
    queryFn: async () => {
      const response = await fetch('http://localhost:8000/api/v1/cloud-security/metrics');
      if (!response.ok) throw new Error('Failed to fetch metrics');
      return response.json();
    },
  });

  // Resolve finding mutation
  const resolveFindingMutation = useMutation({
    mutationFn: async ({ findingId, status }: { findingId: string; status: string }) => {
      const response = await fetch(`http://localhost:8000/api/v1/cloud-security/findings/${findingId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      if (!response.ok) throw new Error('Failed to update finding');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-findings'] });
      queryClient.invalidateQueries({ queryKey: ['cloud-metrics'] });
      Alert.alert('Success', 'Finding status updated');
    },
    onError: (error) => {
      Alert.alert('Error', 'Failed to update finding status');
    },
  });

  const handleResolveFinding = (findingId: string) => {
    resolveFindingMutation.mutate({ findingId, status: 'resolved' });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#FF4444';
      case 'high': return '#FF8800';
      case 'medium': return '#FFCC00';
      case 'low': return '#00CC00';
      case 'info': return '#0088FF';
      default: return COLORS.gray;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'secure': return '#00CC00';
      case 'warning': return '#FFCC00';
      case 'critical': return '#FF4444';
      default: return COLORS.gray;
    }
  };

  const getResourceIcon = (type: string) => {
    switch (type) {
      case 'ec2': return 'server';
      case 's3': return 'database';
      case 'rds': return 'database-outline';
      case 'lambda': return 'function-variant';
      case 'vpc': return 'network';
      case 'iam': return 'account-key';
      default: return 'cloud';
    }
  };

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case 'aws': return 'aws';
      case 'azure': return 'microsoft-azure';
      case 'gcp': return 'google-cloud';
      default: return 'cloud';
    }
  };

  const renderResourceCard = (resource: CloudResource) => (
    <Card key={resource.id} style={styles.resourceCard}>
      <Card.Content>
        <View style={styles.resourceHeader}>
          <View style={styles.resourceInfo}>
            <View style={styles.resourceTitleRow}>
              <Icon name={getResourceIcon(resource.type)} size={20} color={COLORS.primary} />
              <Text style={styles.resourceName}>{resource.name}</Text>
            </View>
            <View style={styles.resourceMeta}>
              <Icon name={getProviderIcon(resource.provider)} size={16} color={COLORS.gray} />
              <Text style={styles.resourceType}>{resource.type.toUpperCase()}</Text>
              <Text style={styles.resourceRegion}>{resource.region}</Text>
            </View>
          </View>
          <Chip
            mode="outlined"
            textStyle={{ color: getStatusColor(resource.status) }}
            style={{ borderColor: getStatusColor(resource.status) }}
          >
            {resource.status.toUpperCase()}
          </Chip>
        </View>
        
        <View style={styles.resourceStats}>
          <View style={styles.statItem}>
            <Text style={styles.statNumber}>{resource.compliance_score}%</Text>
            <Text style={styles.statLabel}>Compliance</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FF4444' }]}>
              {resource.security_issues}
            </Text>
            <Text style={styles.statLabel}>Issues</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statNumber}>${resource.cost}</Text>
            <Text style={styles.statLabel}>Cost/Month</Text>
          </View>
        </View>

        <View style={styles.resourceDetails}>
          <Text style={styles.resourceDetail}>
            <Icon name="calendar" size={16} color={COLORS.gray} />
            Created: {new Date(resource.created_at).toLocaleDateString()}
          </Text>
          <Text style={styles.resourceDetail}>
            <Icon name="shield-scan" size={16} color={COLORS.gray} />
            Last scan: {new Date(resource.last_scan).toLocaleDateString()}
          </Text>
        </View>
      </Card.Content>
      
      <Card.Actions>
        <Button
          mode="outlined"
          onPress={() => setSelectedResource(resource)}
          style={styles.actionButton}
        >
          View Details
        </Button>
        <Button
          mode="contained"
          onPress={() => setShowFindings(true)}
          style={styles.actionButton}
        >
          View Findings
        </Button>
      </Card.Actions>
    </Card>
  );

  const renderFindingCard = (finding: SecurityFinding) => (
    <Card key={finding.id} style={styles.findingCard}>
      <Card.Content>
        <View style={styles.findingHeader}>
          <Text style={styles.findingTitle}>{finding.title}</Text>
          <View style={styles.findingBadges}>
            <Chip
              mode="outlined"
              textStyle={{ color: getSeverityColor(finding.severity) }}
              style={{ borderColor: getSeverityColor(finding.severity), marginRight: 8 }}
            >
              {finding.severity.toUpperCase()}
            </Chip>
            <Chip
              mode="outlined"
              textStyle={{ color: finding.status === 'resolved' ? '#00CC00' : '#FF8800' }}
              style={{ borderColor: finding.status === 'resolved' ? '#00CC00' : '#FF8800' }}
            >
              {finding.status.toUpperCase()}
            </Chip>
          </View>
        </View>
        
        <Text style={styles.findingDescription}>{finding.description}</Text>
        
        <View style={styles.findingDetails}>
          <Text style={styles.findingDetail}>
            <Icon name="clock" size={16} color={COLORS.gray} />
            {new Date(finding.created_at).toLocaleDateString()}
          </Text>
          <Text style={styles.findingDetail}>
            <Icon name="shield-check" size={16} color={COLORS.gray} />
            {finding.compliance_frameworks.join(', ')}
          </Text>
        </View>
        
        <Divider style={styles.divider} />
        
        <Text style={styles.recommendationTitle}>Recommendation:</Text>
        <Text style={styles.recommendationText}>{finding.recommendation}</Text>
        
        {finding.status === 'open' && (
          <Button
            mode="contained"
            onPress={() => handleResolveFinding(finding.id)}
            loading={resolveFindingMutation.isPending}
            style={styles.resolveButton}
          >
            Mark as Resolved
          </Button>
        )}
      </Card.Content>
    </Card>
  );

  const renderMetricsCard = () => (
    <Card style={styles.metricsCard}>
      <Card.Content>
        <Text style={styles.metricsTitle}>Cloud Security Overview</Text>
        
        <View style={styles.metricsGrid}>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.total_resources || 0}</Text>
            <Text style={styles.metricLabel}>Total Resources</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.secure_resources || 0}</Text>
            <Text style={styles.metricLabel}>Secure Resources</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.critical_findings || 0}</Text>
            <Text style={styles.metricLabel}>Critical Findings</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.high_findings || 0}</Text>
            <Text style={styles.metricLabel}>High Findings</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>{metrics?.compliance_score_avg || 0}%</Text>
            <Text style={styles.metricLabel}>Avg Compliance</Text>
          </View>
          <View style={styles.metricItem}>
            <Text style={styles.metricValue}>${metrics?.estimated_cost || 0}</Text>
            <Text style={styles.metricLabel}>Monthly Cost</Text>
          </View>
        </View>
      </Card.Content>
    </Card>
  );

  const renderProviderFilter = () => (
    <View style={styles.filterContainer}>
      <Text style={styles.filterTitle}>Filter by Provider:</Text>
      <View style={styles.filterButtons}>
        <Button
          mode={selectedProvider === 'all' ? 'contained' : 'outlined'}
          onPress={() => setSelectedProvider('all')}
          style={styles.filterButton}
        >
          All
        </Button>
        <Button
          mode={selectedProvider === 'aws' ? 'contained' : 'outlined'}
          onPress={() => setSelectedProvider('aws')}
          style={styles.filterButton}
        >
          AWS
        </Button>
        <Button
          mode={selectedProvider === 'azure' ? 'contained' : 'outlined'}
          onPress={() => setSelectedProvider('azure')}
          style={styles.filterButton}
        >
          Azure
        </Button>
        <Button
          mode={selectedProvider === 'gcp' ? 'contained' : 'outlined'}
          onPress={() => setSelectedProvider('gcp')}
          style={styles.filterButton}
        >
          GCP
        </Button>
      </View>
    </View>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Cloud Security</Text>
        <Button
          mode="contained"
          onPress={() => setShowMetrics(!showMetrics)}
          style={styles.metricsButton}
        >
          {showMetrics ? 'Hide Metrics' : 'Show Metrics'}
        </Button>
      </View>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={resourcesLoading} onRefresh={refetchResources} />
        }
      >
        {renderProviderFilter()}

        {showMetrics && renderMetricsCard()}

        {resourcesLoading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color={COLORS.primary} />
            <Text style={styles.loadingText}>Loading cloud resources...</Text>
          </View>
        ) : (
          <>
            <View style={styles.statsContainer}>
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Total Resources</Text>
                  <Text style={styles.statValue}>{resources?.length || 0}</Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Secure Resources</Text>
                  <Text style={styles.statValue}>
                    {resources?.filter(r => r.status === 'secure').length || 0}
                  </Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Critical Issues</Text>
                  <Text style={styles.statValue}>
                    {resources?.reduce((sum, resource) => sum + resource.security_issues, 0) || 0}
                  </Text>
                </Card.Content>
              </Card>
            </View>

            <Text style={styles.sectionTitle}>Cloud Resources</Text>
            
            {resources?.map(renderResourceCard) || (
              <Card style={styles.emptyCard}>
                <Card.Content>
                  <Text style={styles.emptyText}>No cloud resources found</Text>
                  <Text style={styles.emptySubtext}>
                    Connect your cloud accounts to start monitoring security
                  </Text>
                </Card.Content>
              </Card>
            )}

            {showFindings && selectedResource && (
              <View style={styles.findingsSection}>
                <View style={styles.sectionHeader}>
                  <Text style={styles.sectionTitle}>
                    Security Findings - {selectedResource.name}
                  </Text>
                  <TouchableOpacity
                    onPress={() => setShowFindings(false)}
                    style={styles.closeButton}
                  >
                    <Icon name="close" size={24} color={COLORS.white} />
                  </TouchableOpacity>
                </View>
                
                {findingsLoading ? (
                  <ActivityIndicator size="large" color={COLORS.primary} />
                ) : (
                  findings?.map(renderFindingCard) || (
                    <Text style={styles.emptyText}>No security findings detected</Text>
                  )
                )}
              </View>
            )}
          </>
        )}
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.dark,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    backgroundColor: COLORS.dark,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  headerTitle: {
    fontSize: 24,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  metricsButton: {
    backgroundColor: COLORS.primary,
  },
  content: {
    flex: 1,
    padding: 16,
  },
  filterContainer: {
    marginBottom: 16,
  },
  filterTitle: {
    fontSize: 16,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 8,
  },
  filterButtons: {
    flexDirection: 'row',
    flexWrap: 'wrap',
  },
  filterButton: {
    marginRight: 8,
    marginBottom: 8,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    color: COLORS.white,
    fontSize: 16,
    marginTop: 16,
  },
  metricsCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  metricsTitle: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 16,
  },
  metricsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  metricItem: {
    width: '48%',
    alignItems: 'center',
    marginBottom: 16,
  },
  metricValue: {
    fontSize: 24,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  metricLabel: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    textAlign: 'center',
    marginTop: 4,
  },
  statsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 24,
  },
  statCard: {
    flex: 1,
    marginHorizontal: 4,
    backgroundColor: COLORS.card,
  },
  statTitle: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  statValue: {
    fontSize: 24,
    color: COLORS.white,
    fontFamily: FONTS.bold,
    marginTop: 4,
  },
  sectionTitle: {
    fontSize: 20,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 16,
  },
  resourceCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  resourceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  resourceInfo: {
    flex: 1,
  },
  resourceTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 4,
  },
  resourceName: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginLeft: 8,
  },
  resourceMeta: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  resourceType: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginLeft: 4,
  },
  resourceRegion: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginLeft: 8,
  },
  resourceStats: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  statItem: {
    alignItems: 'center',
  },
  statNumber: {
    fontSize: 20,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  statLabel: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  resourceDetails: {
    marginBottom: 12,
  },
  resourceDetail: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginBottom: 4,
  },
  actionButton: {
    marginRight: 8,
  },
  emptyCard: {
    backgroundColor: COLORS.card,
    alignItems: 'center',
    padding: 32,
  },
  emptyText: {
    fontSize: 16,
    color: COLORS.white,
    fontFamily: FONTS.medium,
    textAlign: 'center',
  },
  emptySubtext: {
    fontSize: 14,
    color: COLORS.gray,
    fontFamily: FONTS.regular,
    textAlign: 'center',
    marginTop: 8,
  },
  findingsSection: {
    marginTop: 24,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  closeButton: {
    padding: 8,
  },
  findingCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  findingHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  findingTitle: {
    fontSize: 16,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    flex: 1,
    marginRight: 12,
  },
  findingBadges: {
    flexDirection: 'row',
  },
  findingDescription: {
    fontSize: 14,
    color: COLORS.lightGray,
    fontFamily: FONTS.regular,
    marginBottom: 12,
  },
  findingDetails: {
    marginBottom: 12,
  },
  findingDetail: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginBottom: 4,
  },
  divider: {
    marginVertical: 12,
    backgroundColor: COLORS.border,
  },
  recommendationTitle: {
    fontSize: 14,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 8,
  },
  recommendationText: {
    fontSize: 12,
    color: COLORS.lightGray,
    fontFamily: FONTS.regular,
    marginBottom: 12,
  },
  resolveButton: {
    backgroundColor: COLORS.primary,
  },
});

export default CloudSecurityScreen; 