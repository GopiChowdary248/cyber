import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  RefreshControl,
  Alert,
} from 'react-native';
import { LinearGradient } from 'react-native-linear-gradient';
import { Card, Title, Paragraph, Button, Chip, FAB, Portal, Dialog } from 'react-native-paper';
import { BarChart, PieChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService, CloudResource, SecurityFinding } from '../services/APIService';
import { Dimensions } from 'react-native';

const { width } = Dimensions.get('window');

const CloudSecurityScreen: React.FC = ({ navigation }: any) => {
  const [resources, setResources] = useState<CloudResource[]>([]);
  const [selectedResource, setSelectedResource] = useState<CloudResource | null>(null);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [findingDetailsModal, setFindingDetailsModal] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<string>('all');

  const apiService = new APIService();

  const fetchResources = async () => {
    try {
      setLoading(true);
      const [resourcesData, metricsData] = await Promise.all([
        apiService.getCloudResources(selectedProvider === 'all' ? undefined : selectedProvider),
        apiService.getCloudMetrics(),
      ]);
      setResources(resourcesData);
      setMetrics(metricsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch cloud resources');
    } finally {
      setLoading(false);
    }
  };

  const fetchFindings = async (resourceId: string) => {
    try {
      const findingsData = await apiService.getCloudFindings(resourceId);
      setFindings(findingsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch security findings');
    }
  };

  const updateFindingStatus = async (findingId: string, status: string) => {
    try {
      await apiService.updateFindingStatus(findingId, status);
      if (selectedResource) {
        fetchFindings(selectedResource.id);
      }
      Alert.alert('Success', 'Finding status updated successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to update finding status');
    }
  };

  useEffect(() => {
    fetchResources();
  }, [selectedProvider]);

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchResources();
    setRefreshing(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'secure': return '#4CAF50';
      case 'warning': return '#FF9800';
      case 'critical': return '#F44336';
      case 'unknown': return '#9E9E9E';
      default: return '#9E9E9E';
    }
  };

  const getResourceTypeColor = (type: string) => {
    switch (type) {
      case 'ec2': return '#FF5722';
      case 's3': return '#2196F3';
      case 'rds': return '#4CAF50';
      case 'lambda': return '#9C27B0';
      case 'vpc': return '#FF9800';
      case 'iam': return '#607D8B';
      default: return '#9E9E9E';
    }
  };

  const getProviderColor = (provider: string) => {
    switch (provider) {
      case 'aws': return '#FF9900';
      case 'azure': return '#0078D4';
      case 'gcp': return '#4285F4';
      default: return '#9E9E9E';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FF9800';
      case 'low': return '#4CAF50';
      case 'info': return '#2196F3';
      default: return '#9E9E9E';
    }
  };

  const chartConfig = {
    backgroundColor: '#1cc910',
    backgroundGradientFrom: '#1cc910',
    backgroundGradientTo: '#1cc910',
    decimalPlaces: 0,
    color: (opacity = 1) => `rgba(255, 255, 255, ${opacity})`,
    style: {
      borderRadius: 16,
    },
  };

  const renderResourceCard = (resource: CloudResource) => (
    <Card key={resource.id} style={styles.resourceCard} onPress={() => {
      setSelectedResource(resource);
      fetchFindings(resource.id);
    }}>
      <Card.Content>
        <View style={styles.resourceHeader}>
          <View style={styles.resourceInfo}>
            <Title style={styles.resourceTitle}>{resource.name}</Title>
            <Paragraph style={styles.resourceType}>{resource.type.toUpperCase()}</Paragraph>
          </View>
          <View style={styles.resourceStatus}>
            <Chip
              mode="outlined"
              textStyle={{ color: getStatusColor(resource.status) }}
              style={[styles.statusChip, { borderColor: getStatusColor(resource.status) }]}
            >
              {resource.status}
            </Chip>
            <Chip
              mode="outlined"
              textStyle={{ color: getProviderColor(resource.provider) }}
              style={[styles.providerChip, { borderColor: getProviderColor(resource.provider) }]}
            >
              {resource.provider.toUpperCase()}
            </Chip>
          </View>
        </View>
        
        <View style={styles.resourceMetrics}>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{resource.security_issues}</Text>
            <Text style={styles.metricLabel}>Issues</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{resource.compliance_score}%</Text>
            <Text style={styles.metricLabel}>Compliance</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>${resource.cost}</Text>
            <Text style={styles.metricLabel}>Cost</Text>
          </View>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{resource.region}</Text>
            <Text style={styles.metricLabel}>Region</Text>
          </View>
        </View>
        
        <View style={styles.resourceFooter}>
          <Text style={styles.resourceDetail}>Last Scan: {new Date(resource.last_scan).toLocaleDateString()}</Text>
          <Text style={styles.resourceDetail}>Created: {new Date(resource.created_at).toLocaleDateString()}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  const renderFindingCard = (finding: SecurityFinding) => (
    <Card key={finding.id} style={styles.findingCard} onPress={() => {
      setSelectedFinding(finding);
      setFindingDetailsModal(true);
    }}>
      <Card.Content>
        <View style={styles.findingHeader}>
          <Title style={styles.findingTitle}>{finding.title}</Title>
          <Chip
            mode="outlined"
            textStyle={{ color: getSeverityColor(finding.severity) }}
            style={[styles.severityChip, { borderColor: getSeverityColor(finding.severity) }]}
          >
            {finding.severity}
          </Chip>
        </View>
        
        <Paragraph style={styles.findingDescription}>{finding.description}</Paragraph>
        
        <View style={styles.findingDetails}>
          <Text style={styles.findingDetail}>Type: {finding.finding_type}</Text>
          <Text style={styles.findingDetail}>Status: {finding.status}</Text>
          <Text style={styles.findingDetail}>Created: {new Date(finding.created_at).toLocaleDateString()}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading cloud resources...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#9C27B0', '#7B1FA2']} style={styles.header}>
        <Text style={styles.headerTitle}>Cloud Security</Text>
        <Text style={styles.headerSubtitle}>Cloud Infrastructure Security</Text>
      </LinearGradient>

      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        {/* Provider Filter */}
        <View style={styles.filterContainer}>
          <Text style={styles.sectionTitle}>Cloud Provider</Text>
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

        {/* Summary Metrics */}
        <View style={styles.summaryContainer}>
          <Text style={styles.sectionTitle}>Security Overview</Text>
          <View style={styles.summaryGrid}>
            <View style={styles.summaryCard}>
              <Icon name="cloud" size={32} color="#9C27B0" />
              <Text style={styles.summaryValue}>{metrics?.total_resources || 0}</Text>
              <Text style={styles.summaryLabel}>Resources</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="shield-check" size={32} color="#4CAF50" />
              <Text style={styles.summaryValue}>{metrics?.secure_resources || 0}</Text>
              <Text style={styles.summaryLabel}>Secure</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="alert-circle" size={32} color="#F44336" />
              <Text style={styles.summaryValue}>{metrics?.critical_findings || 0}</Text>
              <Text style={styles.summaryLabel}>Critical</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="chart-line" size={32} color="#FF9800" />
              <Text style={styles.summaryValue}>{Math.round(metrics?.compliance_score_avg || 0)}%</Text>
              <Text style={styles.summaryLabel}>Compliance</Text>
            </View>
          </View>
        </View>

        {/* Security Findings Chart */}
        <View style={styles.chartContainer}>
          <Text style={styles.sectionTitle}>Security Findings Distribution</Text>
          <BarChart
            data={{
              labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
              datasets: [{
                data: [
                  metrics?.critical_findings || 0,
                  metrics?.high_findings || 0,
                  metrics?.medium_findings || 0,
                  metrics?.low_findings || 0,
                  0, // Info findings would be calculated
                ],
              }],
            }}
            width={width - 40}
            height={220}
            chartConfig={chartConfig}
            style={styles.chart}
          />
        </View>

        {/* Resources List */}
        <View style={styles.resourcesContainer}>
          <Text style={styles.sectionTitle}>Cloud Resources</Text>
          {resources.length === 0 ? (
            <Card style={styles.emptyCard}>
              <Card.Content>
                <Text style={styles.emptyText}>No cloud resources found</Text>
                <Text style={styles.emptySubtext}>Connect your cloud accounts to begin monitoring</Text>
              </Card.Content>
            </Card>
          ) : (
            resources.map(renderResourceCard)
          )}
        </View>

        {/* Findings List for Selected Resource */}
        {selectedResource && findings.length > 0 && (
          <View style={styles.findingsContainer}>
            <Text style={styles.sectionTitle}>Security Findings - {selectedResource.name}</Text>
            {findings.slice(0, 5).map(renderFindingCard)}
          </View>
        )}
      </ScrollView>

      {/* Finding Details Modal */}
      <Portal>
        <Dialog visible={findingDetailsModal} onDismiss={() => setFindingDetailsModal(false)}>
          <Dialog.Title>Security Finding Details</Dialog.Title>
          <Dialog.Content>
            {selectedFinding && (
              <View>
                <View style={styles.findingModalHeader}>
                  <Text style={styles.findingModalTitle}>{selectedFinding.title}</Text>
                  <Chip
                    mode="outlined"
                    textStyle={{ color: getSeverityColor(selectedFinding.severity) }}
                    style={[styles.severityChip, { borderColor: getSeverityColor(selectedFinding.severity) }]}
                  >
                    {selectedFinding.severity}
                  </Chip>
                </View>
                
                <Text style={styles.findingModalDescription}>{selectedFinding.description}</Text>
                
                <View style={styles.findingModalDetails}>
                  <Text style={styles.findingModalDetail}>Type: {selectedFinding.finding_type}</Text>
                  <Text style={styles.findingModalDetail}>Status: {selectedFinding.status}</Text>
                  <Text style={styles.findingModalDetail}>Created: {new Date(selectedFinding.created_at).toLocaleString()}</Text>
                  <Text style={styles.findingModalDetail}>Updated: {new Date(selectedFinding.updated_at).toLocaleString()}</Text>
                </View>
                
                <View style={styles.recommendationContainer}>
                  <Text style={styles.recommendationTitle}>Recommendation:</Text>
                  <Text style={styles.recommendationText}>{selectedFinding.recommendation}</Text>
                </View>
                
                <View style={styles.complianceContainer}>
                  <Text style={styles.complianceTitle}>Compliance Frameworks:</Text>
                  {selectedFinding.compliance_frameworks.map((framework, index) => (
                    <Chip key={index} style={styles.complianceChip} mode="outlined">
                      {framework}
                    </Chip>
                  ))}
                </View>
                
                <View style={styles.actionContainer}>
                  <Text style={styles.actionTitle}>Actions:</Text>
                  <Button
                    mode="outlined"
                    onPress={() => updateFindingStatus(selectedFinding.id, 'resolved')}
                    style={styles.actionButton}
                  >
                    Mark as Resolved
                  </Button>
                  <Button
                    mode="outlined"
                    onPress={() => updateFindingStatus(selectedFinding.id, 'false_positive')}
                    style={styles.actionButton}
                  >
                    Mark as False Positive
                  </Button>
                </View>
              </View>
            )}
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setFindingDetailsModal(false)}>Close</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  header: {
    padding: 20,
    paddingTop: 60,
    paddingBottom: 30,
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: 'white',
    marginBottom: 5,
  },
  headerSubtitle: {
    fontSize: 16,
    color: 'rgba(255, 255, 255, 0.8)',
  },
  content: {
    flex: 1,
  },
  filterContainer: {
    padding: 20,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
  },
  filterButtons: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  filterButton: {
    flex: 1,
    marginHorizontal: 5,
  },
  summaryContainer: {
    padding: 20,
  },
  summaryGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  summaryCard: {
    width: (width - 60) / 2,
    backgroundColor: 'white',
    padding: 20,
    borderRadius: 12,
    alignItems: 'center',
    marginBottom: 15,
    elevation: 2,
  },
  summaryValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 8,
  },
  summaryLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  chartContainer: {
    padding: 20,
    backgroundColor: 'white',
    marginHorizontal: 20,
    borderRadius: 12,
    marginBottom: 20,
  },
  chart: {
    borderRadius: 12,
  },
  resourcesContainer: {
    padding: 20,
  },
  resourceCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  resourceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  resourceInfo: {
    flex: 1,
  },
  resourceTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  resourceType: {
    fontSize: 14,
    color: '#666',
  },
  resourceStatus: {
    alignItems: 'flex-end',
  },
  statusChip: {
    marginBottom: 5,
  },
  providerChip: {
    marginLeft: 10,
  },
  resourceMetrics: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 15,
  },
  metric: {
    alignItems: 'center',
  },
  metricValue: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  metricLabel: {
    fontSize: 10,
    color: '#666',
    marginTop: 2,
  },
  resourceFooter: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 10,
  },
  resourceDetail: {
    fontSize: 12,
    color: '#666',
  },
  findingsContainer: {
    padding: 20,
  },
  findingCard: {
    marginBottom: 15,
    borderRadius: 8,
  },
  findingHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 10,
  },
  findingTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    flex: 1,
    marginRight: 10,
  },
  severityChip: {
    marginLeft: 10,
  },
  findingDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 10,
  },
  findingDetails: {
    marginBottom: 10,
  },
  findingDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  emptyCard: {
    marginBottom: 15,
    borderRadius: 12,
  },
  emptyText: {
    fontSize: 16,
    textAlign: 'center',
    color: '#666',
  },
  emptySubtext: {
    fontSize: 14,
    textAlign: 'center',
    color: '#999',
    marginTop: 5,
  },
  findingModalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  findingModalTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    flex: 1,
    marginRight: 10,
  },
  findingModalDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 15,
  },
  findingModalDetails: {
    marginBottom: 15,
  },
  findingModalDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 5,
  },
  recommendationContainer: {
    marginBottom: 15,
    backgroundColor: '#f5f5f5',
    padding: 10,
    borderRadius: 5,
  },
  recommendationTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 5,
  },
  recommendationText: {
    fontSize: 12,
    color: '#666',
  },
  complianceContainer: {
    marginBottom: 15,
  },
  complianceTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 10,
  },
  complianceChip: {
    marginRight: 5,
    marginBottom: 5,
  },
  actionContainer: {
    marginBottom: 15,
  },
  actionTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 10,
  },
  actionButton: {
    marginBottom: 10,
  },
});

export default CloudSecurityScreen; 