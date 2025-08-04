import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  RefreshControl,
  Alert,
  Modal,
  TextInput,
} from 'react-native';
import { LinearGradient } from 'react-native-linear-gradient';
import { Card, Title, Paragraph, Button, Chip, FAB, Portal, Dialog } from 'react-native-paper';
import { LineChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService, SASTScan, SASTVulnerability } from '../services/APIService';
import { Dimensions } from 'react-native';

const { width } = Dimensions.get('window');

const SASTScreen: React.FC = ({ navigation }: any) => {
  const [scans, setScans] = useState<SASTScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<SASTScan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<SASTVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [newScanModal, setNewScanModal] = useState(false);
  const [scanDetailsModal, setScanDetailsModal] = useState(false);
  const [newScanData, setNewScanData] = useState({
    name: '',
    repository_url: '',
  });

  const apiService = new APIService();

  const fetchScans = async () => {
    try {
      setLoading(true);
      const scansData = await apiService.getSASTScans();
      setScans(scansData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch SAST scans');
    } finally {
      setLoading(false);
    }
  };

  const fetchVulnerabilities = async (scanId: string) => {
    try {
      const vulns = await apiService.getSASTVulnerabilities(scanId);
      setVulnerabilities(vulns);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch vulnerabilities');
    }
  };

  const startNewScan = async () => {
    if (!newScanData.name || !newScanData.repository_url) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }

    try {
      await apiService.startSASTScan(newScanData);
      setNewScanModal(false);
      setNewScanData({ name: '', repository_url: '' });
      fetchScans();
      Alert.alert('Success', 'SAST scan started successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to start SAST scan');
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchScans();
    setRefreshing(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#4CAF50';
      case 'running': return '#2196F3';
      case 'pending': return '#FF9800';
      case 'failed': return '#F44336';
      default: return '#9E9E9E';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FF9800';
      case 'low': return '#4CAF50';
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

  const renderScanCard = (scan: SASTScan) => (
    <Card key={scan.id} style={styles.scanCard} onPress={() => {
      setSelectedScan(scan);
      fetchVulnerabilities(scan.id);
      setScanDetailsModal(true);
    }}>
      <Card.Content>
        <View style={styles.scanHeader}>
          <View style={styles.scanInfo}>
            <Title style={styles.scanTitle}>{scan.project_name}</Title>
            <Paragraph style={styles.scanType}>{scan.scan_type}</Paragraph>
          </View>
          <Chip
            mode="outlined"
            textStyle={{ color: getStatusColor(scan.status) }}
            style={[styles.statusChip, { borderColor: getStatusColor(scan.status) }]}
          >
            {scan.status}
          </Chip>
        </View>
        
        <View style={styles.scanMetrics}>
          <View style={styles.metric}>
            <Text style={styles.metricValue}>{scan.vulnerabilities_count}</Text>
            <Text style={styles.metricLabel}>Total</Text>
          </View>
          <View style={styles.metric}>
            <Text style={[styles.metricValue, { color: '#F44336' }]}>{scan.critical_count}</Text>
            <Text style={styles.metricLabel}>Critical</Text>
          </View>
          <View style={styles.metric}>
            <Text style={[styles.metricValue, { color: '#FF5722' }]}>{scan.high_count}</Text>
            <Text style={styles.metricLabel}>High</Text>
          </View>
          <View style={styles.metric}>
            <Text style={[styles.metricValue, { color: '#FF9800' }]}>{scan.medium_count}</Text>
            <Text style={styles.metricLabel}>Medium</Text>
          </View>
          <View style={styles.metric}>
            <Text style={[styles.metricValue, { color: '#4CAF50' }]}>{scan.low_count}</Text>
            <Text style={styles.metricLabel}>Low</Text>
          </View>
        </View>
        
        <View style={styles.scanFooter}>
          <Text style={styles.scanDate}>Created: {new Date(scan.created_at).toLocaleDateString()}</Text>
          {scan.completed_at && (
            <Text style={styles.scanDate}>Completed: {new Date(scan.completed_at).toLocaleDateString()}</Text>
          )}
        </View>
      </Card.Content>
    </Card>
  );

  const renderVulnerabilityCard = (vuln: SASTVulnerability) => (
    <Card key={vuln.id} style={styles.vulnCard}>
      <Card.Content>
        <View style={styles.vulnHeader}>
          <Title style={styles.vulnTitle}>{vuln.title}</Title>
          <Chip
            mode="outlined"
            textStyle={{ color: getSeverityColor(vuln.severity) }}
            style={[styles.severityChip, { borderColor: getSeverityColor(vuln.severity) }]}
          >
            {vuln.severity}
          </Chip>
        </View>
        
        <Paragraph style={styles.vulnDescription}>{vuln.description}</Paragraph>
        
        <View style={styles.vulnDetails}>
          <Text style={styles.vulnDetail}>File: {vuln.file_path}</Text>
          <Text style={styles.vulnDetail}>Line: {vuln.line_number}</Text>
          <Text style={styles.vulnDetail}>CWE: {vuln.cwe_id}</Text>
          <Text style={styles.vulnDetail}>CVSS: {vuln.cvss_score}</Text>
        </View>
        
        <View style={styles.remediationContainer}>
          <Text style={styles.remediationTitle}>Remediation:</Text>
          <Text style={styles.remediationText}>{vuln.remediation}</Text>
        </View>
      </Card.Content>
    </Card>
  );

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading SAST scans...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#4CAF50', '#45a049']} style={styles.header}>
        <Text style={styles.headerTitle}>SAST Analysis</Text>
        <Text style={styles.headerSubtitle}>Static Application Security Testing</Text>
      </LinearGradient>

      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        {/* Summary Metrics */}
        <View style={styles.summaryContainer}>
          <Text style={styles.sectionTitle}>Scan Summary</Text>
          <View style={styles.summaryGrid}>
            <View style={styles.summaryCard}>
              <Icon name="shield-scan" size={32} color="#4CAF50" />
              <Text style={styles.summaryValue}>{scans.length}</Text>
              <Text style={styles.summaryLabel}>Total Scans</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="bug" size={32} color="#FF5722" />
              <Text style={styles.summaryValue}>
                {scans.reduce((sum, scan) => sum + scan.vulnerabilities_count, 0)}
              </Text>
              <Text style={styles.summaryLabel}>Vulnerabilities</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="alert-circle" size={32} color="#F44336" />
              <Text style={styles.summaryValue}>
                {scans.reduce((sum, scan) => sum + scan.critical_count, 0)}
              </Text>
              <Text style={styles.summaryLabel}>Critical</Text>
            </View>
            <View style={styles.summaryCard}>
              <Icon name="check-circle" size={32} color="#4CAF50" />
              <Text style={styles.summaryValue}>
                {scans.filter(scan => scan.status === 'completed').length}
              </Text>
              <Text style={styles.summaryLabel}>Completed</Text>
            </View>
          </View>
        </View>

        {/* Scans List */}
        <View style={styles.scansContainer}>
          <Text style={styles.sectionTitle}>Recent Scans</Text>
          {scans.length === 0 ? (
            <Card style={styles.emptyCard}>
              <Card.Content>
                <Text style={styles.emptyText}>No SAST scans found</Text>
                <Text style={styles.emptySubtext}>Start your first scan to begin security analysis</Text>
              </Card.Content>
            </Card>
          ) : (
            scans.map(renderScanCard)
          )}
        </View>
      </ScrollView>

      {/* FAB for new scan */}
      <FAB
        style={styles.fab}
        icon="plus"
        onPress={() => setNewScanModal(true)}
      />

      {/* New Scan Modal */}
      <Portal>
        <Dialog visible={newScanModal} onDismiss={() => setNewScanModal(false)}>
          <Dialog.Title>Start New SAST Scan</Dialog.Title>
          <Dialog.Content>
            <TextInput
              style={styles.input}
              placeholder="Project Name"
              value={newScanData.name}
              onChangeText={(text) => setNewScanData({ ...newScanData, name: text })}
            />
            <TextInput
              style={styles.input}
              placeholder="Repository URL"
              value={newScanData.repository_url}
              onChangeText={(text) => setNewScanData({ ...newScanData, repository_url: text })}
            />
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setNewScanModal(false)}>Cancel</Button>
            <Button onPress={startNewScan}>Start Scan</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>

      {/* Scan Details Modal */}
      <Portal>
        <Dialog visible={scanDetailsModal} onDismiss={() => setScanDetailsModal(false)}>
          <Dialog.Title>Scan Details - {selectedScan?.project_name}</Dialog.Title>
          <Dialog.Content>
            <ScrollView style={styles.vulnList}>
              {vulnerabilities.length === 0 ? (
                <Text style={styles.emptyText}>No vulnerabilities found</Text>
              ) : (
                vulnerabilities.map(renderVulnerabilityCard)
              )}
            </ScrollView>
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setScanDetailsModal(false)}>Close</Button>
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
  summaryContainer: {
    padding: 20,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
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
  scansContainer: {
    padding: 20,
  },
  scanCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  scanHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  scanInfo: {
    flex: 1,
  },
  scanTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  scanType: {
    fontSize: 14,
    color: '#666',
  },
  statusChip: {
    marginLeft: 10,
  },
  scanMetrics: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 15,
  },
  metric: {
    alignItems: 'center',
  },
  metricValue: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#333',
  },
  metricLabel: {
    fontSize: 10,
    color: '#666',
    marginTop: 2,
  },
  scanFooter: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 10,
  },
  scanDate: {
    fontSize: 12,
    color: '#666',
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
  fab: {
    position: 'absolute',
    margin: 16,
    right: 0,
    bottom: 0,
    backgroundColor: '#4CAF50',
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    marginBottom: 15,
    fontSize: 16,
  },
  vulnList: {
    maxHeight: 400,
  },
  vulnCard: {
    marginBottom: 15,
    borderRadius: 8,
  },
  vulnHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 10,
  },
  vulnTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    flex: 1,
    marginRight: 10,
  },
  severityChip: {
    marginLeft: 10,
  },
  vulnDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 10,
  },
  vulnDetails: {
    marginBottom: 10,
  },
  vulnDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  remediationContainer: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 10,
  },
  remediationTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 5,
  },
  remediationText: {
    fontSize: 12,
    color: '#666',
  },
});

export default SASTScreen; 