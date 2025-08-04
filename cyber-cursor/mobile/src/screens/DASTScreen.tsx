import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  RefreshControl,
  Alert,
  TextInput,
} from 'react-native';
import { LinearGradient } from 'react-native-linear-gradient';
import { Card, Title, Paragraph, Button, Chip, FAB, Portal, Dialog } from 'react-native-paper';
import { BarChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService, DASTScan, DASTVulnerability } from '../services/APIService';
import { Dimensions } from 'react-native';

const { width } = Dimensions.get('window');

const DASTScreen: React.FC = ({ navigation }: any) => {
  const [scans, setScans] = useState<DASTScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<DASTScan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<DASTVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [newScanModal, setNewScanModal] = useState(false);
  const [scanDetailsModal, setScanDetailsModal] = useState(false);
  const [newScanData, setNewScanData] = useState({
    target_url: '',
    scan_name: '',
    scan_type: 'full',
  });

  const apiService = new APIService();

  const fetchScans = async () => {
    try {
      setLoading(true);
      const scansData = await apiService.getDASTScans();
      setScans(scansData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch DAST scans');
    } finally {
      setLoading(false);
    }
  };

  const fetchVulnerabilities = async (scanId: string) => {
    try {
      const vulns = await apiService.getDASTVulnerabilities(scanId);
      setVulnerabilities(vulns);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch vulnerabilities');
    }
  };

  const startNewScan = async () => {
    if (!newScanData.target_url || !newScanData.scan_name) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }

    try {
      await apiService.startDASTScan(newScanData);
      setNewScanModal(false);
      setNewScanData({ target_url: '', scan_name: '', scan_type: 'full' });
      fetchScans();
      Alert.alert('Success', 'DAST scan started successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to start DAST scan');
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

  const getScanTypeColor = (type: string) => {
    switch (type) {
      case 'full': return '#2196F3';
      case 'quick': return '#4CAF50';
      case 'custom': return '#FF9800';
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

  const renderScanCard = (scan: DASTScan) => (
    <Card key={scan.id} style={styles.scanCard} onPress={() => {
      setSelectedScan(scan);
      fetchVulnerabilities(scan.id);
      setScanDetailsModal(true);
    }}>
      <Card.Content>
        <View style={styles.scanHeader}>
          <View style={styles.scanInfo}>
            <Title style={styles.scanTitle}>{scan.scan_name}</Title>
            <Paragraph style={styles.scanUrl}>{scan.target_url}</Paragraph>
          </View>
          <View style={styles.scanStatus}>
            <Chip
              mode="outlined"
              textStyle={{ color: getStatusColor(scan.status) }}
              style={[styles.statusChip, { borderColor: getStatusColor(scan.status) }]}
            >
              {scan.status}
            </Chip>
            <Chip
              mode="outlined"
              textStyle={{ color: getScanTypeColor(scan.scan_type) }}
              style={[styles.typeChip, { borderColor: getScanTypeColor(scan.scan_type) }]}
            >
              {scan.scan_type}
            </Chip>
          </View>
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
          {scan.scan_duration && (
            <Text style={styles.scanDuration}>Duration: {Math.round(scan.scan_duration / 60)}m</Text>
          )}
        </View>
      </Card.Content>
    </Card>
  );

  const renderVulnerabilityCard = (vuln: DASTVulnerability) => (
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
          <Text style={styles.vulnDetail}>URL: {vuln.url}</Text>
          <Text style={styles.vulnDetail}>Parameter: {vuln.parameter}</Text>
          <Text style={styles.vulnDetail}>CWE: {vuln.cwe_id}</Text>
          <Text style={styles.vulnDetail}>CVSS: {vuln.cvss_score}</Text>
        </View>
        
        <View style={styles.payloadContainer}>
          <Text style={styles.payloadTitle}>Payload:</Text>
          <Text style={styles.payloadText}>{vuln.payload}</Text>
        </View>
        
        <View style={styles.evidenceContainer}>
          <Text style={styles.evidenceTitle}>Evidence:</Text>
          <Text style={styles.evidenceText}>{vuln.evidence}</Text>
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
        <Text>Loading DAST scans...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#FF5722', '#E64A19']} style={styles.header}>
        <Text style={styles.headerTitle}>DAST Testing</Text>
        <Text style={styles.headerSubtitle}>Dynamic Application Security Testing</Text>
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
              <Icon name="web" size={32} color="#FF5722" />
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
              <Icon name="clock" size={32} color="#2196F3" />
              <Text style={styles.summaryValue}>
                {scans.filter(scan => scan.status === 'running').length}
              </Text>
              <Text style={styles.summaryLabel}>Running</Text>
            </View>
          </View>
        </View>

        {/* Vulnerability Distribution Chart */}
        <View style={styles.chartContainer}>
          <Text style={styles.sectionTitle}>Vulnerability Distribution</Text>
          <BarChart
            data={{
              labels: ['Critical', 'High', 'Medium', 'Low'],
              datasets: [{
                data: [
                  scans.reduce((sum, scan) => sum + scan.critical_count, 0),
                  scans.reduce((sum, scan) => sum + scan.high_count, 0),
                  scans.reduce((sum, scan) => sum + scan.medium_count, 0),
                  scans.reduce((sum, scan) => sum + scan.low_count, 0),
                ],
              }],
            }}
            width={width - 40}
            height={220}
            chartConfig={chartConfig}
            style={styles.chart}
          />
        </View>

        {/* Scans List */}
        <View style={styles.scansContainer}>
          <Text style={styles.sectionTitle}>Recent Scans</Text>
          {scans.length === 0 ? (
            <Card style={styles.emptyCard}>
              <Card.Content>
                <Text style={styles.emptyText}>No DAST scans found</Text>
                <Text style={styles.emptySubtext}>Start your first scan to begin security testing</Text>
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
          <Dialog.Title>Start New DAST Scan</Dialog.Title>
          <Dialog.Content>
            <TextInput
              style={styles.input}
              placeholder="Target URL (e.g., https://example.com)"
              value={newScanData.target_url}
              onChangeText={(text) => setNewScanData({ ...newScanData, target_url: text })}
            />
            <TextInput
              style={styles.input}
              placeholder="Scan Name"
              value={newScanData.scan_name}
              onChangeText={(text) => setNewScanData({ ...newScanData, scan_name: text })}
            />
            <View style={styles.scanTypeContainer}>
              <Text style={styles.scanTypeLabel}>Scan Type:</Text>
              <View style={styles.scanTypeButtons}>
                <Button
                  mode={newScanData.scan_type === 'quick' ? 'contained' : 'outlined'}
                  onPress={() => setNewScanData({ ...newScanData, scan_type: 'quick' })}
                  style={styles.scanTypeButton}
                >
                  Quick
                </Button>
                <Button
                  mode={newScanData.scan_type === 'full' ? 'contained' : 'outlined'}
                  onPress={() => setNewScanData({ ...newScanData, scan_type: 'full' })}
                  style={styles.scanTypeButton}
                >
                  Full
                </Button>
                <Button
                  mode={newScanData.scan_type === 'custom' ? 'contained' : 'outlined'}
                  onPress={() => setNewScanData({ ...newScanData, scan_type: 'custom' })}
                  style={styles.scanTypeButton}
                >
                  Custom
                </Button>
              </View>
            </View>
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
          <Dialog.Title>Scan Details - {selectedScan?.scan_name}</Dialog.Title>
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
  scanUrl: {
    fontSize: 14,
    color: '#666',
  },
  scanStatus: {
    alignItems: 'flex-end',
  },
  statusChip: {
    marginBottom: 5,
  },
  typeChip: {
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
  scanDuration: {
    fontSize: 12,
    color: '#666',
    fontStyle: 'italic',
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
    backgroundColor: '#FF5722',
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    marginBottom: 15,
    fontSize: 16,
  },
  scanTypeContainer: {
    marginBottom: 15,
  },
  scanTypeLabel: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#333',
  },
  scanTypeButtons: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  scanTypeButton: {
    flex: 1,
    marginHorizontal: 5,
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
  payloadContainer: {
    marginBottom: 10,
    backgroundColor: '#f5f5f5',
    padding: 10,
    borderRadius: 5,
  },
  payloadTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 5,
  },
  payloadText: {
    fontSize: 12,
    color: '#666',
    fontFamily: 'monospace',
  },
  evidenceContainer: {
    marginBottom: 10,
    backgroundColor: '#fff3e0',
    padding: 10,
    borderRadius: 5,
  },
  evidenceTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 5,
  },
  evidenceText: {
    fontSize: 12,
    color: '#666',
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

export default DASTScreen; 