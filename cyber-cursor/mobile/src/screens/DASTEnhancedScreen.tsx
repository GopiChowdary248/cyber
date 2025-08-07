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
  Dimensions,
} from 'react-native';
import { Card, Title, Paragraph, Button, Chip, FAB, Portal, Dialog, TextInput } from 'react-native-paper';
import { BarChart, PieChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { apiService, DASTScan, DASTVulnerability } from '../services/APIService';

const { width } = Dimensions.get('window');

const DASTEnhancedScreen: React.FC = ({ navigation }: any) => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scans, setScans] = useState<DASTScan[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<DASTVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [newScanModal, setNewScanModal] = useState(false);
  const [scanDetailsModal, setScanDetailsModal] = useState(false);
  const [selectedScan, setSelectedScan] = useState<DASTScan | null>(null);
  const [newScanData, setNewScanData] = useState({
    target_url: '',
    scan_name: '',
    scan_type: 'full',
  });

  const apiServiceInstance = apiService;

  const fetchData = async () => {
    try {
      setLoading(true);
      const [scansData, vulnsData] = await Promise.all([
        apiServiceInstance.getDASTScans(),
        apiServiceInstance.getDASTVulnerabilities('all')
      ]);
      setScans(scansData);
      setVulnerabilities(vulnsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch DAST data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchData();
    setRefreshing(false);
  };

  const startNewScan = async () => {
    if (!newScanData.target_url || !newScanData.scan_name) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }

    try {
      await apiServiceInstance.startDASTScan(newScanData);
      setNewScanModal(false);
      setNewScanData({ target_url: '', scan_name: '', scan_type: 'full' });
      fetchData();
      Alert.alert('Success', 'DAST scan started successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to start DAST scan');
    }
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

  const renderDashboard = () => (
    <ScrollView style={styles.tabContent}>
      <View style={styles.statsContainer}>
        <Card style={styles.statCard}>
          <Card.Content>
            <Title style={styles.statNumber}>{scans.length}</Title>
            <Paragraph>Total Scans</Paragraph>
          </Card.Content>
        </Card>
        
        <Card style={styles.statCard}>
          <Card.Content>
            <Title style={styles.statNumber}>{vulnerabilities.length}</Title>
            <Paragraph>Vulnerabilities</Paragraph>
          </Card.Content>
        </Card>
        
        <Card style={styles.statCard}>
          <Card.Content>
            <Title style={styles.statNumber}>
              {vulnerabilities.filter(v => v.severity === 'critical').length}
            </Title>
            <Paragraph>Critical</Paragraph>
          </Card.Content>
        </Card>
        
        <Card style={styles.statCard}>
          <Card.Content>
            <Title style={styles.statNumber}>
              {vulnerabilities.filter(v => v.severity === 'high').length}
            </Title>
            <Paragraph>High</Paragraph>
          </Card.Content>
        </Card>
      </View>

      <Card style={styles.chartCard}>
        <Card.Content>
          <Title>Vulnerability Distribution</Title>
          <View style={styles.chartContainer}>
            <PieChart
              data={[
                {
                  name: 'Critical',
                  population: vulnerabilities.filter(v => v.severity === 'critical').length,
                  color: '#F44336',
                  legendFontColor: '#7F7F7F',
                },
                {
                  name: 'High',
                  population: vulnerabilities.filter(v => v.severity === 'high').length,
                  color: '#FF5722',
                  legendFontColor: '#7F7F7F',
                },
                {
                  name: 'Medium',
                  population: vulnerabilities.filter(v => v.severity === 'medium').length,
                  color: '#FF9800',
                  legendFontColor: '#7F7F7F',
                },
                {
                  name: 'Low',
                  population: vulnerabilities.filter(v => v.severity === 'low').length,
                  color: '#4CAF50',
                  legendFontColor: '#7F7F7F',
                },
              ]}
              width={width - 60}
              height={200}
              chartConfig={{
                color: (opacity = 1) => `rgba(0, 0, 0, ${opacity})`,
              }}
              accessor="population"
              backgroundColor="transparent"
              paddingLeft="15"
            />
          </View>
        </Card.Content>
      </Card>
    </ScrollView>
  );

  const renderScans = () => (
    <ScrollView style={styles.tabContent}>
      {scans.map((scan) => (
        <Card key={scan.id} style={styles.scanCard}>
          <Card.Content>
            <View style={styles.scanHeader}>
              <Title>{scan.scan_name}</Title>
              <Chip
                mode="outlined"
                textStyle={{ color: getStatusColor(scan.status) }}
                style={{ borderColor: getStatusColor(scan.status) }}
              >
                {scan.status}
              </Chip>
            </View>
            
            <Paragraph>{scan.target_url}</Paragraph>
            <Text style={styles.scanDate}>
              Started: {new Date(scan.created_at).toLocaleString()}
            </Text>
            
            {scan.completed_at && (
              <Text style={styles.scanDate}>
                Completed: {new Date(scan.completed_at).toLocaleString()}
              </Text>
            )}
            
            <View style={styles.scanStats}>
              <View style={styles.scanStat}>
                <Text style={styles.statLabel}>Critical</Text>
                <Text style={[styles.statValue, { color: '#F44336' }]}>
                  {scan.critical_count}
                </Text>
              </View>
              <View style={styles.scanStat}>
                <Text style={styles.statLabel}>High</Text>
                <Text style={[styles.statValue, { color: '#FF5722' }]}>
                  {scan.high_count}
                </Text>
              </View>
              <View style={styles.scanStat}>
                <Text style={styles.statLabel}>Medium</Text>
                <Text style={[styles.statValue, { color: '#FF9800' }]}>
                  {scan.medium_count}
                </Text>
              </View>
              <View style={styles.scanStat}>
                <Text style={styles.statLabel}>Low</Text>
                <Text style={[styles.statValue, { color: '#4CAF50' }]}>
                  {scan.low_count}
                </Text>
              </View>
            </View>
            
            <View style={styles.scanActions}>
              <Button
                mode="contained"
                onPress={() => {
                  setSelectedScan(scan);
                  setScanDetailsModal(true);
                }}
                style={styles.actionButton}
              >
                View Details
              </Button>
              <Button
                mode="outlined"
                onPress={() => navigation.navigate('ScanReport', { scanId: scan.id })}
                style={styles.actionButton}
              >
                Report
              </Button>
            </View>
          </Card.Content>
        </Card>
      ))}
    </ScrollView>
  );

  const renderVulnerabilities = () => (
    <ScrollView style={styles.tabContent}>
      {vulnerabilities.map((vuln) => (
        <Card key={vuln.id} style={styles.vulnCard}>
          <Card.Content>
            <View style={styles.vulnHeader}>
              <Title style={styles.vulnTitle}>{vuln.title}</Title>
              <Chip
                mode="outlined"
                textStyle={{ color: getSeverityColor(vuln.severity) }}
                style={{ borderColor: getSeverityColor(vuln.severity) }}
              >
                {vuln.severity}
              </Chip>
            </View>
            
            <Paragraph>{vuln.description}</Paragraph>
            <Text style={styles.vulnUrl}>{vuln.url}</Text>
            
            {vuln.parameter && (
              <Text style={styles.vulnParam}>Parameter: {vuln.parameter}</Text>
            )}
            
            {vuln.payload && (
              <Text style={styles.vulnPayload}>Payload: {vuln.payload}</Text>
            )}
            
            <View style={styles.vulnActions}>
              <Button
                mode="contained"
                onPress={() => navigation.navigate('VulnerabilityDetails', { vulnId: vuln.id })}
                style={styles.actionButton}
              >
                Details
              </Button>
              <Button
                mode="outlined"
                onPress={() => navigation.navigate('Remediation', { vulnId: vuln.id })}
                style={styles.actionButton}
              >
                Remediation
              </Button>
            </View>
          </Card.Content>
        </Card>
      ))}
    </ScrollView>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>DAST Scanner</Text>
        <Text style={styles.headerSubtitle}>Dynamic Application Security Testing</Text>
      </View>

      <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.tabBar}>
        {[
          { key: 'dashboard', label: 'Dashboard', icon: 'view-dashboard' },
          { key: 'scans', label: 'Scans', icon: 'radar' },
          { key: 'vulnerabilities', label: 'Vulnerabilities', icon: 'bug' },
        ].map((tab) => (
          <TouchableOpacity
            key={tab.key}
            style={[styles.tab, activeTab === tab.key && styles.activeTab]}
            onPress={() => setActiveTab(tab.key)}
          >
            <Icon
              name={tab.icon}
              size={20}
              color={activeTab === tab.key ? '#2a5298' : '#666'}
            />
            <Text style={[styles.tabText, activeTab === tab.key && styles.activeTabText]}>
              {tab.label}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
        }
      >
        {activeTab === 'dashboard' && renderDashboard()}
        {activeTab === 'scans' && renderScans()}
        {activeTab === 'vulnerabilities' && renderVulnerabilities()}
      </ScrollView>

      <FAB
        style={styles.fab}
        icon="plus"
        onPress={() => setNewScanModal(true)}
      />

      <Portal>
        <Dialog visible={newScanModal} onDismiss={() => setNewScanModal(false)}>
          <Dialog.Title>Start New Scan</Dialog.Title>
          <Dialog.Content>
            <TextInput
              label="Scan Name"
              value={newScanData.scan_name}
              onChangeText={(text) => setNewScanData({ ...newScanData, scan_name: text })}
              style={styles.input}
            />
            <TextInput
              label="Target URL"
              value={newScanData.target_url}
              onChangeText={(text) => setNewScanData({ ...newScanData, target_url: text })}
              style={styles.input}
            />
            <TextInput
              label="Scan Type"
              value={newScanData.scan_type}
              onChangeText={(text) => setNewScanData({ ...newScanData, scan_type: text })}
              style={styles.input}
            />
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setNewScanModal(false)}>Cancel</Button>
            <Button onPress={startNewScan}>Start Scan</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>

      <Portal>
        <Dialog visible={scanDetailsModal} onDismiss={() => setScanDetailsModal(false)}>
          <Dialog.Title>Scan Details</Dialog.Title>
          <Dialog.Content>
            {selectedScan && (
              <View>
                <Text style={styles.detailLabel}>Scan Name:</Text>
                <Text style={styles.detailValue}>{selectedScan.scan_name}</Text>
                
                <Text style={styles.detailLabel}>Target URL:</Text>
                <Text style={styles.detailValue}>{selectedScan.target_url}</Text>
                
                <Text style={styles.detailLabel}>Status:</Text>
                <Text style={styles.detailValue}>{selectedScan.status}</Text>
                
                <Text style={styles.detailLabel}>Started:</Text>
                <Text style={styles.detailValue}>
                  {new Date(selectedScan.created_at).toLocaleString()}
                </Text>
                
                {selectedScan.completed_at && (
                  <>
                    <Text style={styles.detailLabel}>Completed:</Text>
                    <Text style={styles.detailValue}>
                      {new Date(selectedScan.completed_at).toLocaleString()}
                    </Text>
                  </>
                )}
                
                <Text style={styles.detailLabel}>Vulnerabilities Found:</Text>
                <Text style={styles.detailValue}>{selectedScan.vulnerabilities_count}</Text>
                
                {selectedScan.scan_duration && (
                  <>
                    <Text style={styles.detailLabel}>Duration:</Text>
                    <Text style={styles.detailValue}>{selectedScan.scan_duration}s</Text>
                  </>
                )}
              </View>
            )}
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setScanDetailsModal(false)}>Close</Button>
            <Button onPress={() => {
              setScanDetailsModal(false);
              if (selectedScan) {
                navigation.navigate('ScanReport', { scanId: selectedScan.id });
              }
            }}>View Report</Button>
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
  header: {
    paddingTop: 50,
    paddingBottom: 20,
    paddingHorizontal: 20,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: 'white',
    marginBottom: 5,
  },
  headerSubtitle: {
    fontSize: 14,
    color: 'rgba(255, 255, 255, 0.8)',
  },
  tabBar: {
    backgroundColor: 'white',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  tab: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 15,
    paddingVertical: 12,
    marginHorizontal: 5,
  },
  activeTab: {
    backgroundColor: '#e3f2fd',
    borderRadius: 20,
  },
  tabText: {
    marginLeft: 5,
    fontSize: 12,
    color: '#666',
  },
  activeTabText: {
    color: '#2a5298',
    fontWeight: 'bold',
  },
  content: {
    flex: 1,
  },
  tabContent: {
    padding: 15,
  },
  statsContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  statCard: {
    width: '48%',
    marginBottom: 10,
  },
  statNumber: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#2a5298',
  },
  chartCard: {
    marginBottom: 20,
  },
  chartContainer: {
    alignItems: 'center',
    marginTop: 10,
  },
  scanCard: {
    marginBottom: 15,
  },
  scanHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  scanDate: {
    fontSize: 12,
    color: '#666',
    marginTop: 5,
  },
  scanStats: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginVertical: 15,
    paddingVertical: 10,
    backgroundColor: '#f8f9fa',
    borderRadius: 8,
  },
  scanStat: {
    alignItems: 'center',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  statValue: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#2a5298',
  },
  scanActions: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 15,
  },
  actionButton: {
    flex: 1,
    marginHorizontal: 5,
  },
  vulnCard: {
    marginBottom: 15,
  },
  vulnHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  vulnTitle: {
    flex: 1,
    marginRight: 10,
  },
  vulnUrl: {
    fontSize: 12,
    color: '#666',
    marginTop: 5,
    fontFamily: 'monospace',
  },
  vulnParam: {
    fontSize: 12,
    color: '#666',
    marginTop: 5,
  },
  vulnPayload: {
    fontSize: 12,
    color: '#666',
    marginTop: 5,
    fontFamily: 'monospace',
    backgroundColor: '#f8f9fa',
    padding: 5,
    borderRadius: 4,
  },
  vulnActions: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 15,
  },
  fab: {
    position: 'absolute',
    margin: 16,
    right: 0,
    bottom: 0,
    backgroundColor: '#2a5298',
  },
  input: {
    marginBottom: 15,
  },
  detailLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 10,
  },
  detailValue: {
    fontSize: 14,
    color: '#666',
    marginBottom: 10,
  },
});

export default DASTEnhancedScreen; 