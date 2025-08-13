import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert,
  RefreshControl,
  ActivityIndicator,
  Dimensions,
  StatusBar,
} from 'react-native';
import { Card, Button, Chip, ProgressBar, Divider, FAB, Portal, Modal, TextInput } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { COLORS, SIZES, FONTS } from '../../constants/constants';
import { LinearGradient } from 'expo-linear-gradient';

const { width, height } = Dimensions.get('window');

interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  file_path: string;
  line_number: number;
  cwe_id: string;
  cvss_score: number;
  remediation: string;
}

// Mock data for demonstration - replace with actual API calls
const mockScans = [
  {
    id: 1,
    project_name: 'Sample Project',
    scan_type: 'SAST',
    status: 'COMPLETED',
    progress: 100,
    vulnerabilities_found: 5,
    bugs_found: 3,
    code_smells_found: 8,
    security_hotspots_found: 2,
    started_at: '2024-01-15T10:00:00Z',
    completed_at: '2024-01-15T10:45:00Z',
    duration: 45,
  },
  {
    id: 2,
    project_name: 'Another Project',
    scan_type: 'SAST',
    status: 'RUNNING',
    progress: 65,
    vulnerabilities_found: 2,
    bugs_found: 1,
    code_smells_found: 4,
    security_hotspots_found: 1,
    started_at: '2024-01-15T11:00:00Z',
  },
];

const mockVulnerabilities = [
  {
    id: 1,
    message: 'SQL Injection vulnerability detected',
    severity: 'critical',
    file_path: 'src/database/connection.py',
    line_number: 45,
    rule_id: 'SQL_INJECTION_1',
    rule_category: 'Security',
  },
  {
    id: 2,
    message: 'XSS vulnerability in user input',
    severity: 'high',
    file_path: 'src/components/UserProfile.jsx',
    line_number: 23,
    rule_id: 'XSS_1',
    rule_category: 'Security',
  },
];

const SASTScreen: React.FC = () => {
  const [selectedScan, setSelectedScan] = useState<any>(null);
  const [showVulnerabilities, setShowVulnerabilities] = useState(false);
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  const [newScanData, setNewScanData] = useState({
    name: '',
    repository_url: '',
    branch: 'main',
    language: 'auto'
  });
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [scansLoading, setScansLoading] = useState(false);
  const [vulnLoading, setVulnLoading] = useState(false);

  // Mock data loading
  useEffect(() => {
    setScansLoading(true);
    // Simulate API call
    setTimeout(() => {
      setScansLoading(false);
    }, 1000);
  }, []);

  // Handle scan start with validation
  const handleStartScan = useCallback(() => {
    if (!newScanData.name.trim()) {
      Alert.alert('Error', 'Project name is required');
      return;
    }
    if (!newScanData.repository_url.trim()) {
      Alert.alert('Error', 'Repository URL is required');
      return;
    }
    
    // Simulate API call
    setScansLoading(true);
    setTimeout(() => {
      setScansLoading(false);
      setShowNewScanModal(false);
      setNewScanData({ name: '', repository_url: '', branch: 'main', language: 'auto' });
      Alert.alert('Success', 'SAST scan started successfully');
    }, 2000);
  }, [newScanData]);

  // Get severity color with better contrast
  const getSeverityColor = useCallback((severity: string) => {
    switch (severity) {
      case 'critical': return '#DC2626';
      case 'high': return '#EA580C';
      case 'medium': return '#D97706';
      case 'low': return '#059669';
      default: return COLORS.gray;
    }
  }, []);

  // Get status color and icon
  const getStatusInfo = useCallback((status: string) => {
    switch (status) {
      case 'COMPLETED': return { color: '#059669', icon: 'check-circle', text: 'Completed' };
      case 'RUNNING': return { color: '#D97706', icon: 'play-circle', text: 'Running' };
      case 'FAILED': return { color: '#DC2626', icon: 'close-circle', text: 'Failed' };
      case 'PENDING': return { color: '#6B7280', icon: 'clock-outline', text: 'Pending' };
      default: return { color: COLORS.gray, icon: 'help-circle', text: 'Unknown' };
    }
  }, []);

  // Filter vulnerabilities based on search and severity
  const filteredVulnerabilities = useCallback(() => {
    return mockVulnerabilities.filter(vuln => {
      const matchesSeverity = filterSeverity === 'all' || vuln.severity === filterSeverity;
      const matchesSearch = searchTerm === '' || 
        vuln.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
        vuln.file_path.toLowerCase().includes(searchTerm.toLowerCase());
      
      return matchesSeverity && matchesSearch;
    });
  }, [filterSeverity, searchTerm]);

  // Render scan card with enhanced UI
  const renderScanCard = useCallback((scan: any) => {
    const statusInfo = getStatusInfo(scan.status);
    
    return (
    <Card key={scan.id} style={styles.scanCard}>
        <LinearGradient
          colors={['rgba(30, 64, 175, 0.1)', 'rgba(30, 64, 175, 0.05)']}
          style={styles.cardGradient}
        >
      <Card.Content>
        <View style={styles.scanHeader}>
          <View style={styles.scanInfo}>
            <Text style={styles.projectName}>{scan.project_name}</Text>
            <Text style={styles.scanType}>{scan.scan_type}</Text>
          </View>
          <Chip
            mode="outlined"
                textStyle={{ color: statusInfo.color, fontWeight: '600' }}
                style={{ borderColor: statusInfo.color, backgroundColor: `${statusInfo.color}15` }}
                icon={() => <Icon name={statusInfo.icon} size={16} color={statusInfo.color} />}
          >
                {statusInfo.text}
          </Chip>
        </View>
            
            {scan.status === 'RUNNING' && scan.progress !== undefined && (
              <View style={styles.progressContainer}>
                <Text style={styles.progressText}>Scan Progress: {scan.progress}%</Text>
                <ProgressBar 
                  progress={scan.progress / 100} 
                  color={statusInfo.color}
                  style={styles.progressBar}
                />
              </View>
            )}
        
        <View style={styles.vulnerabilityStats}>
          <View style={styles.statItem}>
                <Text style={[styles.statNumber, { color: '#DC2626' }]}>
                  {scan.vulnerabilities_found || 0}
            </Text>
                <Text style={styles.statLabel}>Vulnerabilities</Text>
          </View>
          <View style={styles.statItem}>
                <Text style={[styles.statNumber, { color: '#EA580C' }]}>
                  {scan.bugs_found || 0}
            </Text>
                <Text style={styles.statLabel}>Bugs</Text>
          </View>
          <View style={styles.statItem}>
                <Text style={[styles.statNumber, { color: '#D97706' }]}>
                  {scan.code_smells_found || 0}
            </Text>
                <Text style={styles.statLabel}>Code Smells</Text>
          </View>
          <View style={styles.statItem}>
                <Text style={[styles.statNumber, { color: '#059669' }]}>
                  {scan.security_hotspots_found || 0}
            </Text>
                <Text style={styles.statLabel}>Hotspots</Text>
          </View>
        </View>

            <View style={styles.scanDetails}>
              <Text style={styles.scanDetail}>
                <Icon name="calendar" size={14} color={COLORS.gray} />
                Started: {new Date(scan.started_at).toLocaleDateString()}
              </Text>
              {scan.completed_at && (
                <Text style={styles.scanDetail}>
                  <Icon name="check-circle" size={14} color={COLORS.gray} />
                  Completed: {new Date(scan.completed_at).toLocaleDateString()}
                </Text>
              )}
              {scan.duration && (
                <Text style={styles.scanDetail}>
                  <Icon name="timer" size={14} color={COLORS.gray} />
                  Duration: {scan.duration}s
        </Text>
              )}
            </View>
      </Card.Content>
      
          <Card.Actions style={styles.cardActions}>
        <Button
          mode="outlined"
          onPress={() => setSelectedScan(scan)}
          style={styles.actionButton}
              icon="eye"
        >
              Details
        </Button>
        <Button
          mode="contained"
              onPress={() => {
                setSelectedScan(scan);
                setShowVulnerabilities(true);
              }}
          style={styles.actionButton}
              icon="bug"
              buttonColor={COLORS.primary}
              textColor="#fff"
        >
              Vulnerabilities
        </Button>
      </Card.Actions>
        </LinearGradient>
    </Card>
  );
  }, [getStatusInfo]);

  // Render vulnerability card with enhanced UI
  const renderVulnerabilityCard = useCallback((vuln: any) => {
    const severityColor = getSeverityColor(vuln.severity || 'medium');

    return (
    <Card key={vuln.id} style={styles.vulnCard}>
      <Card.Content>
        <View style={styles.vulnHeader}>
            <Text style={styles.vulnTitle} numberOfLines={2}>
              {vuln.message}
            </Text>
          <Chip
            mode="outlined"
              textStyle={{ color: severityColor, fontWeight: '600' }}
              style={{ borderColor: severityColor, backgroundColor: `${severityColor}15` }}
          >
              {vuln.severity?.toUpperCase() || 'MEDIUM'}
          </Chip>
        </View>
        
        <View style={styles.vulnDetails}>
            <View style={styles.vulnDetailRow}>
            <Icon name="file-code" size={16} color={COLORS.gray} />
              <Text style={styles.vulnDetailText}>
            {vuln.file_path}:{vuln.line_number}
          </Text>
            </View>
            {vuln.rule_id && (
              <View style={styles.vulnDetailRow}>
            <Icon name="shield-alert" size={16} color={COLORS.gray} />
                <Text style={styles.vulnDetailText}>Rule: {vuln.rule_id}</Text>
              </View>
            )}
            {vuln.rule_category && (
              <View style={styles.vulnDetailRow}>
                <Icon name="tag" size={16} color={COLORS.gray} />
                <Text style={styles.vulnDetailText}>{vuln.rule_category}</Text>
              </View>
            )}
        </View>
        
          {vuln.message && (
            <>
        <Divider style={styles.divider} />
              <Text style={styles.vulnDescription} numberOfLines={3}>
                {vuln.message}
              </Text>
            </>
          )}
      </Card.Content>
    </Card>
  );
  }, [getSeverityColor]);

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor={COLORS.primary} />
      
      {/* Header */}
      <LinearGradient colors={[COLORS.primary, COLORS.primary + 'DD']} style={styles.header}>
        <Text style={styles.headerTitle}>SAST Security Testing</Text>
        <Text style={styles.headerSubtitle}>Static Application Security Testing</Text>
      </LinearGradient>

      {/* Content */}
      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl 
            refreshing={scansLoading} 
            onRefresh={() => {}}
            colors={[COLORS.primary]}
            tintColor={COLORS.primary}
          />
        }
        showsVerticalScrollIndicator={false}
      >
        {/* Statistics Cards */}
            <View style={styles.statsContainer}>
              <Card style={styles.statCard}>
            <Card.Content style={styles.statCardContent}>
              <Icon name="shield-check" size={32} color={COLORS.primary} />
              <Text style={styles.statValue}>{mockScans.length}</Text>
                  <Text style={styles.statTitle}>Total Scans</Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
            <Card.Content style={styles.statCardContent}>
              <Icon name="play-circle" size={32} color={COLORS.warning} />
                  <Text style={styles.statValue}>
                {mockScans.filter(s => s.status === 'RUNNING').length}
                  </Text>
              <Text style={styles.statTitle}>Active Scans</Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
            <Card.Content style={styles.statCardContent}>
              <Icon name="bug" size={32} color={COLORS.error} />
                  <Text style={styles.statValue}>
                {mockScans.reduce((sum, scan) => sum + (scan.vulnerabilities_found || 0), 0)}
                  </Text>
              <Text style={styles.statTitle}>Vulnerabilities</Text>
                </Card.Content>
              </Card>
            </View>

        {/* Recent Scans Section */}
        <View style={styles.sectionContainer}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionTitle}>Recent Scans</Text>
            <TouchableOpacity onPress={() => setShowNewScanModal(true)}>
              <Icon name="plus-circle" size={24} color={COLORS.primary} />
            </TouchableOpacity>
          </View>
          
          {scansLoading ? (
            <View style={styles.loadingContainer}>
              <ActivityIndicator size="large" color={COLORS.primary} />
              <Text style={styles.loadingText}>Loading SAST scans...</Text>
            </View>
          ) : mockScans.length > 0 ? (
            mockScans.map(renderScanCard)
          ) : (
              <Card style={styles.emptyCard}>
              <Card.Content style={styles.emptyCardContent}>
                <Icon name="shield-off" size={64} color={COLORS.gray} />
                  <Text style={styles.emptyText}>No SAST scans found</Text>
                  <Text style={styles.emptySubtext}>
                    Start your first security scan to identify vulnerabilities
                  </Text>
                <Button 
                  mode="contained" 
                  onPress={() => setShowNewScanModal(true)}
                  style={styles.startFirstScanButton}
                  buttonColor={COLORS.primary}
                  textColor="#fff"
                >
                  Start First Scan
                </Button>
                </Card.Content>
              </Card>
            )}
        </View>
      </ScrollView>

      {/* FAB for quick actions */}
      <FAB
        icon="plus"
        style={styles.fab}
        onPress={() => setShowNewScanModal(true)}
        label="New Scan"
      />

      {/* New Scan Modal */}
      <Portal>
        <Modal
          visible={showNewScanModal}
          onDismiss={() => setShowNewScanModal(false)}
          contentContainerStyle={styles.modalContainer}
        >
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>Start New SAST Scan</Text>
            <TouchableOpacity onPress={() => setShowNewScanModal(false)}>
              <Icon name="close" size={24} color={COLORS.gray} />
            </TouchableOpacity>
          </View>
          
          <TextInput
            label="Project Name"
            value={newScanData.name}
            onChangeText={(text) => setNewScanData(prev => ({ ...prev, name: text }))}
            style={styles.modalInput}
            mode="outlined"
          />
          
          <TextInput
            label="Repository URL"
            value={newScanData.repository_url}
            onChangeText={(text) => setNewScanData(prev => ({ ...prev, repository_url: text }))}
            style={styles.modalInput}
            mode="outlined"
            placeholder="https://github.com/user/repo"
          />
          
          <TextInput
            label="Branch"
            value={newScanData.branch}
            onChangeText={(text) => setNewScanData(prev => ({ ...prev, branch: text }))}
            style={styles.modalInput}
            mode="outlined"
          />
          
          <TextInput
            label="Language"
            value={newScanData.language}
            onChangeText={(text) => setNewScanData(prev => ({ ...prev, language: text }))}
            style={styles.modalInput}
            mode="outlined"
            placeholder="auto"
          />
          
          <View style={styles.modalActions}>
            <Button 
              mode="outlined" 
              onPress={() => setShowNewScanModal(false)}
              style={styles.modalButton}
            >
              Cancel
            </Button>
            <Button 
              mode="contained" 
              onPress={handleStartScan}
              loading={scansLoading}
              style={styles.modalButton}
              buttonColor={COLORS.primary}
              textColor="#fff"
            >
              Start Scan
            </Button>
          </View>
        </Modal>
      </Portal>

      {/* Vulnerabilities Modal */}
      <Portal>
        <Modal
          visible={showVulnerabilities}
          onDismiss={() => setShowVulnerabilities(false)}
          contentContainerStyle={styles.vulnModalContainer}
        >
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>
              Vulnerabilities - {selectedScan?.project_name}
                  </Text>
            <TouchableOpacity onPress={() => setShowVulnerabilities(false)}>
              <Icon name="close" size={24} color={COLORS.gray} />
                  </TouchableOpacity>
                </View>
                
          {/* Filters */}
          <View style={styles.filterContainer}>
            <TextInput
              label="Search vulnerabilities"
              value={searchTerm}
              onChangeText={setSearchTerm}
              style={styles.searchInput}
              mode="outlined"
              left={<TextInput.Icon icon="magnify" />}
            />
            
            <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.severityFilters}>
              {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
                <Chip
                  key={severity}
                  mode={filterSeverity === severity ? 'contained' : 'outlined'}
                  onPress={() => setFilterSeverity(severity)}
                  style={styles.severityChip}
                  textStyle={{ color: filterSeverity === severity ? '#fff' : getSeverityColor(severity) }}
                >
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                </Chip>
              ))}
            </ScrollView>
          </View>
          
          {/* Vulnerabilities List */}
          <ScrollView style={styles.vulnList}>
                {vulnLoading ? (
              <View style={styles.loadingContainer}>
                  <ActivityIndicator size="large" color={COLORS.primary} />
                <Text style={styles.loadingText}>Loading vulnerabilities...</Text>
              </View>
            ) : filteredVulnerabilities().length > 0 ? (
              filteredVulnerabilities().map(renderVulnerabilityCard)
            ) : (
              <View style={styles.emptyVulnContainer}>
                <Icon name="shield-check" size={64} color={COLORS.gray} />
                <Text style={styles.emptyVulnText}>No vulnerabilities found</Text>
                <Text style={styles.emptyVulnSubtext}>
                  {searchTerm || filterSeverity !== 'all' 
                    ? 'Try adjusting your filters' 
                    : 'Great! No security issues detected'
                  }
                </Text>
              </View>
        )}
      </ScrollView>
        </Modal>
      </Portal>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.background,
  },
  header: {
    paddingTop: 50,
    paddingBottom: 20,
    paddingHorizontal: 20,
  },
  headerTitle: {
    fontSize: 28,
    fontFamily: FONTS.bold,
    color: '#fff',
    marginBottom: 4,
  },
  headerSubtitle: {
    fontSize: 16,
    color: 'rgba(255, 255, 255, 0.8)',
    fontFamily: FONTS.medium,
  },
  content: {
    flex: 1,
    paddingHorizontal: 20,
  },
  statsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 20,
    marginBottom: 30,
  },
  statCard: {
    flex: 1,
    marginHorizontal: 4,
    elevation: 2,
  },
  statCardContent: {
    alignItems: 'center',
    padding: 16,
  },
  statValue: {
    fontSize: 24,
    fontFamily: FONTS.bold,
    color: COLORS.text,
    marginTop: 8,
    marginBottom: 4,
  },
  statTitle: {
    fontSize: 12,
    color: COLORS.textSecondary,
    fontFamily: FONTS.medium,
    textAlign: 'center',
  },
  sectionContainer: {
    marginBottom: 30,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  sectionTitle: {
    fontSize: 20,
    fontFamily: FONTS.bold,
    color: COLORS.text,
  },
  scanCard: {
    marginBottom: 16,
    elevation: 4,
    borderRadius: 12,
    overflow: 'hidden',
  },
  cardGradient: {
    borderRadius: 12,
  },
  scanHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 16,
  },
  scanInfo: {
    flex: 1,
    marginRight: 12,
  },
  projectName: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.text,
    marginBottom: 4,
  },
  scanType: {
    fontSize: 14,
    color: COLORS.textSecondary,
    fontFamily: FONTS.medium,
  },
  progressContainer: {
    marginBottom: 16,
  },
  progressText: {
    fontSize: 12,
    color: COLORS.textSecondary,
    fontFamily: FONTS.medium,
    marginBottom: 8,
  },
  progressBar: {
    height: 6,
    borderRadius: 3,
  },
  vulnerabilityStats: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  statItem: {
    alignItems: 'center',
    flex: 1,
  },
  statNumber: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    marginBottom: 4,
  },
  statLabel: {
    fontSize: 10,
    color: COLORS.textSecondary,
    fontFamily: FONTS.medium,
    textAlign: 'center',
  },
  scanDetails: {
    marginBottom: 16,
  },
  scanDetail: {
    fontSize: 12,
    color: COLORS.textSecondary,
    fontFamily: FONTS.medium,
    marginBottom: 4,
    flexDirection: 'row',
    alignItems: 'center',
  },
  cardActions: {
    paddingHorizontal: 16,
    paddingBottom: 16,
  },
  actionButton: {
    marginRight: 8,
    borderRadius: 8,
  },
  emptyCard: {
    backgroundColor: COLORS.card,
    alignItems: 'center',
    padding: 32,
    elevation: 2,
    borderRadius: 12,
  },
  emptyCardContent: {
    alignItems: 'center',
  },
  emptyText: {
    fontSize: 18,
    color: COLORS.text,
    fontFamily: FONTS.bold,
    textAlign: 'center',
    marginTop: 16,
    marginBottom: 8,
  },
  emptySubtext: {
    fontSize: 14,
    color: COLORS.textSecondary,
    fontFamily: FONTS.regular,
    textAlign: 'center',
    marginBottom: 20,
  },
  startFirstScanButton: {
    borderRadius: 8,
  },
  fab: {
    position: 'absolute',
    margin: 16,
    right: 0,
    bottom: 0,
    backgroundColor: COLORS.primary,
  },
  modalContainer: {
    backgroundColor: COLORS.card,
    margin: 20,
    borderRadius: 12,
    padding: 20,
    maxHeight: height * 0.8,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  modalTitle: {
    fontSize: 20,
    fontFamily: FONTS.bold,
    color: COLORS.text,
  },
  modalInput: {
    marginBottom: 16,
  },
  modalActions: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    marginTop: 20,
  },
  modalButton: {
    marginLeft: 12,
    borderRadius: 8,
  },
  vulnModalContainer: {
    backgroundColor: COLORS.card,
    margin: 20,
    borderRadius: 12,
    padding: 20,
    maxHeight: height * 0.9,
  },
  filterContainer: {
    marginBottom: 20,
  },
  searchInput: {
    marginBottom: 16,
  },
  severityFilters: {
    marginBottom: 16,
  },
  severityChip: {
    marginRight: 8,
  },
  vulnList: {
    flex: 1,
  },
  vulnCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
    elevation: 2,
    borderRadius: 8,
  },
  vulnHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 12,
  },
  vulnTitle: {
    fontSize: 16,
    fontFamily: FONTS.bold,
    color: COLORS.text,
    flex: 1,
    marginRight: 12,
  },
  vulnDetails: {
    marginBottom: 12,
  },
  vulnDetailRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  vulnDetailText: {
    fontSize: 12,
    color: COLORS.textSecondary,
    fontFamily: FONTS.medium,
    marginLeft: 8,
  },
  divider: {
    marginVertical: 12,
    backgroundColor: COLORS.border,
  },
  vulnDescription: {
    fontSize: 14,
    color: COLORS.textSecondary,
    fontFamily: FONTS.regular,
    lineHeight: 20,
  },
  loadingContainer: {
    alignItems: 'center',
    padding: 40,
  },
  loadingText: {
    fontSize: 16,
    color: COLORS.textSecondary,
    fontFamily: FONTS.medium,
    marginTop: 16,
  },
  errorContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 40,
  },
  errorTitle: {
    fontSize: 20,
    fontFamily: FONTS.bold,
    color: COLORS.text,
    marginTop: 16,
    marginBottom: 8,
  },
  errorMessage: {
    fontSize: 16,
    color: COLORS.textSecondary,
    fontFamily: FONTS.regular,
    textAlign: 'center',
    marginBottom: 24,
  },
  retryButton: {
    borderRadius: 8,
  },
  emptyVulnContainer: {
    alignItems: 'center',
    padding: 40,
  },
  emptyVulnText: {
    fontSize: 18,
    color: COLORS.text,
    fontFamily: FONTS.bold,
    marginTop: 16,
    marginBottom: 8,
  },
  emptyVulnSubtext: {
    fontSize: 14,
    color: COLORS.textSecondary,
    fontFamily: FONTS.regular,
    textAlign: 'center',
  },
});

export default SASTScreen; 