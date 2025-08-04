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
import { Card, Button, Chip, ProgressBar, Divider, TextInput } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { COLORS, SIZES, FONTS } from '../../constants/theme';

interface DASTScan {
  id: string;
  target_url: string;
  scan_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  scan_type: string;
  created_at: string;
  completed_at?: string;
  vulnerabilities_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_duration?: number;
}

interface DASTVulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  url: string;
  parameter: string;
  payload: string;
  cwe_id: string;
  cvss_score: number;
  remediation: string;
  evidence: string;
}

const DASTScreen: React.FC = () => {
  const [selectedScan, setSelectedScan] = useState<DASTScan | null>(null);
  const [showVulnerabilities, setShowVulnerabilities] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [scanName, setScanName] = useState('');
  const [showNewScanForm, setShowNewScanForm] = useState(false);
  const queryClient = useQueryClient();

  // Fetch DAST scans
  const { data: scans, isLoading: scansLoading, refetch: refetchScans } = useQuery({
    queryKey: ['dast-scans'],
    queryFn: async () => {
      const response = await fetch('http://localhost:8000/api/v1/dast/scans');
      if (!response.ok) throw new Error('Failed to fetch scans');
      return response.json();
    },
  });

  // Fetch vulnerabilities for selected scan
  const { data: vulnerabilities, isLoading: vulnLoading } = useQuery({
    queryKey: ['dast-vulnerabilities', selectedScan?.id],
    queryFn: async () => {
      if (!selectedScan) return [];
      const response = await fetch(`http://localhost:8000/api/v1/dast/scans/${selectedScan.id}/vulnerabilities`);
      if (!response.ok) throw new Error('Failed to fetch vulnerabilities');
      return response.json();
    },
    enabled: !!selectedScan,
  });

  // Start new scan mutation
  const startScanMutation = useMutation({
    mutationFn: async (scanData: { target_url: string; scan_name: string; scan_type: string }) => {
      const response = await fetch('http://localhost:8000/api/v1/dast/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanData),
      });
      if (!response.ok) throw new Error('Failed to start scan');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dast-scans'] });
      setShowNewScanForm(false);
      setTargetUrl('');
      setScanName('');
      Alert.alert('Success', 'DAST scan started successfully');
    },
    onError: (error) => {
      Alert.alert('Error', 'Failed to start DAST scan');
    },
  });

  const handleStartScan = () => {
    if (!targetUrl.trim() || !scanName.trim()) {
      Alert.alert('Error', 'Please fill in all required fields');
      return;
    }

    startScanMutation.mutate({
      target_url: targetUrl.trim(),
      scan_name: scanName.trim(),
      scan_type: 'comprehensive',
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#FF4444';
      case 'high': return '#FF8800';
      case 'medium': return '#FFCC00';
      case 'low': return '#00CC00';
      default: return COLORS.gray;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#00CC00';
      case 'running': return '#FFCC00';
      case 'failed': return '#FF4444';
      default: return COLORS.gray;
    }
  };

  const renderScanCard = (scan: DASTScan) => (
    <Card key={scan.id} style={styles.scanCard}>
      <Card.Content>
        <View style={styles.scanHeader}>
          <View style={styles.scanInfo}>
            <Text style={styles.scanName}>{scan.scan_name}</Text>
            <Text style={styles.targetUrl}>{scan.target_url}</Text>
          </View>
          <Chip
            mode="outlined"
            textStyle={{ color: getStatusColor(scan.status) }}
            style={{ borderColor: getStatusColor(scan.status) }}
          >
            {scan.status.toUpperCase()}
          </Chip>
        </View>
        
        <View style={styles.vulnerabilityStats}>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FF4444' }]}>
              {scan.critical_count}
            </Text>
            <Text style={styles.statLabel}>Critical</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FF8800' }]}>
              {scan.high_count}
            </Text>
            <Text style={styles.statLabel}>High</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#FFCC00' }]}>
              {scan.medium_count}
            </Text>
            <Text style={styles.statLabel}>Medium</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statNumber, { color: '#00CC00' }]}>
              {scan.low_count}
            </Text>
            <Text style={styles.statLabel}>Low</Text>
          </View>
        </View>

        <View style={styles.scanDetails}>
          <Text style={styles.scanDetail}>
            <Icon name="web" size={16} color={COLORS.gray} />
            {scan.scan_type}
          </Text>
          <Text style={styles.scanDetail}>
            <Icon name="clock-outline" size={16} color={COLORS.gray} />
            {scan.scan_duration ? `${scan.scan_duration}s` : 'N/A'}
          </Text>
          <Text style={styles.scanDetail}>
            <Icon name="calendar" size={16} color={COLORS.gray} />
            {new Date(scan.created_at).toLocaleDateString()}
          </Text>
        </View>
      </Card.Content>
      
      <Card.Actions>
        <Button
          mode="outlined"
          onPress={() => setSelectedScan(scan)}
          style={styles.actionButton}
        >
          View Details
        </Button>
        <Button
          mode="contained"
          onPress={() => setShowVulnerabilities(true)}
          style={styles.actionButton}
        >
          View Vulnerabilities
        </Button>
      </Card.Actions>
    </Card>
  );

  const renderVulnerabilityCard = (vuln: DASTVulnerability) => (
    <Card key={vuln.id} style={styles.vulnCard}>
      <Card.Content>
        <View style={styles.vulnHeader}>
          <Text style={styles.vulnTitle}>{vuln.title}</Text>
          <Chip
            mode="outlined"
            textStyle={{ color: getSeverityColor(vuln.severity) }}
            style={{ borderColor: getSeverityColor(vuln.severity) }}
          >
            {vuln.severity.toUpperCase()}
          </Chip>
        </View>
        
        <Text style={styles.vulnDescription}>{vuln.description}</Text>
        
        <View style={styles.vulnDetails}>
          <Text style={styles.vulnDetail}>
            <Icon name="link" size={16} color={COLORS.gray} />
            {vuln.url}
          </Text>
          <Text style={styles.vulnDetail}>
            <Icon name="code-tags" size={16} color={COLORS.gray} />
            Parameter: {vuln.parameter}
          </Text>
          <Text style={styles.vulnDetail}>
            <Icon name="shield-alert" size={16} color={COLORS.gray} />
            CWE-{vuln.cwe_id}
          </Text>
          <Text style={styles.vulnDetail}>
            <Icon name="chart-line" size={16} color={COLORS.gray} />
            CVSS: {vuln.cvss_score}
          </Text>
        </View>
        
        <Divider style={styles.divider} />
        
        <Text style={styles.evidenceTitle}>Evidence:</Text>
        <Text style={styles.evidenceText}>{vuln.evidence}</Text>
        
        <Text style={styles.remediationTitle}>Remediation:</Text>
        <Text style={styles.remediationText}>{vuln.remediation}</Text>
      </Card.Content>
    </Card>
  );

  const renderNewScanForm = () => (
    <Card style={styles.newScanCard}>
      <Card.Content>
        <Text style={styles.formTitle}>Start New DAST Scan</Text>
        
        <TextInput
          label="Target URL"
          value={targetUrl}
          onChangeText={setTargetUrl}
          mode="outlined"
          style={styles.input}
          placeholder="https://example.com"
          keyboardType="url"
        />
        
        <TextInput
          label="Scan Name"
          value={scanName}
          onChangeText={setScanName}
          mode="outlined"
          style={styles.input}
          placeholder="My Security Scan"
        />
        
        <View style={styles.formActions}>
          <Button
            mode="outlined"
            onPress={() => setShowNewScanForm(false)}
            style={styles.formButton}
          >
            Cancel
          </Button>
          <Button
            mode="contained"
            onPress={handleStartScan}
            loading={startScanMutation.isPending}
            style={styles.formButton}
          >
            Start Scan
          </Button>
        </View>
      </Card.Content>
    </Card>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>DAST Security Testing</Text>
        <Button
          mode="contained"
          onPress={() => setShowNewScanForm(true)}
          style={styles.startScanButton}
        >
          New Scan
        </Button>
      </View>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={scansLoading} onRefresh={refetchScans} />
        }
      >
        {showNewScanForm && renderNewScanForm()}

        {scansLoading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color={COLORS.primary} />
            <Text style={styles.loadingText}>Loading DAST scans...</Text>
          </View>
        ) : (
          <>
            <View style={styles.statsContainer}>
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Total Scans</Text>
                  <Text style={styles.statValue}>{scans?.length || 0}</Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Active Scans</Text>
                  <Text style={styles.statValue}>
                    {scans?.filter(s => s.status === 'running').length || 0}
                  </Text>
                </Card.Content>
              </Card>
              
              <Card style={styles.statCard}>
                <Card.Content>
                  <Text style={styles.statTitle}>Total Vulnerabilities</Text>
                  <Text style={styles.statValue}>
                    {scans?.reduce((sum, scan) => sum + scan.vulnerabilities_count, 0) || 0}
                  </Text>
                </Card.Content>
              </Card>
            </View>

            <Text style={styles.sectionTitle}>Recent Scans</Text>
            
            {scans?.map(renderScanCard) || (
              <Card style={styles.emptyCard}>
                <Card.Content>
                  <Text style={styles.emptyText}>No DAST scans found</Text>
                  <Text style={styles.emptySubtext}>
                    Start your first dynamic security scan to identify vulnerabilities
                  </Text>
                </Card.Content>
              </Card>
            )}

            {showVulnerabilities && selectedScan && (
              <View style={styles.vulnerabilitiesSection}>
                <View style={styles.sectionHeader}>
                  <Text style={styles.sectionTitle}>
                    Vulnerabilities - {selectedScan.scan_name}
                  </Text>
                  <TouchableOpacity
                    onPress={() => setShowVulnerabilities(false)}
                    style={styles.closeButton}
                  >
                    <Icon name="close" size={24} color={COLORS.white} />
                  </TouchableOpacity>
                </View>
                
                {vulnLoading ? (
                  <ActivityIndicator size="large" color={COLORS.primary} />
                ) : (
                  vulnerabilities?.map(renderVulnerabilityCard) || (
                    <Text style={styles.emptyText}>No vulnerabilities found</Text>
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
  startScanButton: {
    backgroundColor: COLORS.primary,
  },
  content: {
    flex: 1,
    padding: 16,
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
  newScanCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  formTitle: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 16,
  },
  input: {
    marginBottom: 16,
    backgroundColor: COLORS.dark,
  },
  formActions: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
  },
  formButton: {
    marginLeft: 8,
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
  scanCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  scanHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  scanInfo: {
    flex: 1,
  },
  scanName: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  targetUrl: {
    fontSize: 14,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  vulnerabilityStats: {
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
  },
  statLabel: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
  },
  scanDetails: {
    marginBottom: 12,
  },
  scanDetail: {
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
  vulnerabilitiesSection: {
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
  vulnCard: {
    marginBottom: 16,
    backgroundColor: COLORS.card,
  },
  vulnHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  vulnTitle: {
    fontSize: 16,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    flex: 1,
    marginRight: 12,
  },
  vulnDescription: {
    fontSize: 14,
    color: COLORS.lightGray,
    fontFamily: FONTS.regular,
    marginBottom: 12,
  },
  vulnDetails: {
    marginBottom: 12,
  },
  vulnDetail: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
    marginBottom: 4,
  },
  divider: {
    marginVertical: 12,
    backgroundColor: COLORS.border,
  },
  evidenceTitle: {
    fontSize: 14,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 8,
  },
  evidenceText: {
    fontSize: 12,
    color: COLORS.lightGray,
    fontFamily: FONTS.regular,
    marginBottom: 12,
  },
  remediationTitle: {
    fontSize: 14,
    fontFamily: FONTS.bold,
    color: COLORS.white,
    marginBottom: 8,
  },
  remediationText: {
    fontSize: 12,
    color: COLORS.lightGray,
    fontFamily: FONTS.regular,
  },
});

export default DASTScreen; 