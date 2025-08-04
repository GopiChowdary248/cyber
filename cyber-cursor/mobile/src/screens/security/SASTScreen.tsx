import React, { useState, useEffect } from 'react';
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
import { Card, Button, Chip, ProgressBar, Divider } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { COLORS, SIZES, FONTS } from '../../constants/theme';

interface SASTScan {
  id: string;
  project_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  scan_type: string;
  created_at: string;
  completed_at?: string;
  vulnerabilities_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

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

const SASTScreen: React.FC = () => {
  const [selectedScan, setSelectedScan] = useState<SASTScan | null>(null);
  const [showVulnerabilities, setShowVulnerabilities] = useState(false);
  const queryClient = useQueryClient();

  // Fetch SAST scans
  const { data: scans, isLoading: scansLoading, refetch: refetchScans } = useQuery({
    queryKey: ['sast-scans'],
    queryFn: async () => {
      const response = await fetch('http://localhost:8000/api/v1/sast/scans');
      if (!response.ok) throw new Error('Failed to fetch scans');
      return response.json();
    },
  });

  // Fetch vulnerabilities for selected scan
  const { data: vulnerabilities, isLoading: vulnLoading } = useQuery({
    queryKey: ['sast-vulnerabilities', selectedScan?.id],
    queryFn: async () => {
      if (!selectedScan) return [];
      const response = await fetch(`http://localhost:8000/api/v1/sast/scans/${selectedScan.id}/vulnerabilities`);
      if (!response.ok) throw new Error('Failed to fetch vulnerabilities');
      return response.json();
    },
    enabled: !!selectedScan,
  });

  // Start new scan mutation
  const startScanMutation = useMutation({
    mutationFn: async (projectData: { name: string; repository_url: string }) => {
      const response = await fetch('http://localhost:8000/api/v1/sast/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(projectData),
      });
      if (!response.ok) throw new Error('Failed to start scan');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sast-scans'] });
      Alert.alert('Success', 'SAST scan started successfully');
    },
    onError: (error) => {
      Alert.alert('Error', 'Failed to start SAST scan');
    },
  });

  const handleStartScan = () => {
    Alert.prompt(
      'Start New SAST Scan',
      'Enter project details:',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Start',
          onPress: (projectName) => {
            if (projectName) {
              startScanMutation.mutate({
                name: projectName,
                repository_url: 'https://github.com/example/project',
              });
            }
          },
        },
      ],
      'plain-text'
    );
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

  const renderScanCard = (scan: SASTScan) => (
    <Card key={scan.id} style={styles.scanCard}>
      <Card.Content>
        <View style={styles.scanHeader}>
          <View style={styles.scanInfo}>
            <Text style={styles.projectName}>{scan.project_name}</Text>
            <Text style={styles.scanType}>{scan.scan_type}</Text>
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

        <Text style={styles.scanDate}>
          Created: {new Date(scan.created_at).toLocaleDateString()}
        </Text>
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

  const renderVulnerabilityCard = (vuln: Vulnerability) => (
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
            <Icon name="file-code" size={16} color={COLORS.gray} />
            {vuln.file_path}:{vuln.line_number}
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
        
        <Text style={styles.remediationTitle}>Remediation:</Text>
        <Text style={styles.remediationText}>{vuln.remediation}</Text>
      </Card.Content>
    </Card>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>SAST Security Testing</Text>
        <Button
          mode="contained"
          onPress={handleStartScan}
          loading={startScanMutation.isPending}
          style={styles.startScanButton}
        >
          Start New Scan
        </Button>
      </View>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={scansLoading} onRefresh={refetchScans} />
        }
      >
        {scansLoading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color={COLORS.primary} />
            <Text style={styles.loadingText}>Loading SAST scans...</Text>
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
                  <Text style={styles.emptyText}>No SAST scans found</Text>
                  <Text style={styles.emptySubtext}>
                    Start your first security scan to identify vulnerabilities
                  </Text>
                </Card.Content>
              </Card>
            )}

            {showVulnerabilities && selectedScan && (
              <View style={styles.vulnerabilitiesSection}>
                <View style={styles.sectionHeader}>
                  <Text style={styles.sectionTitle}>
                    Vulnerabilities - {selectedScan.project_name}
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
  projectName: {
    fontSize: 18,
    fontFamily: FONTS.bold,
    color: COLORS.white,
  },
  scanType: {
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
  scanDate: {
    fontSize: 12,
    color: COLORS.gray,
    fontFamily: FONTS.medium,
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

export default SASTScreen; 