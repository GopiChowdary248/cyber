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
  Dimensions,
} from 'react-native';
import { LinearGradient } from 'react-native-linear-gradient';
import { Card, Title, Paragraph, Button, Chip, FAB, Portal, Dialog, Tab, TabView, DataTable, ProgressBar, Searchbar, Menu, Divider } from 'react-native-paper';
import { LineChart, PieChart } from 'react-native-chart-kit';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService, SASTProject, SASTScan, SASTIssue, SASTSecurityHotspot, SASTQualityGate, SASTCodeCoverage, SASTOverview } from '../services/APIService';

const { width, height } = Dimensions.get('window');

const SASTEnhancedScreen: React.FC = ({ navigation }: any) => {
  const [index, setIndex] = useState(0);
  const [routes] = useState([
    { key: 'overview', title: 'Overview', icon: 'view-dashboard' },
    { key: 'projects', title: 'Projects', icon: 'folder-multiple' },
    { key: 'scans', title: 'Scans', icon: 'shield-scan' },
    { key: 'hotspots', title: 'Hotspots', icon: 'alert-circle' },
    { key: 'quality', title: 'Quality Gates', icon: 'gate' },
    { key: 'coverage', title: 'Coverage', icon: 'chart-line' },
    { key: 'issues', title: 'Issues', icon: 'bug' },
  ]);

  // State for data
  const [overview, setOverview] = useState<SASTOverview | null>(null);
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [scans, setScans] = useState<SASTScan[]>([]);
  const [hotspots, setHotspots] = useState<SASTSecurityHotspot[]>([]);
  const [qualityGates, setQualityGates] = useState<SASTQualityGate[]>([]);
  const [coverage, setCoverage] = useState<SASTCodeCoverage[]>([]);
  const [issues, setIssues] = useState<SASTIssue[]>([]);
  
  // UI State
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedProject, setSelectedProject] = useState<SASTProject | null>(null);
  const [newScanModal, setNewScanModal] = useState(false);
  const [newScanData, setNewScanData] = useState({
    branch: 'main',
    scan_type: 'FULL_SCAN',
  });

  // Filter and Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sortBy, setSortBy] = useState('date');
  const [sortOrder, setSortOrder] = useState('desc');

  // Modal States
  const [hotspotReviewModal, setHotspotReviewModal] = useState(false);
  const [selectedHotspot, setSelectedHotspot] = useState<SASTSecurityHotspot | null>(null);
  const [reviewComment, setReviewComment] = useState('');
  const [reviewResolution, setReviewResolution] = useState<'SAFE' | 'FIXED' | 'ACKNOWLEDGED'>('SAFE');

  const apiService = new APIService();

  const fetchData = async () => {
    try {
      setLoading(true);
      
      // Fetch all SAST data
      const [projectsData, overviewData] = await Promise.all([
        apiService.getSASTProjects(),
        apiService.getSASTOverview(1), // Default to first project
      ]);
      
      setProjects(projectsData);
      setOverview(overviewData);
      
      if (projectsData.length > 0) {
        const projectId = projectsData[0].id;
        setSelectedProject(projectsData[0]);
        
        const [scansData, hotspotsData, qualityData, coverageData, issuesData] = await Promise.all([
          apiService.getSASTScans(projectId),
          apiService.getSASTSecurityHotspots(projectId),
          apiService.getSASTQualityGates(projectId),
          apiService.getSASTCodeCoverage(projectId),
          apiService.getSASTIssues(projectId),
        ]);
        
        setScans(scansData);
        setHotspots(hotspotsData);
        setQualityGates(qualityData);
        setCoverage(coverageData);
        setIssues(issuesData);
      }
    } catch (error) {
      Alert.alert('Error', 'Failed to fetch SAST data');
    } finally {
      setLoading(false);
    }
  };

  const startNewScan = async () => {
    if (!selectedProject) {
      Alert.alert('Error', 'Please select a project first');
      return;
    }

    try {
      await apiService.startSASTScan(selectedProject.id, newScanData);
      setNewScanModal(false);
      setNewScanData({ branch: 'main', scan_type: 'FULL_SCAN' });
      fetchData();
      Alert.alert('Success', 'SAST scan started successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to start SAST scan');
    }
  };

  const reviewHotspot = async () => {
    if (!selectedHotspot) return;

    try {
      // Here you would call the API to update the hotspot
      // await apiService.updateSecurityHotspot(selectedHotspot.id, {
      //   status: 'REVIEWED',
      //   resolution: reviewResolution,
      //   review_comment: reviewComment,
      // });

      setHotspotReviewModal(false);
      setSelectedHotspot(null);
      setReviewComment('');
      setReviewResolution('SAFE');
      fetchData();
      Alert.alert('Success', 'Security hotspot reviewed successfully');
    } catch (error) {
      Alert.alert('Error', 'Failed to review security hotspot');
    }
  };

  const filterData = (data: any[], searchField: string) => {
    let filtered = data;

    // Search filter
    if (searchQuery) {
      filtered = filtered.filter(item => 
        item[searchField]?.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Status filter
    if (statusFilter !== 'all') {
      filtered = filtered.filter(item => item.status === statusFilter);
    }

    // Severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(item => item.severity === severityFilter);
    }

    // Sort
    filtered.sort((a, b) => {
      let aValue, bValue;
      
      switch (sortBy) {
        case 'date':
          aValue = new Date(a.created_at).getTime();
          bValue = new Date(b.created_at).getTime();
          break;
        case 'severity':
          aValue = getSeverityWeight(a.severity);
          bValue = getSeverityWeight(b.severity);
          break;
        case 'name':
          aValue = a.rule_name || a.name || '';
          bValue = b.rule_name || b.name || '';
          break;
        default:
          aValue = a[sortBy] || 0;
          bValue = b[sortBy] || 0;
      }

      if (sortOrder === 'desc') {
        return bValue > aValue ? 1 : -1;
      } else {
        return aValue > bValue ? 1 : -1;
      }
    });

    return filtered;
  };

  const getSeverityWeight = (severity: string) => {
    switch (severity) {
      case 'BLOCKER': return 5;
      case 'CRITICAL': return 4;
      case 'MAJOR': return 3;
      case 'MINOR': return 2;
      case 'INFO': return 1;
      default: return 0;
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED': return '#4CAF50';
      case 'RUNNING': return '#2196F3';
      case 'PENDING': return '#FF9800';
      case 'FAILED': return '#F44336';
      case 'CANCELLED': return '#9E9E9E';
      default: return '#9E9E9E';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'BLOCKER': return '#D32F2F';
      case 'CRITICAL': return '#F44336';
      case 'MAJOR': return '#FF5722';
      case 'MINOR': return '#FF9800';
      case 'INFO': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  const getQualityGateColor = (status: string) => {
    switch (status) {
      case 'PASSED': return '#4CAF50';
      case 'FAILED': return '#F44336';
      case 'WARN': return '#FF9800';
      default: return '#9E9E9E';
    }
  };

  const getHotspotStatusColor = (status: string) => {
    switch (status) {
      case 'TO_REVIEW': return '#FF9800';
      case 'REVIEWED': return '#2196F3';
      case 'SAFE': return '#4CAF50';
      case 'FIXED': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading SAST data...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <LinearGradient colors={['#4CAF50', '#45a049']} style={styles.header}>
        <Text style={styles.headerTitle}>SAST Analysis</Text>
        <Text style={styles.headerSubtitle}>Static Application Security Testing</Text>
      </LinearGradient>

      <TabView
        navigationState={{ index, routes }}
        renderScene={({ route }) => {
          switch (route.key) {
            case 'overview':
              return (
                <ScrollView style={styles.tabContent}>
                  {overview && (
                    <>
                      {/* Summary Cards */}
                      <View style={styles.summaryGrid}>
                        <Card style={styles.summaryCard}>
                          <Card.Content>
                            <Icon name="folder-multiple" size={32} color="#4CAF50" />
                            <Text style={styles.summaryValue}>{overview.total_projects}</Text>
                            <Text style={styles.summaryLabel}>Projects</Text>
                          </Card.Content>
                        </Card>
                        
                        <Card style={styles.summaryCard}>
                          <Card.Content>
                            <Icon name="shield-scan" size={32} color="#2196F3" />
                            <Text style={styles.summaryValue}>{overview.total_scans}</Text>
                            <Text style={styles.summaryLabel}>Scans</Text>
                          </Card.Content>
                        </Card>
                        
                        <Card style={styles.summaryCard}>
                          <Card.Content>
                            <Icon name="bug" size={32} color="#FF5722" />
                            <Text style={styles.summaryValue}>{overview.total_issues}</Text>
                            <Text style={styles.summaryLabel}>Issues</Text>
                          </Card.Content>
                        </Card>
                        
                        <Card style={styles.summaryCard}>
                          <Card.Content>
                            <Icon name="alert-circle" size={32} color="#FF9800" />
                            <Text style={styles.summaryValue}>{overview.total_security_hotspots}</Text>
                            <Text style={styles.summaryLabel}>Hotspots</Text>
                          </Card.Content>
                        </Card>
                      </View>

                      {/* Security Score */}
                      <Card style={styles.metricCard}>
                        <Card.Content>
                          <Title>Security Score</Title>
                          <View style={styles.scoreContainer}>
                            <Text style={[styles.securityScore, { color: overview.security_score >= 80 ? '#4CAF50' : overview.security_score >= 60 ? '#FF9800' : '#F44336' }]}>
                              {overview.security_score}%
                            </Text>
                            <ProgressBar 
                              progress={overview.security_score / 100} 
                              color={overview.security_score >= 80 ? '#4CAF50' : overview.security_score >= 60 ? '#FF9800' : '#F44336'}
                              style={styles.progressBar}
                            />
                          </View>
                        </Card.Content>
                      </Card>

                      {/* Issue Distribution */}
                      <Card style={styles.metricCard}>
                        <Card.Content>
                          <Title>Issue Distribution</Title>
                          <View style={styles.issueDistribution}>
                            <View style={styles.issueItem}>
                              <Text style={[styles.issueCount, { color: '#D32F2F' }]}>{overview.blocker_issues}</Text>
                              <Text style={styles.issueLabel}>Blocker</Text>
                            </View>
                            <View style={styles.issueItem}>
                              <Text style={[styles.issueCount, { color: '#F44336' }]}>{overview.critical_issues}</Text>
                              <Text style={styles.issueLabel}>Critical</Text>
                            </View>
                            <View style={styles.issueItem}>
                              <Text style={[styles.issueCount, { color: '#FF5722' }]}>{overview.high_issues}</Text>
                              <Text style={styles.issueLabel}>High</Text>
                            </View>
                            <View style={styles.issueItem}>
                              <Text style={[styles.issueCount, { color: '#FF9800' }]}>{overview.medium_issues}</Text>
                              <Text style={styles.issueLabel}>Medium</Text>
                            </View>
                            <View style={styles.issueItem}>
                              <Text style={[styles.issueCount, { color: '#4CAF50' }]}>{overview.low_issues}</Text>
                              <Text style={styles.issueLabel}>Low</Text>
                            </View>
                          </View>
                        </Card.Content>
                      </Card>
                    </>
                  )}
                </ScrollView>
              );
            case 'projects':
              return (
                <ScrollView style={styles.tabContent}>
                  {projects.map((project) => (
                    <Card key={project.id} style={styles.projectCard}>
                      <Card.Content>
                        <View style={styles.projectHeader}>
                          <View style={styles.projectInfo}>
                            <Title style={styles.projectTitle}>{project.name}</Title>
                            <Text style={styles.projectKey}>{project.key}</Text>
                            <Text style={styles.projectLanguage}>{project.language}</Text>
                          </View>
                          <Chip
                            mode="outlined"
                            textStyle={{ color: getQualityGateColor(project.quality_gate || 'WARN') }}
                            style={[styles.qualityChip, { borderColor: getQualityGateColor(project.quality_gate || 'WARN') }]}
                          >
                            {project.quality_gate || 'WARN'}
                          </Chip>
                        </View>
                        
                        <View style={styles.projectMetrics}>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{project.vulnerability_count || 0}</Text>
                            <Text style={styles.metricLabel}>Vulnerabilities</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{project.bug_count || 0}</Text>
                            <Text style={styles.metricLabel}>Bugs</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{project.code_smell_count || 0}</Text>
                            <Text style={styles.metricLabel}>Code Smells</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{project.security_hotspot_count || 0}</Text>
                            <Text style={styles.metricLabel}>Hotspots</Text>
                          </View>
                        </View>
                      </Card.Content>
                    </Card>
                  ))}
                </ScrollView>
              );
            case 'scans':
              return (
                <ScrollView style={styles.tabContent}>
                  {scans.map((scan) => (
                    <Card key={scan.id} style={styles.scanCard}>
                      <Card.Content>
                        <View style={styles.scanHeader}>
                          <View style={styles.scanInfo}>
                            <Title style={styles.scanTitle}>{scan.project_name}</Title>
                            <Text style={styles.scanType}>{scan.scan_type}</Text>
                            <Text style={styles.scanBranch}>Branch: {scan.branch}</Text>
                          </View>
                          <Chip
                            mode="outlined"
                            textStyle={{ color: getStatusColor(scan.status) }}
                            style={[styles.statusChip, { borderColor: getStatusColor(scan.status) }]}
                          >
                            {scan.status}
                          </Chip>
                        </View>
                        
                        {scan.progress !== undefined && (
                          <View style={styles.progressContainer}>
                            <Text style={styles.progressText}>Progress: {scan.progress.toFixed(1)}%</Text>
                            <ProgressBar progress={scan.progress / 100} color={getStatusColor(scan.status)} style={styles.progressBar} />
                          </View>
                        )}
                        
                        <View style={styles.scanMetrics}>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{scan.issues_found || 0}</Text>
                            <Text style={styles.metricLabel}>Issues</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{scan.vulnerabilities_found || 0}</Text>
                            <Text style={styles.metricLabel}>Vulnerabilities</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{scan.bugs_found || 0}</Text>
                            <Text style={styles.metricLabel}>Bugs</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{scan.code_smells_found || 0}</Text>
                            <Text style={styles.metricLabel}>Code Smells</Text>
                          </View>
                        </View>
                      </Card.Content>
                    </Card>
                  ))}
                </ScrollView>
              );
            case 'hotspots':
              return (
                <View style={styles.tabContent}>
                  {/* Search and Filter Bar */}
                  <View style={styles.filterContainer}>
                    <Searchbar
                      placeholder="Search hotspots..."
                      onChangeText={setSearchQuery}
                      value={searchQuery}
                      style={styles.searchBar}
                    />
                    <View style={styles.filterRow}>
                      <Menu
                        visible={false}
                        onDismiss={() => {}}
                        anchor={
                          <Button mode="outlined" onPress={() => {}}>
                            Status: {statusFilter}
                          </Button>
                        }
                      >
                        <Menu.Item onPress={() => setStatusFilter('all')} title="All" />
                        <Menu.Item onPress={() => setStatusFilter('TO_REVIEW')} title="To Review" />
                        <Menu.Item onPress={() => setStatusFilter('REVIEWED')} title="Reviewed" />
                        <Menu.Item onPress={() => setStatusFilter('SAFE')} title="Safe" />
                        <Menu.Item onPress={() => setStatusFilter('FIXED')} title="Fixed" />
                      </Menu>
                    </View>
                  </View>

                  <ScrollView>
                    {filterData(hotspots, 'rule_name').map((hotspot) => (
                      <Card key={hotspot.id} style={styles.hotspotCard}>
                        <Card.Content>
                          <View style={styles.hotspotHeader}>
                            <View style={styles.hotspotInfo}>
                              <Title style={styles.hotspotTitle}>{hotspot.rule_name}</Title>
                              <Text style={styles.hotspotMessage}>{hotspot.message}</Text>
                            </View>
                            <Chip
                              mode="outlined"
                              textStyle={{ color: getHotspotStatusColor(hotspot.status) }}
                              style={[styles.statusChip, { borderColor: getHotspotStatusColor(hotspot.status) }]}
                            >
                              {hotspot.status}
                            </Chip>
                          </View>
                          
                          <View style={styles.hotspotDetails}>
                            <Text style={styles.hotspotDetail}>File: {hotspot.file_path}</Text>
                            <Text style={styles.hotspotDetail}>Line: {hotspot.line_number}</Text>
                            {hotspot.cwe_id && <Text style={styles.hotspotDetail}>CWE: {hotspot.cwe_id}</Text>}
                            {hotspot.cvss_score && <Text style={styles.hotspotDetail}>CVSS: {hotspot.cvss_score}</Text>}
                            {hotspot.owasp_category && <Text style={styles.hotspotDetail}>OWASP: {hotspot.owasp_category}</Text>}
                          </View>
                          
                          {hotspot.description && (
                            <Text style={styles.hotspotDescription}>{hotspot.description}</Text>
                          )}
                          
                          {hotspot.status === 'TO_REVIEW' && (
                            <Button
                              mode="contained"
                              onPress={() => {
                                setSelectedHotspot(hotspot);
                                setHotspotReviewModal(true);
                              }}
                              style={styles.reviewButton}
                            >
                              Review Hotspot
                            </Button>
                          )}
                          
                          {hotspot.review_comment && (
                            <View style={styles.reviewContainer}>
                              <Text style={styles.reviewTitle}>Review Comment:</Text>
                              <Text style={styles.reviewComment}>{hotspot.review_comment}</Text>
                            </View>
                          )}
                        </Card.Content>
                      </Card>
                    ))}
                  </ScrollView>
                </View>
              );
            case 'quality':
              return (
                <ScrollView style={styles.tabContent}>
                  {qualityGates.map((gate) => (
                    <Card key={gate.id} style={styles.qualityGateCard}>
                      <Card.Content>
                        <View style={styles.qualityGateHeader}>
                          <Title style={styles.qualityGateTitle}>Quality Gate</Title>
                          <Chip
                            mode="outlined"
                            textStyle={{ color: getQualityGateColor(gate.status) }}
                            style={[styles.statusChip, { borderColor: getQualityGateColor(gate.status) }]}
                          >
                            {gate.status}
                          </Chip>
                        </View>
                        
                        <View style={styles.qualityGateMetrics}>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{gate.max_blocker_issues || 0}</Text>
                            <Text style={styles.metricLabel}>Max Blocker</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{gate.max_critical_issues || 0}</Text>
                            <Text style={styles.metricLabel}>Max Critical</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{gate.max_major_issues || 0}</Text>
                            <Text style={styles.metricLabel}>Max Major</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{gate.max_debt_ratio || 0}</Text>
                            <Text style={styles.metricLabel}>Max Debt Ratio</Text>
                          </View>
                        </View>
                        
                        <View style={styles.qualityGateRatings}>
                          <Text style={styles.ratingLabel}>Min Security: <Text style={styles.rating}>{gate.min_security_rating || 'N/A'}</Text></Text>
                          <Text style={styles.ratingLabel}>Min Reliability: <Text style={styles.rating}>{gate.min_reliability_rating || 'N/A'}</Text></Text>
                          <Text style={styles.ratingLabel}>Min Maintainability: <Text style={styles.rating}>{gate.min_maintainability_rating || 'N/A'}</Text></Text>
                        </View>
                      </Card.Content>
                    </Card>
                  ))}
                </ScrollView>
              );
            case 'coverage':
              return (
                <ScrollView style={styles.tabContent}>
                  {coverage.map((cov) => (
                    <Card key={cov.id} style={styles.coverageCard}>
                      <Card.Content>
                        <Title style={styles.coverageTitle}>{cov.file_path}</Title>
                        
                        <View style={styles.coverageMetrics}>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{cov.line_coverage.toFixed(1)}%</Text>
                            <Text style={styles.metricLabel}>Line Coverage</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{cov.branch_coverage.toFixed(1)}%</Text>
                            <Text style={styles.metricLabel}>Branch Coverage</Text>
                          </View>
                          <View style={styles.metric}>
                            <Text style={styles.metricValue}>{cov.overall_coverage.toFixed(1)}%</Text>
                            <Text style={styles.metricLabel}>Overall Coverage</Text>
                          </View>
                        </View>
                        
                        <View style={styles.coverageDetails}>
                          <Text style={styles.coverageDetail}>Lines to Cover: {cov.lines_to_cover}</Text>
                          <Text style={styles.coverageDetail}>Covered Lines: {cov.covered_lines}</Text>
                          <Text style={styles.coverageDetail}>Uncovered Lines: {cov.uncovered_lines}</Text>
                          <Text style={styles.coverageDetail}>Conditions to Cover: {cov.conditions_to_cover}</Text>
                          <Text style={styles.coverageDetail}>Covered Conditions: {cov.covered_conditions}</Text>
                          <Text style={styles.coverageDetail}>Uncovered Conditions: {cov.uncovered_conditions}</Text>
                        </View>
                        
                        <View style={styles.coverageProgress}>
                          <Text style={styles.progressText}>Line Coverage</Text>
                          <ProgressBar 
                            progress={cov.line_coverage / 100} 
                            color={cov.line_coverage >= 80 ? '#4CAF50' : cov.line_coverage >= 60 ? '#FF9800' : '#F44336'}
                            style={styles.progressBar}
                          />
                        </View>
                      </Card.Content>
                    </Card>
                  ))}
                </ScrollView>
              );
            case 'issues':
              return (
                <View style={styles.tabContent}>
                  {/* Search and Filter Bar */}
                  <View style={styles.filterContainer}>
                    <Searchbar
                      placeholder="Search issues..."
                      onChangeText={setSearchQuery}
                      value={searchQuery}
                      style={styles.searchBar}
                    />
                    <View style={styles.filterRow}>
                      <Menu
                        visible={false}
                        onDismiss={() => {}}
                        anchor={
                          <Button mode="outlined" onPress={() => {}}>
                            Severity: {severityFilter}
                          </Button>
                        }
                      >
                        <Menu.Item onPress={() => setSeverityFilter('all')} title="All" />
                        <Menu.Item onPress={() => setSeverityFilter('BLOCKER')} title="Blocker" />
                        <Menu.Item onPress={() => setSeverityFilter('CRITICAL')} title="Critical" />
                        <Menu.Item onPress={() => setSeverityFilter('MAJOR')} title="Major" />
                        <Menu.Item onPress={() => setSeverityFilter('MINOR')} title="Minor" />
                        <Menu.Item onPress={() => setSeverityFilter('INFO')} title="Info" />
                      </Menu>
                    </View>
                  </View>

                  <ScrollView>
                    {filterData(issues, 'rule_name').map((issue) => (
                      <Card key={issue.id} style={styles.issueCard}>
                        <Card.Content>
                          <View style={styles.issueHeader}>
                            <View style={styles.issueInfo}>
                              <Title style={styles.issueTitle}>{issue.rule_name}</Title>
                              <Text style={styles.issueMessage}>{issue.message}</Text>
                            </View>
                            <Chip
                              mode="outlined"
                              textStyle={{ color: getSeverityColor(issue.severity) }}
                              style={[styles.severityChip, { borderColor: getSeverityColor(issue.severity) }]}
                            >
                              {issue.severity}
                            </Chip>
                          </View>
                          
                          <View style={styles.issueDetails}>
                            <Text style={styles.issueDetail}>Type: {issue.type}</Text>
                            <Text style={styles.issueDetail}>Status: {issue.status || 'OPEN'}</Text>
                            <Text style={styles.issueDetail}>File: {issue.file_path}</Text>
                            <Text style={styles.issueDetail}>Line: {issue.line_number}</Text>
                            {issue.cwe_id && <Text style={styles.issueDetail}>CWE: {issue.cwe_id}</Text>}
                            {issue.cvss_score && <Text style={styles.issueDetail}>CVSS: {issue.cvss_score}</Text>}
                            {issue.owasp_category && <Text style={styles.issueDetail}>OWASP: {issue.owasp_category}</Text>}
                          </View>
                          
                          {issue.description && (
                            <Text style={styles.issueDescription}>{issue.description}</Text>
                          )}
                          
                          <View style={styles.issueFooter}>
                            <Text style={styles.issueDate}>Created: {new Date(issue.created_at).toLocaleDateString()}</Text>
                            {issue.effort && <Text style={styles.issueDate}>Effort: {issue.effort} minutes</Text>}
                            {issue.debt && <Text style={styles.issueDate}>Debt: {issue.debt} minutes</Text>}
                          </View>
                        </Card.Content>
                      </Card>
                    ))}
                  </ScrollView>
                </View>
              );
            default:
              return (
                <ScrollView style={styles.tabContent}>
                  <Text style={styles.comingSoon}>Coming Soon...</Text>
                </ScrollView>
              );
          }
        }}
        onIndexChange={setIndex}
        renderTabBar={(props) => (
          <TabBar
            {...props}
            scrollEnabled
            indicatorStyle={styles.tabIndicator}
            style={styles.tabBar}
            labelStyle={styles.tabLabel}
            renderIcon={({ route, focused, color }) => (
              <Icon name={route.icon} size={20} color={color} />
            )}
          />
        )}
      />

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
              placeholder="Branch"
              value={newScanData.branch}
              onChangeText={(text) => setNewScanData({ ...newScanData, branch: text })}
            />
            <TextInput
              style={styles.input}
              placeholder="Scan Type"
              value={newScanData.scan_type}
              onChangeText={(text) => setNewScanData({ ...newScanData, scan_type: text })}
            />
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setNewScanModal(false)}>Cancel</Button>
            <Button onPress={startNewScan}>Start Scan</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>

      {/* Hotspot Review Modal */}
      <Portal>
        <Dialog visible={hotspotReviewModal} onDismiss={() => setHotspotReviewModal(false)}>
          <Dialog.Title>Review Security Hotspot</Dialog.Title>
          <Dialog.Content>
            {selectedHotspot && (
              <>
                <Text style={styles.modalTitle}>{selectedHotspot.rule_name}</Text>
                <Text style={styles.modalMessage}>{selectedHotspot.message}</Text>
                
                <Text style={styles.modalLabel}>Resolution:</Text>
                <View style={styles.resolutionButtons}>
                  <Button
                    mode={reviewResolution === 'SAFE' ? 'contained' : 'outlined'}
                    onPress={() => setReviewResolution('SAFE')}
                    style={styles.resolutionButton}
                  >
                    Safe
                  </Button>
                  <Button
                    mode={reviewResolution === 'FIXED' ? 'contained' : 'outlined'}
                    onPress={() => setReviewResolution('FIXED')}
                    style={styles.resolutionButton}
                  >
                    Fixed
                  </Button>
                  <Button
                    mode={reviewResolution === 'ACKNOWLEDGED' ? 'contained' : 'outlined'}
                    onPress={() => setReviewResolution('ACKNOWLEDGED')}
                    style={styles.resolutionButton}
                  >
                    Acknowledged
                  </Button>
                </View>
                
                <Text style={styles.modalLabel}>Review Comment:</Text>
                <TextInput
                  style={styles.textArea}
                  placeholder="Enter your review comment..."
                  value={reviewComment}
                  onChangeText={setReviewComment}
                  multiline
                  numberOfLines={3}
                />
              </>
            )}
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setHotspotReviewModal(false)}>Cancel</Button>
            <Button onPress={reviewHotspot}>Submit Review</Button>
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
  tabBar: {
    backgroundColor: 'white',
    elevation: 2,
  },
  tabIndicator: {
    backgroundColor: '#4CAF50',
  },
  tabLabel: {
    color: '#333',
    fontWeight: '600',
  },
  tabContent: {
    flex: 1,
    padding: 20,
  },
  comingSoon: {
    fontSize: 18,
    textAlign: 'center',
    color: '#666',
    marginTop: 50,
  },
  filterContainer: {
    marginBottom: 20,
  },
  searchBar: {
    marginBottom: 10,
    elevation: 2,
  },
  filterRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  summaryGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  summaryCard: {
    width: (width - 60) / 2,
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  summaryValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 8,
    textAlign: 'center',
  },
  summaryLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
    textAlign: 'center',
  },
  metricCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  scoreContainer: {
    alignItems: 'center',
    marginTop: 10,
  },
  securityScore: {
    fontSize: 48,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  progressBar: {
    height: 8,
    borderRadius: 4,
    width: '100%',
  },
  issueDistribution: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 15,
  },
  issueItem: {
    alignItems: 'center',
  },
  issueCount: {
    fontSize: 20,
    fontWeight: 'bold',
  },
  issueLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
  projectCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  projectHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  projectInfo: {
    flex: 1,
  },
  projectTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  projectKey: {
    fontSize: 14,
    color: '#666',
    marginBottom: 2,
  },
  projectLanguage: {
    fontSize: 12,
    color: '#999',
  },
  qualityChip: {
    marginLeft: 10,
  },
  projectMetrics: {
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
    marginBottom: 2,
  },
  scanBranch: {
    fontSize: 12,
    color: '#999',
  },
  statusChip: {
    marginLeft: 10,
  },
  progressContainer: {
    marginBottom: 15,
  },
  progressText: {
    fontSize: 12,
    color: '#666',
    marginBottom: 5,
  },
  scanMetrics: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 15,
  },
  hotspotCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  hotspotHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  hotspotInfo: {
    flex: 1,
  },
  hotspotTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  hotspotMessage: {
    fontSize: 14,
    color: '#666',
  },
  hotspotDetails: {
    marginBottom: 10,
  },
  hotspotDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  hotspotDescription: {
    fontSize: 14,
    color: '#333',
    marginBottom: 10,
    fontStyle: 'italic',
  },
  reviewButton: {
    marginTop: 10,
    backgroundColor: '#2196F3',
  },
  reviewContainer: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 10,
    marginTop: 10,
  },
  reviewTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 5,
  },
  reviewComment: {
    fontSize: 12,
    color: '#666',
  },
  qualityGateCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  qualityGateHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 15,
  },
  qualityGateTitle: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  qualityGateMetrics: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 15,
  },
  qualityGateRatings: {
    marginBottom: 15,
  },
  ratingLabel: {
    fontSize: 14,
    color: '#666',
    marginBottom: 2,
  },
  rating: {
    fontWeight: 'bold',
  },
  coverageCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  coverageTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 15,
  },
  coverageMetrics: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 15,
  },
  coverageDetails: {
    marginBottom: 15,
  },
  coverageDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  coverageProgress: {
    marginBottom: 10,
  },
  issueCard: {
    marginBottom: 15,
    borderRadius: 12,
    elevation: 2,
  },
  issueHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 15,
  },
  issueInfo: {
    flex: 1,
  },
  issueTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  issueMessage: {
    fontSize: 14,
    color: '#666',
  },
  severityChip: {
    marginLeft: 10,
  },
  issueDetails: {
    marginBottom: 10,
  },
  issueDetail: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  issueDescription: {
    fontSize: 14,
    color: '#333',
    marginBottom: 10,
    fontStyle: 'italic',
  },
  issueFooter: {
    borderTopWidth: 1,
    borderTopColor: '#eee',
    paddingTop: 10,
  },
  issueDate: {
    fontSize: 12,
    color: '#666',
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
  modalTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  modalMessage: {
    fontSize: 14,
    color: '#666',
    marginBottom: 15,
  },
  modalLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 5,
    marginTop: 10,
  },
  resolutionButtons: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 15,
  },
  resolutionButton: {
    flex: 1,
    marginHorizontal: 2,
  },
  textArea: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    textAlignVertical: 'top',
  },
});

export default SASTEnhancedScreen; 