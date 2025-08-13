import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  LinearProgress,
  Alert,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Badge,
  CircularProgress
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Download as DownloadIcon,
  Settings as SettingsIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  Code as CodeIcon,
  TrendingUp as TrendingIcon,
  Assessment as AssessmentIcon,
  Upload as UploadIcon
} from '@mui/icons-material';
import { sastService } from '../../services/sastService';
import { useAuth } from '../../contexts/AuthContext';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`sast-tabpanel-${index}`}
      aria-labelledby={`sast-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const EnhancedSASTDashboard: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  
  // Dashboard data
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [projects, setProjects] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [securityHotspots, setSecurityHotspots] = useState<any[]>([]);
  const [qualityGates, setQualityGates] = useState<any[]>([]);
  const [statistics, setStatistics] = useState<any>(null);
  
  // Scan management
  const [scanning, setScanning] = useState(false);
  const [selectedProject, setSelectedProject] = useState<string>('');
  const [scanConfig, setScanConfig] = useState({
    scan_type: 'full',
    branch: 'main',
    priority: 'normal'
  });
  
  // Modals
  const [showScanModal, setShowScanModal] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  
  // File upload
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadProjectId, setUploadProjectId] = useState<string>('');
  
  // Error handling
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Load dashboard data
  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [
        dashboard,
        projectsData,
        scansData,
        vulnerabilitiesData,
        hotspotsData,
        gatesData,
        statsData
      ] = await Promise.all([
        sastService.getDashboard(),
        sastService.getProjects(),
        sastService.getScans(),
        sastService.getVulnerabilities(),
        sastService.getSecurityHotspots(),
        sastService.getQualityGates(),
        sastService.getStatistics()
      ]);
      
      setDashboardData(dashboard);
      setProjects(projectsData);
      setScans(scansData);
      setVulnerabilities(vulnerabilitiesData);
      setSecurityHotspots(hotspotsData);
      setQualityGates(gatesData);
      setStatistics(statsData);
      
    } catch (err) {
      setError('Failed to load dashboard data');
      console.error('Dashboard load error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Refresh data
  const refreshData = useCallback(async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
  }, [loadDashboardData]);

  // Start scan
  const startScan = useCallback(async () => {
    if (!selectedProject) {
      setError('Please select a project');
      return;
    }
    
    try {
      setScanning(true);
      setError(null);
      
      const scan = await sastService.startScan(selectedProject, scanConfig);
      setSuccess(`Scan started successfully! Scan ID: ${scan.id}`);
      setShowScanModal(false);
      
      // Refresh data after a short delay
      setTimeout(refreshData, 2000);
      
    } catch (err) {
      setError('Failed to start scan');
      console.error('Scan start error:', err);
    } finally {
      setScanning(false);
    }
  }, [selectedProject, scanConfig, refreshData]);

  // Stop scan
  const stopScan = useCallback(async (scanId: string) => {
    try {
      await sastService.stopScan(scanId);
      setSuccess('Scan stopped successfully');
      refreshData();
    } catch (err) {
      setError('Failed to stop scan');
      console.error('Scan stop error:', err);
    }
  }, [refreshData]);

  // Upload and scan file
  const uploadAndScan = useCallback(async () => {
    if (!uploadFile || !uploadProjectId) {
      setError('Please select a file and project');
      return;
    }
    
    try {
      setScanning(true);
      setError(null);
      
      const scan = await sastService.uploadAndScan(uploadFile, uploadProjectId, scanConfig);
      setSuccess(`File uploaded and scan started! Scan ID: ${scan.id}`);
      setShowUploadModal(false);
      setUploadFile(null);
      setUploadProjectId('');
      
      // Refresh data after a short delay
      setTimeout(refreshData, 2000);
      
    } catch (err) {
      setError('Failed to upload and scan file');
      console.error('Upload scan error:', err);
    } finally {
      setScanning(false);
    }
  }, [uploadFile, uploadProjectId, scanConfig, refreshData]);

  // Export report
  const exportReport = useCallback(async (projectId: string, format: 'pdf' | 'csv' | 'json' = 'pdf') => {
    try {
      const blob = await sastService.exportProjectReport(projectId, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sast_report_${projectId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      setError('Failed to export report');
      console.error('Export error:', err);
    }
  }, []);

  // Load data on component mount
  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(refreshData, 30000);
    return () => clearInterval(interval);
  }, [refreshData]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          SAST Security Dashboard
        </Typography>
        <Box>
          <Tooltip title="Refresh">
            <IconButton onClick={refreshData} disabled={refreshing}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Settings">
            <IconButton onClick={() => setShowSettingsModal(true)}>
              <SettingsIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Alerts */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      {/* Quick Actions */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Quick Actions
          </Typography>
          <Box display="flex" gap={2} flexWrap="wrap">
            <Button
              variant="contained"
              startIcon={<PlayIcon />}
              onClick={() => setShowScanModal(true)}
              disabled={scanning}
            >
              Start New Scan
            </Button>
            <Button
              variant="outlined"
              startIcon={<UploadIcon />}
              onClick={() => setShowUploadModal(true)}
              disabled={scanning}
            >
              Upload & Scan
            </Button>
            <Button
              variant="outlined"
              startIcon={<AssessmentIcon />}
              onClick={() => setActiveTab(3)}
            >
              View Reports
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={activeTab} onChange={(_, newValue) => setActiveTab(newValue)}>
          <Tab label="Overview" />
          <Tab label="Projects" />
          <Tab label="Scans" />
          <Tab label="Vulnerabilities" />
          <Tab label="Security Hotspots" />
          <Tab label="Quality Gates" />
          <Tab label="Statistics" />
        </Tabs>
      </Box>

      {/* Overview Tab */}
      <TabPanel value={activeTab} index={0}>
        <Grid container spacing={3}>
          {/* Summary Cards */}
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Projects
                </Typography>
                <Typography variant="h4">
                  {dashboardData?.overview?.total_projects || 0}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Active Scans
                </Typography>
                <Typography variant="h4">
                  {dashboardData?.overview?.active_scans || 0}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Critical Issues
                </Typography>
                <Typography variant="h4" color="error">
                  {dashboardData?.overview?.critical_issues || 0}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Security Score
                </Typography>
                <Typography variant="h4" color="primary">
                  {dashboardData?.overview?.security_score || 0}%
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          {/* Recent Activity */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Recent Activity
                </Typography>
                <Box maxHeight="300px" overflow="auto">
                  {dashboardData?.recent_activity?.scans?.slice(0, 5).map((scan: any, index: number) => (
                    <Box key={index} display="flex" justifyContent="space-between" alignItems="center" py={1}>
                      <Box>
                        <Typography variant="body2">
                          Scan {scan.id} - {scan.status}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {new Date(scan.started_at).toLocaleString()}
                        </Typography>
                      </Box>
                      <Chip
                        label={scan.vulnerabilities_found || 0}
                        size="small"
                        color="primary"
                      />
                    </Box>
                  ))}
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Vulnerability Trends */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Vulnerability Trends
                </Typography>
                <Box maxHeight="300px" overflow="auto">
                  {dashboardData?.trends?.vulnerabilities_trend?.slice(0, 5).map((trend: any, index: number) => (
                    <Box key={index} py={1}>
                      <Typography variant="body2">
                        {trend.date}
                      </Typography>
                      <Box display="flex" gap={1} mt={1}>
                        <Chip label={`C: ${trend.critical}`} size="small" color="error" />
                        <Chip label={`H: ${trend.high}`} size="small" color="warning" />
                        <Chip label={`M: ${trend.medium}`} size="small" color="info" />
                        <Chip label={`L: ${trend.low}`} size="small" color="success" />
                      </Box>
                    </Box>
                  ))}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Projects Tab */}
      <TabPanel value={activeTab} index={1}>
        <Grid container spacing={3}>
          {projects.map((project) => (
            <Grid item xs={12} md={6} lg={4} key={project.id}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    {project.name}
                  </Typography>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    {project.language} • {project.key}
                  </Typography>
                  
                  <Box display="flex" gap={1} mb={2}>
                    <Chip
                      label={`Security: ${project.security_rating}`}
                      size="small"
                      color={project.security_rating === 'A' ? 'success' : 'warning'}
                    />
                    <Chip
                      label={`Coverage: ${project.coverage}%`}
                      size="small"
                      color="primary"
                    />
                  </Box>
                  
                  <Box display="flex" gap={1} flexWrap="wrap">
                    <Chip
                      label={`${project.vulnerabilities_count} Vulns`}
                      size="small"
                      color="error"
                    />
                    <Chip
                      label={`${project.bugs_count} Bugs`}
                      size="small"
                      color="warning"
                    />
                    <Chip
                      label={`${project.code_smell_count} Smells`}
                      size="small"
                      color="info"
                    />
                  </Box>
                  
                  <Box display="flex" gap={1} mt={2}>
                    <Button
                      size="small"
                      variant="outlined"
                      onClick={() => {
                        setSelectedProject(project.id);
                        setShowScanModal(true);
                      }}
                    >
                      Scan
                    </Button>
                    <Button
                      size="small"
                      variant="outlined"
                      onClick={() => exportReport(project.id)}
                    >
                      Export
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Scans Tab */}
      <TabPanel value={activeTab} index={2}>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Scan ID</TableCell>
                <TableCell>Project</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Issues Found</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell>{scan.id}</TableCell>
                  <TableCell>{scan.project_id}</TableCell>
                  <TableCell>
                    <Chip
                      label={scan.status}
                      size="small"
                      color={
                        scan.status === 'COMPLETED' ? 'success' :
                        scan.status === 'IN_PROGRESS' ? 'warning' :
                        scan.status === 'FAILED' ? 'error' : 'default'
                      }
                    />
                  </TableCell>
                  <TableCell>
                    {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}
                  </TableCell>
                  <TableCell>
                    {scan.duration ? `${Math.round(scan.duration / 60)}m` : 'N/A'}
                  </TableCell>
                  <TableCell>
                    <Badge badgeContent={scan.issues_found || 0} color="primary">
                      <BugIcon />
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Box display="flex" gap={1}>
                      {scan.status === 'IN_PROGRESS' && (
                        <Button
                          size="small"
                          variant="outlined"
                          color="error"
                          onClick={() => stopScan(scan.id)}
                        >
                          Stop
                        </Button>
                      )}
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => exportReport(scan.id)}
                      >
                        Report
                      </Button>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Vulnerabilities Tab */}
      <TabPanel value={activeTab} index={3}>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Rule</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>File</TableCell>
                <TableCell>Line</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Tool</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {vulnerabilities.map((vuln) => (
                <TableRow key={vuln.id}>
                  <TableCell>{vuln.id}</TableCell>
                  <TableCell>{vuln.rule_key}</TableCell>
                  <TableCell>
                    <Chip
                      label={vuln.severity}
                      size="small"
                      color={
                        vuln.severity === 'CRITICAL' ? 'error' :
                        vuln.severity === 'HIGH' ? 'warning' :
                        vuln.severity === 'MEDIUM' ? 'info' : 'default'
                      }
                    />
                  </TableCell>
                  <TableCell>{vuln.type}</TableCell>
                  <TableCell>{vuln.component}</TableCell>
                  <TableCell>{vuln.line}</TableCell>
                  <TableCell>{vuln.message}</TableCell>
                  <TableCell>{vuln.tool}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Security Hotspots Tab */}
      <TabPanel value={activeTab} index={4}>
        <Grid container spacing={3}>
          {securityHotspots.map((hotspot) => (
            <Grid item xs={12} md={6} key={hotspot.id}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    {hotspot.rule_name}
                  </Typography>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    {hotspot.message}
                  </Typography>
                  
                  <Box display="flex" gap={1} mb={2}>
                    <Chip
                      label={hotspot.status}
                      size="small"
                      color={
                        hotspot.status === 'REVIEWED' ? 'success' :
                        hotspot.status === 'TO_REVIEW' ? 'warning' : 'default'
                      }
                    />
                    {hotspot.cwe_id && (
                      <Chip label={hotspot.cwe_id} size="small" color="primary" />
                    )}
                  </Box>
                  
                  <Typography variant="body2">
                    File: {hotspot.file_path}:{hotspot.line_number}
                  </Typography>
                  
                  {hotspot.review_comment && (
                    <Typography variant="body2" color="textSecondary" mt={1}>
                      Comment: {hotspot.review_comment}
                    </Typography>
                  )}
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Quality Gates Tab */}
      <TabPanel value={activeTab} index={5}>
        <Grid container spacing={3}>
          {qualityGates.map((gate) => (
            <Grid item xs={12} md={6} key={gate.id}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Quality Gate {gate.id}
                  </Typography>
                  
                  <Box display="flex" gap={1} mb={2}>
                    <Chip
                      label={gate.status}
                      size="small"
                      color={
                        gate.status === 'PASSED' ? 'success' :
                        gate.status === 'FAILED' ? 'error' : 'warning'
                      }
                    />
                  </Box>
                  
                  <Typography variant="body2" gutterBottom>
                    Max Critical: {gate.max_critical_issues}
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    Max Major: {gate.max_major_issues}
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    Min Coverage: {gate.min_coverage}%
                  </Typography>
                  
                  {gate.last_evaluation && (
                    <Typography variant="caption" color="textSecondary">
                      Last evaluated: {new Date(gate.last_evaluation).toLocaleString()}
                    </Typography>
                  )}
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Statistics Tab */}
      <TabPanel value={activeTab} index={6}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Overall Statistics
                </Typography>
                <Typography variant="body1">
                  Total Projects: {statistics?.total_projects || 0}
                </Typography>
                <Typography variant="body1">
                  Total Scans: {statistics?.total_scans || 0}
                </Typography>
                <Typography variant="body1">
                  Total Vulnerabilities: {statistics?.total_vulnerabilities || 0}
                </Typography>
                <Typography variant="body1">
                  Security Score: {statistics?.security_score || 0}%
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Vulnerabilities by Severity
                </Typography>
                {statistics?.vulnerabilities_by_severity && Object.entries(statistics.vulnerabilities_by_severity).map(([severity, count]) => (
                  <Box key={severity} display="flex" justifyContent="space-between" alignItems="center" py={1}>
                    <Typography variant="body2" textTransform="capitalize">
                      {severity}
                    </Typography>
                    <Chip
                      label={count as number}
                      size="small"
                      color={
                        severity === 'critical' ? 'error' :
                        severity === 'high' ? 'warning' :
                        severity === 'medium' ? 'info' : 'default'
                      }
                    />
                  </Box>
                ))}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Scan Modal */}
      <Dialog open={showScanModal} onClose={() => setShowScanModal(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Start New Scan</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Project</InputLabel>
            <Select
              value={selectedProject}
              onChange={(e) => setSelectedProject(e.target.value)}
              label="Project"
            >
              {projects.map((project) => (
                <MenuItem key={project.id} value={project.id}>
                  {project.name} ({project.language})
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Scan Type</InputLabel>
            <Select
              value={scanConfig.scan_type}
              onChange={(e) => setScanConfig({ ...scanConfig, scan_type: e.target.value })}
              label="Scan Type"
            >
              <MenuItem value="full">Full Scan</MenuItem>
              <MenuItem value="incremental">Incremental Scan</MenuItem>
              <MenuItem value="quick">Quick Scan</MenuItem>
            </Select>
          </FormControl>
          
          <TextField
            fullWidth
            label="Branch"
            value={scanConfig.branch}
            onChange={(e) => setScanConfig({ ...scanConfig, branch: e.target.value })}
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowScanModal(false)}>Cancel</Button>
          <Button
            onClick={startScan}
            variant="contained"
            disabled={scanning || !selectedProject}
          >
            {scanning ? 'Starting...' : 'Start Scan'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Upload Modal */}
      <Dialog open={showUploadModal} onClose={() => setShowUploadModal(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Upload & Scan File</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Project</InputLabel>
            <Select
              value={uploadProjectId}
              onChange={(e) => setUploadProjectId(e.target.value)}
              label="Project"
            >
              {projects.map((project) => (
                <MenuItem key={project.id} value={project.id}>
                  {project.name} ({project.language})
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          
          <Button
            variant="outlined"
            component="label"
            fullWidth
            sx={{ mt: 2 }}
          >
            Choose File
            <input
              type="file"
              hidden
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
              accept=".zip,.tar,.gz,.py,.js,.java,.php,.go,.cs,.rb"
            />
          </Button>
          
          {uploadFile && (
            <Typography variant="body2" sx={{ mt: 1 }}>
              Selected: {uploadFile.name}
            </Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowUploadModal(false)}>Cancel</Button>
          <Button
            onClick={uploadAndScan}
            variant="contained"
            disabled={scanning || !uploadFile || !uploadProjectId}
          >
            {scanning ? 'Uploading...' : 'Upload & Scan'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Settings Modal */}
      <Dialog open={showSettingsModal} onClose={() => setShowSettingsModal(false)} maxWidth="md" fullWidth>
        <DialogTitle>SAST Settings</DialogTitle>
        <DialogContent>
          <Typography variant="body1">
            SAST configuration and settings will be implemented here.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowSettingsModal(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default EnhancedSASTDashboard;
