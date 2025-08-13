import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box, Grid, Card, CardContent, Typography, Button, Chip, LinearProgress, Alert, IconButton, Tooltip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Select, MenuItem, FormControl, InputLabel,
  Tabs, Tab, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, Badge, CircularProgress,
  Accordion, AccordionSummary, AccordionDetails, List, ListItem, ListItemText, ListItemIcon, Divider,
  FormControlLabel, Switch, Slider, Typography as MuiTypography, Snackbar, Fab
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Notifications as NotificationsIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Timeline as TimelineIcon,
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
  Memory as MemoryIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkCheckIcon,
  Settings as SettingsIcon,
  Close as CloseIcon,
  ExpandMore as ExpandMoreIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon
} from '@mui/icons-material';
import { sastService } from '../services/sastService';

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
      id={`realtime-tabpanel-${index}`}
      aria-labelledby={`realtime-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

interface RealTimeMonitoringProps {
  projectId?: string;
  projectName?: string;
}

interface VulnerabilityAlert {
  id: string;
  file_path: string;
  line_number: number;
  severity: string;
  vulnerability_type: string;
  description: string;
  timestamp: string;
  confidence: number;
  context: any;
}

interface ScanProgress {
  scan_id: string;
  status: string;
  progress: number;
  current_file: string;
  files_scanned: number;
  total_files: number;
  vulnerabilities_found: number;
  timestamp: string;
}

interface RealTimeStats {
  files_analyzed: number;
  vulnerabilities_found: number;
  analysis_time_total: number;
  last_analysis: string;
  monitoring_active: boolean;
  total_analysis_results: number;
  total_vulnerabilities: number;
  file_hashes_tracked: number;
}

const RealTimeMonitoring: React.FC<RealTimeMonitoringProps> = ({ projectId, projectName }) => {
  const [tabValue, setTabValue] = useState(0);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'disconnected' | 'connecting' | 'connected'>('disconnected');
  const [vulnerabilityAlerts, setVulnerabilityAlerts] = useState<VulnerabilityAlert[]>([]);
  const [scanProgress, setScanProgress] = useState<ScanProgress[]>([]);
  const [realTimeStats, setRealTimeStats] = useState<RealTimeStats | null>(null);
  const [websocket, setWebsocket] = useState<WebSocket | null>(null);
  const [notifications, setNotifications] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [refreshInterval, setRefreshInterval] = useState<number>(30);
  const [showSettings, setShowSettings] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <ErrorIcon color="error" />;
      case 'high': return <WarningIcon color="warning" />;
      case 'medium': return <InfoIcon color="info" />;
      case 'low': return <CheckCircleIcon color="success" />;
      default: return <InfoIcon />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const connectWebSocket = useCallback(async () => {
    try {
      setConnectionStatus('connecting');
      
      // Create WebSocket connection
      const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/sast/realtime`;
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        setConnectionStatus('connected');
        setError(null);
        console.log('WebSocket connected');
        
        // Subscribe to real-time updates
        ws.send(JSON.stringify({
          type: 'subscribe',
          subscription_type: 'real_time',
          project_id: projectId
        }));
      };
      
      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          handleWebSocketMessage(message);
        } catch (e) {
          console.error('Error parsing WebSocket message:', e);
        }
      };
      
      ws.onclose = () => {
        setConnectionStatus('disconnected');
        console.log('WebSocket disconnected');
        
        // Attempt to reconnect
        if (isMonitoring) {
          reconnectTimeoutRef.current = setTimeout(() => {
            connectWebSocket();
          }, 5000);
        }
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setError('WebSocket connection error');
        setConnectionStatus('disconnected');
      };
      
      setWebsocket(ws);
      
    } catch (error) {
      console.error('Error connecting WebSocket:', error);
      setError('Failed to connect to real-time monitor');
      setConnectionStatus('disconnected');
    }
  }, [projectId, isMonitoring]);

  const disconnectWebSocket = useCallback(() => {
    if (websocket) {
      websocket.close();
      setWebsocket(null);
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    setConnectionStatus('disconnected');
  }, [websocket]);

  const handleWebSocketMessage = (message: any) => {
    switch (message.type) {
      case 'vulnerability_detected':
        setVulnerabilityAlerts(prev => [message.data, ...prev.slice(0, 99)]); // Keep last 100
        if (notifications) {
          setSuccess(`New vulnerability detected: ${message.data.vulnerability_type}`);
        }
        break;
        
      case 'scan_progress':
        setScanProgress(prev => {
          const existing = prev.find(p => p.scan_id === message.data.scan_id);
          if (existing) {
            return prev.map(p => p.scan_id === message.data.scan_id ? message.data : p);
          } else {
            return [message.data, ...prev.slice(0, 19)]; // Keep last 20
          }
        });
        break;
        
      case 'analysis_complete':
        if (notifications) {
          setSuccess(`Analysis completed: ${message.data.analysis_type}`);
        }
        break;
        
      case 'real_time_update':
        // Handle real-time updates
        break;
        
      case 'heartbeat':
        // Handle heartbeat
        break;
        
      default:
        console.log('Unknown message type:', message.type);
    }
  };

  const startMonitoring = async () => {
    try {
      if (projectId) {
        await sastService.startRealTimeMonitoring(projectId);
        setIsMonitoring(true);
        connectWebSocket();
        setSuccess('Real-time monitoring started');
      } else {
        setError('Project ID is required to start monitoring');
      }
    } catch (error) {
      console.error('Error starting monitoring:', error);
      setError('Failed to start real-time monitoring');
    }
  };

  const stopMonitoring = async () => {
    try {
      if (projectId) {
        await sastService.stopRealTimeMonitoring(projectId);
        setIsMonitoring(false);
        disconnectWebSocket();
        setSuccess('Real-time monitoring stopped');
      }
    } catch (error) {
      console.error('Error stopping monitoring:', error);
      setError('Failed to stop real-time monitoring');
    }
  };

  const loadRealTimeStats = async () => {
    try {
      if (projectId) {
        const stats = await sastService.getRealTimeStats(projectId);
        setRealTimeStats(stats);
      }
    } catch (error) {
      console.error('Error loading real-time stats:', error);
    }
  };

  const clearAlerts = () => {
    setVulnerabilityAlerts([]);
  };

  const clearScanProgress = () => {
    setScanProgress([]);
  };

  const exportData = async () => {
    try {
      if (projectId) {
        const data = await sastService.exportRealTimeData(projectId);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `realtime-data-${projectId}-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setSuccess('Data exported successfully');
      }
    } catch (error) {
      console.error('Error exporting data:', error);
      setError('Failed to export data');
    }
  };

  // Auto-refresh effect
  useEffect(() => {
    if (autoRefresh && isMonitoring) {
      refreshIntervalRef.current = setInterval(() => {
        loadRealTimeStats();
      }, refreshInterval * 1000);
    }

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [autoRefresh, isMonitoring, refreshInterval, projectId]);

  // Initial load
  useEffect(() => {
    if (projectId) {
      loadRealTimeStats();
    }
  }, [projectId]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnectWebSocket();
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [disconnectWebSocket]);

  return (
    <Box sx={{ width: '100%' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Real-Time Monitoring
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <Chip
            label={connectionStatus}
            color={connectionStatus === 'connected' ? 'success' : connectionStatus === 'connecting' ? 'warning' : 'error'}
            icon={connectionStatus === 'connected' ? <CheckCircleIcon /> : <ErrorIcon />}
          />
          <Button
            variant="contained"
            color={isMonitoring ? 'error' : 'success'}
            startIcon={isMonitoring ? <StopIcon /> : <PlayIcon />}
            onClick={isMonitoring ? stopMonitoring : startMonitoring}
            disabled={connectionStatus === 'connecting'}
          >
            {isMonitoring ? 'Stop Monitoring' : 'Start Monitoring'}
          </Button>
          <IconButton onClick={() => setShowSettings(true)}>
            <SettingsIcon />
          </IconButton>
        </Box>
      </Box>

      {/* Connection Status */}
      {connectionStatus === 'disconnected' && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Not connected to real-time monitor. Start monitoring to enable live updates.
        </Alert>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="Real-time Monitoring Tabs">
          <Tab label="Overview" icon={<TimelineIcon />} iconPosition="start" />
          <Tab label="Live Alerts" icon={<NotificationsIcon />} iconPosition="start" />
          <Tab label="Scan Progress" icon={<SpeedIcon />} iconPosition="start" />
          <Tab label="Statistics" icon={<MemoryIcon />} iconPosition="start" />
          <Tab label="Configuration" icon={<SettingsIcon />} iconPosition="start" />
        </Tabs>
      </Box>

      {/* Tab Panels */}
      <TabPanel value={tabValue} index={0}>
        {/* Overview */}
        <Grid container spacing={3}>
          {/* Status Cards */}
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      Monitoring Status
                    </Typography>
                    <Typography variant="h4" component="div">
                      {isMonitoring ? 'Active' : 'Inactive'}
                    </Typography>
                  </Box>
                  <Chip
                    label={isMonitoring ? 'ON' : 'OFF'}
                    color={isMonitoring ? 'success' : 'default'}
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      Vulnerabilities Today
                    </Typography>
                    <Typography variant="h4" component="div">
                      {vulnerabilityAlerts.filter(v => 
                        new Date(v.timestamp).toDateString() === new Date().toDateString()
                      ).length}
                    </Typography>
                  </Box>
                  <BugReportIcon color="primary" />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      Active Scans
                    </Typography>
                    <Typography variant="h4" component="div">
                      {scanProgress.filter(s => s.status === 'running').length}
                    </Typography>
                  </Box>
                  <SpeedIcon color="primary" />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      Files Tracked
                    </Typography>
                    <Typography variant="h4" component="div">
                      {realTimeStats?.file_hashes_tracked || 0}
                    </Typography>
                  </Box>
                  <StorageIcon color="primary" />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Recent Activity */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Recent Activity
                </Typography>
                <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
                  {vulnerabilityAlerts.length === 0 ? (
                    <Typography color="textSecondary" align="center" sx={{ py: 4 }}>
                      No recent activity
                    </Typography>
                  ) : (
                    <List>
                      {vulnerabilityAlerts.slice(0, 10).map((alert, index) => (
                        <ListItem key={alert.id} divider={index < 9}>
                          <ListItemIcon>
                            {getSeverityIcon(alert.severity)}
                          </ListItemIcon>
                          <ListItemText
                            primary={alert.vulnerability_type}
                            secondary={`${alert.file_path}:${alert.line_number} - ${formatTimestamp(alert.timestamp)}`}
                          />
                          <Chip
                            label={alert.severity}
                            color={getSeverityColor(alert.severity) as any}
                            size="small"
                          />
                        </ListItem>
                      ))}
                    </List>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        {/* Live Alerts */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
            Live Vulnerability Alerts ({vulnerabilityAlerts.length})
          </Typography>
          <Box>
            <Button onClick={clearAlerts} disabled={vulnerabilityAlerts.length === 0}>
              Clear All
            </Button>
            <Button onClick={exportData} variant="outlined">
              Export Data
            </Button>
          </Box>
        </Box>

        {vulnerabilityAlerts.length === 0 ? (
          <Alert severity="info">
            No vulnerability alerts yet. Start monitoring to see live updates.
          </Alert>
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>File</TableCell>
                  <TableCell>Line</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Time</TableCell>
                  <TableCell>Confidence</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {vulnerabilityAlerts.map((alert) => (
                  <TableRow key={alert.id}>
                    <TableCell>
                      <Chip
                        label={alert.severity}
                        color={getSeverityColor(alert.severity) as any}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{alert.vulnerability_type}</TableCell>
                    <TableCell>{alert.file_path}</TableCell>
                    <TableCell>{alert.line_number}</TableCell>
                    <TableCell>{alert.description}</TableCell>
                    <TableCell>{formatTimestamp(alert.timestamp)}</TableCell>
                    <TableCell>
                      <LinearProgress
                        variant="determinate"
                        value={alert.confidence * 100}
                        sx={{ width: 60, height: 8, borderRadius: 4 }}
                      />
                      <Typography variant="caption" display="block">
                        {Math.round(alert.confidence * 100)}%
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        {/* Scan Progress */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
            Active Scans ({scanProgress.filter(s => s.status === 'running').length})
          </Typography>
          <Button onClick={clearScanProgress} disabled={scanProgress.length === 0}>
            Clear History
          </Button>
        </Box>

        {scanProgress.length === 0 ? (
          <Alert severity="info">
            No active scans. Start a scan to see progress updates.
          </Alert>
        ) : (
          <Grid container spacing={2}>
            {scanProgress.map((scan) => (
              <Grid item xs={12} key={scan.scan_id}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                      <Typography variant="h6">
                        Scan {scan.scan_id.slice(0, 8)}...
                      </Typography>
                      <Chip
                        label={scan.status}
                        color={scan.status === 'running' ? 'primary' : 'default'}
                      />
                    </Box>
                    
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" color="textSecondary">
                        Progress: {scan.files_scanned} / {scan.total_files} files
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={(scan.files_scanned / scan.total_files) * 100}
                        sx={{ mt: 1 }}
                      />
                    </Box>
                    
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Current File
                        </Typography>
                        <Typography variant="body1" noWrap>
                          {scan.current_file || 'N/A'}
                        </Typography>
                      </Grid>
                      <Grid item xs={3}>
                        <Typography variant="body2" color="textSecondary">
                          Vulnerabilities
                        </Typography>
                        <Typography variant="body1">
                          {scan.vulnerabilities_found}
                        </Typography>
                      </Grid>
                      <Grid item xs={3}>
                        <Typography variant="body2" color="textSecondary">
                          Updated
                        </Typography>
                        <Typography variant="body1">
                          {formatTimestamp(scan.timestamp)}
                        </Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        {/* Statistics */}
        <Grid container spacing={3}>
          {realTimeStats ? (
            <>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Analysis Statistics
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Files Analyzed
                        </Typography>
                        <Typography variant="h4">
                          {realTimeStats.files_analyzed}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Vulnerabilities Found
                        </Typography>
                        <Typography variant="h4" color="error">
                          {realTimeStats.vulnerabilities_found}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Total Analysis Time
                        </Typography>
                        <Typography variant="h6">
                          {Math.round(realTimeStats.analysis_time_total)}s
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Last Analysis
                        </Typography>
                        <Typography variant="body2">
                          {realTimeStats.last_analysis ? formatTimestamp(realTimeStats.last_analysis) : 'Never'}
                        </Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      System Status
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Monitoring Active
                        </Typography>
                        <Chip
                          label={realTimeStats.monitoring_active ? 'Yes' : 'No'}
                          color={realTimeStats.monitoring_active ? 'success' : 'default'}
                        />
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Analysis Results
                        </Typography>
                        <Typography variant="h6">
                          {realTimeStats.total_analysis_results}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Total Vulnerabilities
                        </Typography>
                        <Typography variant="h6" color="error">
                          {realTimeStats.total_vulnerabilities}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">
                          Files Tracked
                        </Typography>
                        <Typography variant="h6">
                          {realTimeStats.file_hashes_tracked}
                        </Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            </>
          ) : (
            <Grid item xs={12}>
              <Alert severity="info">
                No statistics available. Start monitoring to collect data.
              </Alert>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={4}>
        {/* Configuration */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Notification Settings
                </Typography>
                <FormControlLabel
                  control={
                    <Switch
                      checked={notifications}
                      onChange={(e) => setNotifications(e.target.checked)}
                    />
                  }
                  label="Enable Notifications"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={autoRefresh}
                      onChange={(e) => setAutoRefresh(e.target.checked)}
                    />
                  }
                  label="Auto-refresh Statistics"
                />
                {autoRefresh && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Refresh Interval: {refreshInterval} seconds
                    </Typography>
                    <Slider
                      value={refreshInterval}
                      onChange={(e, value) => setRefreshInterval(value as number)}
                      min={5}
                      max={120}
                      step={5}
                      marks
                      valueLabelDisplay="auto"
                    />
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Connection Settings
                </Typography>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  WebSocket Status: {connectionStatus}
                </Typography>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Monitoring: {isMonitoring ? 'Active' : 'Inactive'}
                </Typography>
                <Box sx={{ mt: 2 }}>
                  <Button
                    variant="outlined"
                    onClick={connectWebSocket}
                    disabled={connectionStatus === 'connected'}
                    sx={{ mr: 1 }}
                  >
                    Connect
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={disconnectWebSocket}
                    disabled={connectionStatus === 'disconnected'}
                  >
                    Disconnect
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Settings Dialog */}
      <Dialog open={showSettings} onClose={() => setShowSettings(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Real-Time Monitoring Settings
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                General Settings
              </Typography>
              <FormControlLabel
                control={
                  <Switch
                    checked={notifications}
                    onChange={(e) => setNotifications(e.target.checked)}
                  />
                }
                label="Enable Notifications"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={autoRefresh}
                    onChange={(e) => setAutoRefresh(e.target.checked)}
                  />
                }
                label="Auto-refresh Statistics"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Performance Settings
              </Typography>
              <FormControl fullWidth sx={{ mt: 2 }}>
                <InputLabel>Refresh Interval</InputLabel>
                <Select
                  value={refreshInterval}
                  onChange={(e) => setRefreshInterval(e.target.value as number)}
                  label="Refresh Interval"
                >
                  <MenuItem value={5}>5 seconds</MenuItem>
                  <MenuItem value={15}>15 seconds</MenuItem>
                  <MenuItem value={30}>30 seconds</MenuItem>
                  <MenuItem value={60}>1 minute</MenuItem>
                  <MenuItem value={120}>2 minutes</MenuItem>
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowSettings(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Notifications */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
      >
        <Alert onClose={() => setError(null)} severity="error">
          {error}
        </Alert>
      </Snackbar>

      <Snackbar
        open={!!success}
        autoHideDuration={4000}
        onClose={() => setSuccess(null)}
      >
        <Alert onClose={() => setSuccess(null)} severity="success">
          {success}
        </Alert>
      </Snackbar>

      {/* Floating Action Button */}
      <Fab
        color="primary"
        aria-label="refresh"
        sx={{ position: 'fixed', bottom: 16, right: 16 }}
        onClick={loadRealTimeStats}
      >
        <RefreshIcon />
      </Fab>
    </Box>
  );
};

export default RealTimeMonitoring;
