import React, { useState, useEffect, useCallback } from 'react';
import { 
  Box, 
  Button, 
  Card, 
  CardContent, 
  Typography, 
  TextField, 
  Chip, 
  LinearProgress, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemIcon,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Alert,
  IconButton,
  Tooltip
} from '@mui/material';
import { 
  PlayArrow, 
  Stop, 
  Refresh, 
  Security, 
  BugReport, 
  Warning, 
  Info,
  Error,
  CheckCircle,
  ExpandMore,
  ExpandLess
} from '@mui/icons-material';
import { startScanner, stopScanner, getScannerStatus, getScanIssues } from '../../../services/dastProjectToolsService';

interface ScanIssue {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'false_positive' | 'low' | 'medium' | 'high';
  url: string;
  method: string;
  evidence: any;
  cwe_id?: string;
  references?: string[];
  created_at: string;
}

interface ScannerTabProps {
  projectId: string;
}

const DASTScannerTab: React.FC<ScannerTabProps> = ({ projectId }) => {
  const [scanConfig, setScanConfig] = useState({
    targetUrls: '',
    scanModules: ['sql_injection', 'xss', 'csrf'],
    rateLimit: 100,
    maxConcurrent: 5
  });
  
  const [activeScan, setActiveScan] = useState<{
    id: string;
    status: string;
    progress: number;
    started_at: string;
    total_requests: number;
  } | null>(null);
  
  const [scanIssues, setScanIssues] = useState<ScanIssue[]>([]);
  const [showStartDialog, setShowStartDialog] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scanModules = [
    { id: 'sql_injection', name: 'SQL Injection', description: 'Detects SQL injection vulnerabilities' },
    { id: 'xss', name: 'Cross-Site Scripting', description: 'Detects XSS vulnerabilities' },
    { id: 'csrf', name: 'CSRF', description: 'Detects missing CSRF protection' },
    { id: 'open_redirect', name: 'Open Redirect', description: 'Detects open redirect vulnerabilities' },
    { id: 'ssrf', name: 'SSRF', description: 'Detects server-side request forgery' }
  ];

  const severityColors = {
    low: 'success',
    medium: 'warning',
    high: 'error',
    critical: 'error'
  };

  const confidenceColors = {
    false_positive: 'default',
    low: 'info',
    medium: 'warning',
    high: 'error'
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <Error color="error" />;
      case 'medium':
        return <Warning color="warning" />;
      case 'low':
        return <Info color="info" />;
      default:
        return <Info color="info" />;
    }
  };

  const handleStartScan = useCallback(async () => {
    if (!scanConfig.targetUrls.trim()) {
      setError('Please enter target URLs');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const targetUrls = scanConfig.targetUrls.split('\n').map(url => url.trim()).filter(url => url);
      const response = await startScanner(projectId, targetUrls, {
        modules: scanConfig.scanModules,
        rate_limit: scanConfig.rateLimit,
        max_concurrent: scanConfig.maxConcurrent
      });

      setActiveScan({
        id: response.scan_id,
        status: 'running',
        progress: 0,
        started_at: new Date().toISOString(),
        total_requests: targetUrls.length * scanConfig.scanModules.length
      });

      setShowStartDialog(false);
      setScanIssues([]);
      
      // Start polling for status
      pollScanStatus(response.scan_id);
    } catch (err: any) {
      setError(err.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  }, [projectId, scanConfig]);

  const handleStopScan = useCallback(async () => {
    if (!activeScan) return;

    try {
      await stopScanner(projectId, activeScan.id);
      setActiveScan(prev => prev ? { ...prev, status: 'stopped' } : null);
    } catch (err: any) {
      setError(err.message || 'Failed to stop scan');
    }
  }, [projectId, activeScan]);

  const pollScanStatus = useCallback(async (scanId: string) => {
    const interval = setInterval(async () => {
      try {
        const status = await getScannerStatus(projectId, scanId);
        
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(interval);
          setActiveScan(null);
          
          if (status.status === 'completed') {
            // Fetch scan issues
            const issues = await getScanIssues(projectId, scanId);
            setScanIssues(issues.issues || []);
          }
        } else {
          setActiveScan(prev => prev ? { ...prev, ...status } : null);
        }
      } catch (err) {
        console.error('Error polling scan status:', err);
      }
    }, 2000);

    // Cleanup interval after 10 minutes
    setTimeout(() => clearInterval(interval), 600000);
  }, [projectId]);

  const formatScanDuration = (startedAt: string) => {
    const start = new Date(startedAt);
    const now = new Date();
    const diff = Math.floor((now.getTime() - start.getTime()) / 1000);
    
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
    return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  };

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="h5" gutterBottom>
        <Security sx={{ mr: 1, verticalAlign: 'middle' }} />
        Vulnerability Scanner
      </Typography>

      {/* Scan Configuration */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Scan Configuration
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={3}
                label="Target URLs (one per line)"
                placeholder="https://example.com
https://example.com/admin
https://example.com/api"
                value={scanConfig.targetUrls}
                onChange={(e) => setScanConfig(prev => ({ ...prev, targetUrls: e.target.value }))}
                helperText="Enter target URLs to scan for vulnerabilities"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Scan Modules</InputLabel>
                <Select
                  multiple
                  value={scanConfig.scanModules}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, scanModules: e.target.value as string[] }))}
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => (
                        <Chip key={value} label={scanModules.find(m => m.id === value)?.name || value} size="small" />
                      ))}
                    </Box>
                  )}
                >
                  {scanModules.map((module) => (
                    <MenuItem key={module.id} value={module.id}>
                      <ListItemIcon>
                        <BugReport fontSize="small" />
                      </ListItemIcon>
                      <Box>
                        <Typography variant="body2">{module.name}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {module.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                type="number"
                label="Rate Limit (ms)"
                value={scanConfig.rateLimit}
                onChange={(e) => setScanConfig(prev => ({ ...prev, rateLimit: parseInt(e.target.value) || 100 }))}
                inputProps={{ min: 50, max: 1000 }}
              />
            </Grid>
            
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                type="number"
                label="Max Concurrent"
                value={scanConfig.maxConcurrent}
                onChange={(e) => setScanConfig(prev => ({ ...prev, maxConcurrent: parseInt(e.target.value) || 5 }))}
                inputProps={{ min: 1, max: 20 }}
              />
            </Grid>
          </Grid>
          
          <Box sx={{ mt: 2 }}>
            <Button
              variant="contained"
              color="primary"
              startIcon={<PlayArrow />}
              onClick={() => setShowStartDialog(true)}
              disabled={loading || !scanConfig.targetUrls.trim()}
            >
              Start Scan
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Active Scan Status */}
      {activeScan && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Active Scan: {activeScan.id.slice(-8)}
              </Typography>
              <Box>
                <Chip 
                  label={activeScan.status.toUpperCase()} 
                  color={activeScan.status === 'running' ? 'success' : 'warning'}
                  sx={{ mr: 1 }}
                />
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<Stop />}
                  onClick={handleStopScan}
                  size="small"
                >
                  Stop
                </Button>
              </Box>
            </Box>
            
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="body2">Progress</Typography>
                <Typography variant="body2">{activeScan.progress}%</Typography>
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={activeScan.progress} 
                sx={{ height: 8, borderRadius: 4 }}
              />
            </Box>
            
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Typography variant="body2" color="text.secondary">
                  Started: {formatScanDuration(activeScan.started_at)}
                </Typography>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="body2" color="text.secondary">
                  Total Requests: {activeScan.total_requests}
                </Typography>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="body2" color="text.secondary">
                  Status: {activeScan.status}
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Scan Issues */}
      {scanIssues.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Scan Results ({scanIssues.length} issues found)
            </Typography>
            
            <List>
              {scanIssues.map((issue) => (
                <ListItem key={issue.id} divider>
                  <ListItemIcon>
                    {getSeverityIcon(issue.severity)}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="subtitle1">{issue.title}</Typography>
                        <Chip 
                          label={issue.severity.toUpperCase()} 
                          color={severityColors[issue.severity] as any}
                          size="small"
                        />
                        <Chip 
                          label={issue.confidence.toUpperCase()} 
                          color={confidenceColors[issue.confidence] as any}
                          size="small"
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          {issue.description}
                        </Typography>
                        <Typography variant="caption" display="block">
                          <strong>URL:</strong> {issue.url}
                        </Typography>
                        <Typography variant="caption" display="block">
                          <strong>Method:</strong> {issue.method}
                        </Typography>
                        {issue.cwe_id && (
                          <Typography variant="caption" display="block">
                            <strong>CWE:</strong> {issue.cwe_id}
                          </Typography>
                        )}
                        {issue.evidence && (
                          <Typography variant="caption" display="block">
                            <strong>Evidence:</strong> {JSON.stringify(issue.evidence)}
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </CardContent>
        </Card>
      )}

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Start Scan Dialog */}
      <Dialog open={showStartDialog} onClose={() => setShowStartDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Start Vulnerability Scan</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Are you sure you want to start a vulnerability scan? This will send requests to the target URLs.
          </Typography>
          
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>Target URLs:</Typography>
            <Box sx={{ maxHeight: 100, overflow: 'auto', bgcolor: 'grey.50', p: 1, borderRadius: 1 }}>
              {scanConfig.targetUrls.split('\n').map((url, index) => (
                <Typography key={index} variant="body2" fontFamily="monospace">
                  {url.trim()}
                </Typography>
              ))}
            </Box>
          </Box>
          
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>Selected Modules:</Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
              {scanConfig.scanModules.map((moduleId) => {
                const module = scanModules.find(m => m.id === moduleId);
                return (
                  <Chip 
                    key={moduleId} 
                    label={module?.name || moduleId} 
                    size="small" 
                    color="primary" 
                    variant="outlined"
                  />
                );
              })}
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowStartDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleStartScan} 
            variant="contained" 
            color="primary"
            disabled={loading}
          >
            {loading ? 'Starting...' : 'Start Scan'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DASTScannerTab;
