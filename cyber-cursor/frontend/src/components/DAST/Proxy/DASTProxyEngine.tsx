import React, { useState, useEffect, useCallback } from 'react';
import { 
  Box, 
  Button, 
  Card, 
  CardContent, 
  Typography, 
  TextField, 
  Chip, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemIcon,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Grid,
  Alert,
  IconButton,
  Tooltip,
  Switch,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import { 
  PlayArrow, 
  Stop, 
  Settings, 
  Key, 
  Security, 
  Http,
  ExpandMore,
  ExpandLess,
  Add,
  Delete,
  ContentCopy,
  Refresh
} from '@mui/icons-material';
import { 
  startProxyEngine, 
  stopProxyEngine, 
  getProxyEngineStatus,
  createIngestToken,
  listIngestTokens
} from '../../../services/dastProjectToolsService';

interface ProxyEngineStatus {
  status: 'stopped' | 'running' | 'starting' | 'stopping';
  listen_host?: string;
  listen_port?: number;
  ca_cert_path?: string;
  mitm_enabled?: boolean;
  intercept_enabled?: boolean;
  started_at?: string;
  total_requests?: number;
  total_websocket_frames?: number;
}

interface IngestToken {
  id: string;
  name: string;
  token: string;
  expires_at?: string;
  created_at: string;
  last_used_at?: string;
}

interface ProxyEngineProps {
  projectId: string;
}

const DASTProxyEngine: React.FC<ProxyEngineProps> = ({ projectId }) => {
  const [engineStatus, setEngineStatus] = useState<ProxyEngineStatus | null>(null);
  const [ingestTokens, setIngestTokens] = useState<IngestToken[]>([]);
  const [showCreateTokenDialog, setShowCreateTokenDialog] = useState(false);
  const [showSettingsDialog, setShowSettingsDialog] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pollingInterval, setPollingInterval] = useState<NodeJS.Timeout | null>(null);

  const [newToken, setNewToken] = useState({
    name: '',
    expiresInDays: 30
  });

  const [engineConfig, setEngineConfig] = useState({
    listen_host: '127.0.0.1',
    listen_port: 8080,
    mitm_enabled: true,
    intercept_enabled: false,
    upstream_proxy: '',
    dns_override: '',
    ca_cert_path: ''
  });

  const loadEngineStatus = useCallback(async () => {
    try {
      const status = await getProxyEngineStatus(projectId);
      setEngineStatus(status);
    } catch (err: any) {
      console.error('Failed to load engine status:', err);
    }
  }, [projectId]);

  const loadIngestTokens = useCallback(async () => {
    try {
      const tokens = await listIngestTokens(projectId);
      setIngestTokens(tokens || []);
    } catch (err: any) {
      console.error('Failed to load ingest tokens:', err);
    }
  }, [projectId]);

  useEffect(() => {
    loadEngineStatus();
    loadIngestTokens();

    // Start polling for status updates
    const interval = setInterval(loadEngineStatus, 2000);
    setPollingInterval(interval);

    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, [loadEngineStatus, loadIngestTokens]);

  const handleStartEngine = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      await startProxyEngine(projectId, engineConfig);
      await loadEngineStatus();
      setShowSettingsDialog(false);
    } catch (err: any) {
      setError(err.message || 'Failed to start proxy engine');
    } finally {
      setLoading(false);
    }
  }, [projectId, engineConfig, loadEngineStatus]);

  const handleStopEngine = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      await stopProxyEngine(projectId);
      await loadEngineStatus();
    } catch (err: any) {
      setError(err.message || 'Failed to stop proxy engine');
    } finally {
      setLoading(false);
    }
  }, [projectId, loadEngineStatus]);

  const handleCreateToken = useCallback(async () => {
    if (!newToken.name.trim()) {
      setError('Token name is required');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await createIngestToken(projectId, newToken.name, newToken.expiresInDays);
      setShowCreateTokenDialog(false);
      setNewToken({ name: '', expiresInDays: 30 });
      await loadIngestTokens();
    } catch (err: any) {
      setError(err.message || 'Failed to create ingest token');
    } finally {
      setLoading(false);
    }
  }, [projectId, newToken, loadIngestTokens]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'success';
      case 'starting':
      case 'stopping':
        return 'warning';
      case 'stopped':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <PlayArrow color="success" />;
      case 'starting':
      case 'stopping':
        return <Refresh color="warning" />;
      case 'stopped':
        return <Stop color="error" />;
      default:
        return <Stop />;
    }
  };

  const formatDuration = (startedAt?: string) => {
    if (!startedAt) return 'N/A';
    
    const start = new Date(startedAt);
    const now = new Date();
    const diff = Math.floor((now.getTime() - start.getTime()) / 1000);
    
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
    return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  };

  const renderIngestToken = (token: IngestToken) => (
    <Card key={token.id} sx={{ mb: 2 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Box>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Key color="primary" />
              {token.name}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Created: {new Date(token.created_at).toLocaleString()}
            </Typography>
            {token.last_used_at && (
              <Typography variant="body2" color="text.secondary">
                Last used: {new Date(token.last_used_at).toLocaleString()}
              </Typography>
            )}
            {token.expires_at && (
              <Typography variant="body2" color="text.secondary">
                Expires: {new Date(token.expires_at).toLocaleString()}
              </Typography>
            )}
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Copy token">
              <IconButton size="small" onClick={() => copyToClipboard(token.token)}>
                <ContentCopy />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        <Box sx={{ bgcolor: 'grey.50', p: 2, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
          <Typography variant="caption" display="block" color="text.secondary" gutterBottom>
            Ingest Token (use in X-Ingest-Token header):
          </Typography>
          {token.token}
        </Box>

        <Box sx={{ mt: 2 }}>
          <Typography variant="caption" color="text.secondary">
            Use this token in the X-Ingest-Token header when sending traffic to the proxy engine.
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="h5" gutterBottom>
        <Security sx={{ mr: 1, verticalAlign: 'middle' }} />
        Proxy Engine
      </Typography>

      {/* Engine Status */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">
              Engine Status
            </Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="outlined"
                startIcon={<Settings />}
                onClick={() => setShowSettingsDialog(true)}
                size="small"
              >
                Settings
              </Button>
              {engineStatus?.status === 'running' ? (
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<Stop />}
                  onClick={handleStopEngine}
                  disabled={loading}
                  size="small"
                >
                  Stop Engine
                </Button>
              ) : (
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<PlayArrow />}
                  onClick={handleStartEngine}
                  disabled={loading}
                  size="small"
                >
                  Start Engine
                </Button>
              )}
            </Box>
          </Box>

          {engineStatus && (
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  {getStatusIcon(engineStatus.status)}
                  <Chip 
                    label={engineStatus.status.toUpperCase()} 
                    color={getStatusColor(engineStatus.status) as any}
                    size="small"
                  />
                </Box>
                
                <Typography variant="body2" color="text.secondary">
                  <strong>Listen Address:</strong> {engineStatus.listen_host || 'N/A'}:{engineStatus.listen_port || 'N/A'}
                </Typography>
                
                <Typography variant="body2" color="text.secondary">
                  <strong>MITM:</strong> {engineStatus.mitm_enabled ? 'Enabled' : 'Disabled'}
                </Typography>
                
                <Typography variant="body2" color="text.secondary">
                  <strong>Intercept:</strong> {engineStatus.intercept_enabled ? 'Enabled' : 'Disabled'}
                </Typography>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="body2" color="text.secondary">
                  <strong>Started:</strong> {formatDuration(engineStatus.started_at)}
                </Typography>
                
                <Typography variant="body2" color="text.secondary">
                  <strong>Total Requests:</strong> {engineStatus.total_requests || 0}
                </Typography>
                
                <Typography variant="body2" color="text.secondary">
                  <strong>WebSocket Frames:</strong> {engineStatus.total_websocket_frames || 0}
                </Typography>
                
                {engineStatus.ca_cert_path && (
                  <Typography variant="body2" color="text.secondary">
                    <strong>CA Cert:</strong> {engineStatus.ca_cert_path}
                  </Typography>
                )}
              </Grid>
            </Grid>
          )}
        </CardContent>
      </Card>

      {/* Ingest Tokens */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">
              <Key sx={{ mr: 1, verticalAlign: 'middle' }} />
              Ingest Tokens
            </Typography>
            <Button
              variant="contained"
              color="primary"
              startIcon={<Add />}
              onClick={() => setShowCreateTokenDialog(true)}
              size="small"
            >
              Create Token
            </Button>
          </Box>

          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Ingest tokens are used to authenticate traffic sent to the proxy engine. 
            Use the X-Ingest-Token header when sending HTTP flows and WebSocket frames.
          </Typography>

          {ingestTokens.length > 0 ? (
            <Box>
              {ingestTokens.map(renderIngestToken)}
            </Box>
          ) : (
            <Box sx={{ textAlign: 'center', py: 3 }}>
              <Typography variant="body1" color="text.secondary">
                No ingest tokens configured yet.
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Create a token to start sending traffic to the proxy engine.
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Create Token Dialog */}
      <Dialog open={showCreateTokenDialog} onClose={() => setShowCreateTokenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create Ingest Token</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Token Name"
                value={newToken.name}
                onChange={(e) => setNewToken(prev => ({ ...prev, name: e.target.value }))}
                helperText="Give this token a descriptive name (e.g., 'Proxy Engine 1', 'Crawler')"
                placeholder="Proxy Engine 1"
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                type="number"
                label="Expires In (Days)"
                value={newToken.expiresInDays}
                onChange={(e) => setNewToken(prev => ({ ...prev, expiresInDays: parseInt(e.target.value) || 30 }))}
                helperText="Leave empty for never expires"
                inputProps={{ min: 1, max: 365 }}
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowCreateTokenDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleCreateToken} 
            variant="contained" 
            color="primary"
            disabled={loading || !newToken.name.trim()}
          >
            {loading ? 'Creating...' : 'Create Token'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Engine Settings Dialog */}
      <Dialog open={showSettingsDialog} onClose={() => setShowSettingsDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Proxy Engine Settings</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Listen Host"
                value={engineConfig.listen_host}
                onChange={(e) => setEngineConfig(prev => ({ ...prev, listen_host: e.target.value }))}
                helperText="IP address to bind to"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                type="number"
                label="Listen Port"
                value={engineConfig.listen_port}
                onChange={(e) => setEngineConfig(prev => ({ ...prev, listen_port: parseInt(e.target.value) || 8080 }))}
                helperText="Port to listen on"
                inputProps={{ min: 1024, max: 65535 }}
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Upstream Proxy (Optional)"
                value={engineConfig.upstream_proxy}
                onChange={(e) => setEngineConfig(prev => ({ ...prev, upstream_proxy: e.target.value }))}
                helperText="Format: host:port or host:port:username:password"
                placeholder="proxy.example.com:8080"
              />
            </Grid>
            
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="DNS Override (Optional)"
                value={engineConfig.dns_override}
                onChange={(e) => setEngineConfig(prev => ({ ...prev, dns_override: e.target.value }))}
                helperText="Custom DNS server (e.g., 8.8.8.8)"
                placeholder="8.8.8.8"
              />
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="CA Certificate Path (Optional)"
                value={engineConfig.ca_cert_path}
                onChange={(e) => setEngineConfig(prev => ({ ...prev, ca_cert_path: e.target.value }))}
                helperText="Path to custom CA certificate for MITM"
                placeholder="/path/to/ca.crt"
              />
            </Grid>
            
            <Grid item xs={12}>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography variant="body2">MITM Enabled</Typography>
                  <Switch
                    checked={engineConfig.mitm_enabled}
                    onChange={(e) => setEngineConfig(prev => ({ ...prev, mitm_enabled: e.target.checked }))}
                  />
                </Box>
                
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography variant="body2">Intercept Enabled</Typography>
                  <Switch
                    checked={engineConfig.intercept_enabled}
                    onChange={(e) => setEngineConfig(prev => ({ ...prev, intercept_enabled: e.target.checked }))}
                  />
                </Box>
              </Box>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowSettingsDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleStartEngine} 
            variant="contained" 
            color="primary"
            disabled={loading}
          >
            {loading ? 'Starting...' : 'Start Engine'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DASTProxyEngine;
