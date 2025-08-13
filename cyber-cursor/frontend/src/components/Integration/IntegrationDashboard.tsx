import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardContent, 
  Typography, 
  Grid, 
  Chip, 
  Button, 
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  CircularProgress,
  Alert,
  IconButton,
  Tooltip,
  Collapse
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Help as HelpIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Download as DownloadIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';
import integrationStatusService, { 
  SystemIntegrationOverview, 
  ServiceIntegrationStatus,
  EndpointStatus 
} from '../../services/integrationStatusService';

interface IntegrationDashboardProps {
  autoRefresh?: boolean;
  refreshInterval?: number; // in milliseconds
}

const IntegrationDashboard: React.FC<IntegrationDashboardProps> = ({
  autoRefresh = true,
  refreshInterval = 30000 // 30 seconds
}) => {
  const [overview, setOverview] = useState<SystemIntegrationOverview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedServices, setExpandedServices] = useState<Set<string>>(new Set());
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchIntegrationStatus = async () => {
    try {
      setLoading(true);
      setError(null);
      const status = await integrationStatusService.checkAllServices();
      setOverview(status);
      setLastRefresh(new Date());
    } catch (err: any) {
      setError(err.message || 'Failed to fetch integration status');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntegrationStatus();

    if (autoRefresh) {
      const interval = setInterval(fetchIntegrationStatus, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, refreshInterval]);

  const toggleServiceExpansion = (serviceName: string) => {
    const newExpanded = new Set(expandedServices);
    if (newExpanded.has(serviceName)) {
      newExpanded.delete(serviceName);
    } else {
      newExpanded.add(serviceName);
    }
    setExpandedServices(newExpanded);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'success';
      case 'unhealthy':
        return 'error';
      case 'partial':
        return 'warning';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircleIcon color="success" />;
      case 'unhealthy':
        return <ErrorIcon color="error" />;
      case 'partial':
        return <WarningIcon color="warning" />;
      default:
        return <HelpIcon color="action" />;
    }
  };

  const exportReport = () => {
    const report = integrationStatusService.exportStatusReport();
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `integration-status-report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getEndpointStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return '#4caf50';
      case 'unhealthy':
        return '#f44336';
      default:
        return '#ff9800';
    }
  };

  if (loading && !overview) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Integration Status Dashboard
        </Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={exportReport}
            sx={{ mr: 2 }}
          >
            Export Report
          </Button>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={fetchIntegrationStatus}
            disabled={loading}
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {lastRefresh && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Last updated: {lastRefresh.toLocaleString()}
        </Typography>
      )}

      {overview && (
        <>
          {/* System Overview Cards */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    Total Services
                  </Typography>
                  <Typography variant="h4" component="div">
                    {overview.totalServices}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    Healthy Services
                  </Typography>
                  <Typography variant="h4" component="div" color="success.main">
                    {overview.healthyServices}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    Partial Services
                  </Typography>
                  <Typography variant="h4" component="div" color="warning.main">
                    {overview.partialServices}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    Overall Health
                  </Typography>
                  <Typography variant="h4" component="div" color="primary.main">
                    {overview.overallHealth}%
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Services Status Table */}
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Service Status Details
              </Typography>
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Service</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Endpoints</TableCell>
                      <TableCell>Health</TableCell>
                      <TableCell>Last Check</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {overview.services.map((service) => (
                      <React.Fragment key={service.service}>
                        <TableRow>
                          <TableCell>
                            <Typography variant="subtitle2">
                              {service.service.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              icon={getStatusIcon(service.overallStatus)}
                              label={service.overallStatus}
                              color={getStatusColor(service.overallStatus) as any}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {service.healthyEndpoints}/{service.totalEndpoints}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Box display="flex" alignItems="center">
                              <Box
                                sx={{
                                  width: 60,
                                  height: 8,
                                  backgroundColor: '#e0e0e0',
                                  borderRadius: 4,
                                  overflow: 'hidden'
                                }}
                              >
                                <Box
                                  sx={{
                                    width: `${(service.healthyEndpoints / service.totalEndpoints) * 100}%`,
                                    height: '100%',
                                    backgroundColor: getStatusColor(service.overallStatus) === 'success' ? '#4caf50' : 
                                                   getStatusColor(service.overallStatus) === 'warning' ? '#ff9800' : '#f44336'
                                  }}
                                />
                              </Box>
                              <Typography variant="body2" sx={{ ml: 1 }}>
                                {Math.round((service.healthyEndpoints / service.totalEndpoints) * 100)}%
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {service.lastCheck.toLocaleTimeString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Tooltip title={expandedServices.has(service.service) ? "Hide details" : "Show details"}>
                              <IconButton
                                size="small"
                                onClick={() => toggleServiceExpansion(service.service)}
                              >
                                {expandedServices.has(service.service) ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                              </IconButton>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expanded endpoint details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
                            <Collapse in={expandedServices.has(service.service)} timeout="auto" unmountOnExit>
                              <Box sx={{ margin: 1 }}>
                                <Typography variant="h6" gutterBottom component="div">
                                  Endpoint Details
                                </Typography>
                                <Table size="small">
                                  <TableHead>
                                    <TableRow>
                                      <TableCell>Method</TableCell>
                                      <TableCell>Endpoint</TableCell>
                                      <TableCell>Status</TableCell>
                                      <TableCell>Response Time</TableCell>
                                      <TableCell>Details</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {service.endpoints.map((endpoint, index) => (
                                      <TableRow key={index}>
                                        <TableCell>
                                          <Chip
                                            label={endpoint.method}
                                            size="small"
                                            variant="outlined"
                                          />
                                        </TableCell>
                                        <TableCell>
                                          <Typography variant="body2" fontFamily="monospace">
                                            {endpoint.endpoint}
                                          </Typography>
                                        </TableCell>
                                        <TableCell>
                                          <Box
                                            sx={{
                                              width: 12,
                                              height: 12,
                                              borderRadius: '50%',
                                              backgroundColor: getEndpointStatusColor(endpoint.status),
                                              display: 'inline-block',
                                              mr: 1
                                            }}
                                          />
                                          {endpoint.status}
                                        </TableCell>
                                        <TableCell>
                                          <Typography variant="body2">
                                            {endpoint.responseTime}ms
                                          </Typography>
                                        </TableCell>
                                        <TableCell>
                                          {endpoint.error && (
                                            <Tooltip title={endpoint.error}>
                                              <IconButton size="small">
                                                <VisibilityIcon />
                                              </IconButton>
                                            </Tooltip>
                                          )}
                                          {endpoint.statusCode && (
                                            <Chip
                                              label={endpoint.statusCode}
                                              size="small"
                                              variant="outlined"
                                              color={endpoint.statusCode >= 400 ? 'error' : 'default'}
                                            />
                                          )}
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </Box>
                            </Collapse>
                          </TableCell>
                        </TableRow>
                      </React.Fragment>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </>
      )}
    </Box>
  );
};

export default IntegrationDashboard;
