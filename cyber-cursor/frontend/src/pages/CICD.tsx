import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  Alert,
  Snackbar,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Pagination,
  Tooltip,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction
} from '@mui/material';
import {
  PlayIcon,
  PauseIcon,
  StopIcon,
  EyeIcon,
  TrashIcon,
  PlusIcon,
  PencilIcon,
  ArrowPathIcon,
  CalendarIcon,
  UserIcon,
  CodeBracketIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  CogIcon,
  ChartBarIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  ShieldCheckIcon,
  LockClosedIcon,
  GlobeAltIcon,
  ServerIcon,
  CircleStackIcon,
  WifiIcon,
  ComputerDesktopIcon,
  ExclamationCircleIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ArrowTopRightOnSquareIcon,
  ArrowDownTrayIcon
} from '@heroicons/react/24/outline';
import { cicdService, PipelineResponse, PipelineCreate, PipelineUpdate, PipelineStatus, PipelineTrigger, SecurityScanType, PipelineFilter } from '../services/cicdService';

interface CICDPageState {
  pipelines: PipelineResponse[];
  loading: boolean;
  error: string | null;
  dialogOpen: boolean;
  editMode: boolean;
  currentPipeline: PipelineResponse | null;
  formData: Partial<PipelineCreate>;
  filters: PipelineFilter;
  pagination: {
    page: number;
    limit: number;
    total: number;
  };
  metrics: any;
  showMetrics: boolean;
  selectedTab: number;
  selectedPipeline: PipelineResponse | null;
  pipelineRuns: any[];
  showRuns: boolean;
}

const CICD: React.FC = () => {
  const [state, setState] = useState<CICDPageState>({
    pipelines: [],
    loading: false,
    error: null,
    dialogOpen: false,
    editMode: false,
    currentPipeline: null,
    formData: {
      name: '',
      description: '',
      repository_url: '',
      branch: 'main',
      trigger: PipelineTrigger.MANUAL,
      security_scan_types: [SecurityScanType.SAST],
      enabled: true
    },
    filters: {},
    pagination: {
      page: 1,
      limit: 20,
      total: 0
    },
    metrics: null,
    showMetrics: false,
    selectedTab: 0,
    selectedPipeline: null,
    pipelineRuns: [],
    showRuns: false
  });

  useEffect(() => {
    loadPipelines();
    loadMetrics();
  }, [state.pagination.page, state.filters]);

  const loadPipelines = async () => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    try {
      const response = await cicdService.getPipelines(
        state.pagination.page,
        state.pagination.limit,
        state.filters
      );
      setState(prev => ({
        ...prev,
        pipelines: response.pipelines,
        pagination: {
          ...prev.pagination,
          total: response.total
        },
        loading: false
      }));
    } catch (error) {
      setState(prev => ({
        ...prev,
        error: 'Failed to load pipelines',
        loading: false
      }));
    }
  };

  const loadMetrics = async () => {
    try {
      const metrics = await cicdService.getCICDMetrics();
      setState(prev => ({ ...prev, metrics }));
    } catch (error) {
      console.error('Failed to load metrics:', error);
    }
  };

  const loadPipelineRuns = async (pipelineId: string) => {
    try {
      const response = await cicdService.getPipelineRuns(pipelineId);
      setState(prev => ({ ...prev, pipelineRuns: response.runs }));
    } catch (error) {
      console.error('Failed to load pipeline runs:', error);
    }
  };

  const handleOpenDialog = (pipeline?: PipelineResponse) => {
    if (pipeline) {
      setState(prev => ({
        ...prev,
        editMode: true,
        currentPipeline: pipeline,
        formData: { ...pipeline },
        dialogOpen: true
      }));
    } else {
      setState(prev => ({
        ...prev,
        editMode: false,
        currentPipeline: null,
        formData: {
          name: '',
          description: '',
          repository_url: '',
          branch: 'main',
          trigger: PipelineTrigger.MANUAL,
          security_scan_types: [SecurityScanType.SAST],
          enabled: true
        },
        dialogOpen: true
      }));
    }
  };

  const handleCloseDialog = () => {
    setState(prev => ({ ...prev, dialogOpen: false }));
  };

  const handleSubmit = async () => {
    try {
      if (state.editMode && state.currentPipeline) {
        await cicdService.updatePipeline(state.currentPipeline.id, state.formData as PipelineUpdate);
      } else {
        await cicdService.createPipeline(state.formData as PipelineCreate);
      }
      handleCloseDialog();
      loadPipelines();
      loadMetrics();
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Failed to save pipeline' }));
    }
  };

  const handleDelete = async (pipelineId: string) => {
    if (window.confirm('Are you sure you want to delete this pipeline?')) {
      try {
        await cicdService.deletePipeline(pipelineId);
        loadPipelines();
        loadMetrics();
      } catch (error) {
        setState(prev => ({ ...prev, error: 'Failed to delete pipeline' }));
      }
    }
  };

  const handleTogglePipeline = async (pipelineId: string, enabled: boolean) => {
    try {
      await cicdService.togglePipeline(pipelineId, enabled);
      loadPipelines();
      loadMetrics();
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Failed to toggle pipeline' }));
    }
  };

  const handleTriggerPipeline = async (pipelineId: string) => {
    try {
      await cicdService.triggerPipeline(pipelineId);
      setState(prev => ({ ...prev, error: 'Pipeline triggered successfully' }));
      loadPipelines();
      loadMetrics();
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Failed to trigger pipeline' }));
    }
  };

  const handleViewPipeline = (pipeline: PipelineResponse) => {
    setState(prev => ({
      ...prev,
      selectedPipeline: pipeline,
      selectedTab: 0,
      showRuns: true
    }));
    loadPipelineRuns(pipeline.id);
  };

  const getStatusColor = (status: PipelineStatus) => {
    switch (status) {
      case PipelineStatus.SUCCESS: return 'success';
      case PipelineStatus.FAILED: return 'error';
      case PipelineStatus.RUNNING: return 'info';
      case PipelineStatus.PENDING: return 'warning';
      case PipelineStatus.CANCELLED: return 'default';
      case PipelineStatus.SKIPPED: return 'default';
      default: return 'default';
    }
  };

  const getTriggerIcon = (trigger: PipelineTrigger) => {
          switch (trigger) {
        case PipelineTrigger.MANUAL: return <PlayIcon />;
        case PipelineTrigger.SCHEDULED: return <CalendarIcon />;
        case PipelineTrigger.WEBHOOK: return <GlobeAltIcon />;
        case PipelineTrigger.PUSH: return <CodeBracketIcon />;
        case PipelineTrigger.PULL_REQUEST: return <ArrowPathIcon />;
        case PipelineTrigger.MERGE: return <ArrowPathIcon />;
        default: return <PlayIcon />;
      }
  };

  const getSecurityScanIcon = (scanType: SecurityScanType) => {
    switch (scanType) {
      case SecurityScanType.SAST: return <ShieldCheckIcon />;
              case SecurityScanType.DAST: return <LockClosedIcon />;
        case SecurityScanType.SCA: return <CircleStackIcon />;
        case SecurityScanType.CONTAINER_SCAN: return <ServerIcon />;
        case SecurityScanType.INFRASTRUCTURE_SCAN: return <WifiIcon />;
      default: return <ShieldCheckIcon />;
    }
  };

  const handleFilterChange = (filter: Partial<PipelineFilter>) => {
    setState(prev => ({
      ...prev,
      filters: { ...prev.filters, ...filter },
      pagination: { ...prev.pagination, page: 1 }
    }));
  };

  const handlePageChange = (event: React.ChangeEvent<unknown>, page: number) => {
    setState(prev => ({
      ...prev,
      pagination: { ...prev.pagination, page }
    }));
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setState(prev => ({ ...prev, selectedTab: newValue }));
  };

  if (state.loading && state.pipelines.length === 0) {
    return (
      <Box sx={{ width: '100%' }}>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="xl">
      <Box sx={{ my: 4 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            CI/CD Pipelines
          </Typography>
          <Box>
            <Button
              variant="outlined"
              startIcon={<ChartBarIcon />}
              onClick={() => setState(prev => ({ ...prev, showMetrics: !prev.showMetrics }))}
              sx={{ mr: 2 }}
            >
              {state.showMetrics ? 'Hide' : 'Show'} Metrics
            </Button>
            <Button
              variant="contained"
              startIcon={<PlusIcon />}
              onClick={() => handleOpenDialog()}
            >
              Add Pipeline
            </Button>
          </Box>
        </Box>

        {/* Metrics Section */}
        {state.showMetrics && state.metrics && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                CI/CD Overview
              </Typography>
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="primary">
                      {state.metrics.total_pipelines}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Total Pipelines
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="success.main">
                      {state.metrics.active_pipelines}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Active Pipelines
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="info.main">
                      {state.metrics.total_runs}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Total Runs
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="success.main">
                      {state.metrics.success_rate.toFixed(1)}%
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Success Rate
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        )}

        {/* Filters */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Filters
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={state.filters.status || ''}
                    onChange={(e) => handleFilterChange({ status: e.target.value as PipelineStatus })}
                    label="Status"
                  >
                    <MenuItem value="">All Statuses</MenuItem>
                    {Object.values(PipelineStatus).map((status) => (
                      <MenuItem key={status} value={status}>{status}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Trigger</InputLabel>
                  <Select
                    value={state.filters.trigger || ''}
                    onChange={(e) => handleFilterChange({ trigger: e.target.value as PipelineTrigger })}
                    label="Trigger"
                  >
                    <MenuItem value="">All Triggers</MenuItem>
                    {Object.values(PipelineTrigger).map((trigger) => (
                      <MenuItem key={trigger} value={trigger}>{trigger}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Security Scan</InputLabel>
                  <Select
                    value={state.filters.security_scan_type || ''}
                    onChange={(e) => handleFilterChange({ security_scan_type: e.target.value as SecurityScanType })}
                    label="Security Scan"
                  >
                    <MenuItem value="">All Scan Types</MenuItem>
                    {Object.values(SecurityScanType).map((scanType) => (
                      <MenuItem key={scanType} value={scanType}>{scanType}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Button
                  variant="outlined"
                  startIcon={<ArrowPathIcon />}
                  onClick={loadPipelines}
                  fullWidth
                >
                  Refresh
                </Button>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Main Content */}
        <Grid container spacing={3}>
          {/* Pipelines List */}
          <Grid item xs={12} md={state.showRuns ? 6 : 12}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Pipelines ({state.pagination.total})
                  </Typography>
                  <Button
                    size="small"
                    startIcon={<ArrowDownTrayIcon />}
                    onClick={() => {/* Handle export */}}
                  >
                    Export
                  </Button>
                </Box>

                <TableContainer component={Paper}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Pipeline</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Trigger</TableCell>
                        <TableCell>Security Scans</TableCell>
                        <TableCell>Last Run</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {state.pipelines.map((pipeline) => (
                        <TableRow key={pipeline.id}>
                          <TableCell>
                            <Box>
                              <Typography variant="subtitle2">{pipeline.name}</Typography>
                              <Typography variant="body2" color="textSecondary">
                                {pipeline.description}
                              </Typography>
                              <Typography variant="caption" color="textSecondary">
                                {pipeline.repository_url}
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              <Chip
                                label={pipeline.last_run_status || 'No runs'}
                                color={getStatusColor(pipeline.last_run_status || PipelineStatus.PENDING) as any}
                                size="small"
                                sx={{ mr: 1 }}
                              />
                              <FormControlLabel
                                control={
                                  <Switch
                                    checked={pipeline.enabled}
                                    onChange={(e) => handleTogglePipeline(pipeline.id, e.target.checked)}
                                    size="small"
                                  />
                                }
                                label=""
                              />
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Chip
                              icon={getTriggerIcon(pipeline.trigger)}
                              label={pipeline.trigger}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', gap: 0.5 }}>
                              {pipeline.security_scan_types.map((scanType) => (
                                <Tooltip key={scanType} title={scanType}>
                                  <IconButton size="small" color="primary">
                                    {getSecurityScanIcon(scanType)}
                                  </IconButton>
                                </Tooltip>
                              ))}
                            </Box>
                          </TableCell>
                          <TableCell>
                            {pipeline.last_run_at ? (
                              <Typography variant="body2">
                                {new Date(pipeline.last_run_at).toLocaleDateString()}
                              </Typography>
                            ) : (
                              <Typography variant="body2" color="textSecondary">
                                Never
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Box>
                              <IconButton
                                size="small"
                                onClick={() => handleViewPipeline(pipeline)}
                                color="primary"
                              >
                                <EyeIcon />
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={() => handleTriggerPipeline(pipeline.id)}
                                color="success"
                              >
                                <PlayIcon />
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={() => handleOpenDialog(pipeline)}
                                color="primary"
                              >
                                <PencilIcon />
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={() => handleDelete(pipeline.id)}
                                color="error"
                              >
                                <TrashIcon />
                              </IconButton>
                            </Box>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                {/* Pagination */}
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                  <Pagination
                    count={Math.ceil(state.pagination.total / state.pagination.limit)}
                    page={state.pagination.page}
                    onChange={handlePageChange}
                    color="primary"
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Pipeline Details */}
          {state.showRuns && state.selectedPipeline && (
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6">
                      {state.selectedPipeline.name}
                    </Typography>
                    <IconButton
                      size="small"
                      onClick={() => setState(prev => ({ ...prev, showRuns: false }))}
                    >
                      <ChevronRightIcon />
                    </IconButton>
                  </Box>

                  <Tabs value={state.selectedTab} onChange={handleTabChange}>
                    <Tab label="Overview" />
                    <Tab label="Runs" />
                    <Tab label="Security" />
                    <Tab label="Settings" />
                  </Tabs>

                  {/* Overview Tab */}
                  {state.selectedTab === 0 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="body2" color="textSecondary" gutterBottom>
                        {state.selectedPipeline.description}
                      </Typography>
                      <Grid container spacing={2} sx={{ mt: 2 }}>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Repository</Typography>
                          <Typography variant="body2">{state.selectedPipeline.repository_url}</Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Branch</Typography>
                          <Typography variant="body2">{state.selectedPipeline.branch}</Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Total Runs</Typography>
                          <Typography variant="body2">{state.selectedPipeline.total_runs}</Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">Success Rate</Typography>
                          <Typography variant="body2">{state.selectedPipeline.success_rate.toFixed(1)}%</Typography>
                        </Grid>
                      </Grid>
                    </Box>
                  )}

                  {/* Runs Tab */}
                  {state.selectedTab === 1 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Recent Runs
                      </Typography>
                      <List>
                        {state.pipelineRuns.slice(0, 5).map((run) => (
                          <ListItem key={run.id} dense>
                            <ListItemText
                              primary={`Run #${run.id.slice(-8)}`}
                              secondary={`${run.status} - ${new Date(run.started_at).toLocaleString()}`}
                            />
                            <ListItemSecondaryAction>
                              <Chip
                                label={run.status}
                                color={getStatusColor(run.status) as any}
                                size="small"
                              />
                            </ListItemSecondaryAction>
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}

                  {/* Security Tab */}
                  {state.selectedTab === 2 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Security Scans
                      </Typography>
                      <Grid container spacing={1}>
                        {state.selectedPipeline.security_scan_types.map((scanType) => (
                          <Grid item xs={12} key={scanType}>
                            <Chip
                              icon={getSecurityScanIcon(scanType)}
                              label={scanType}
                              variant="outlined"
                              component="div"
                            />
                          </Grid>
                        ))}
                      </Grid>
                    </Box>
                  )}

                  {/* Settings Tab */}
                  {state.selectedTab === 3 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Pipeline Settings
                      </Typography>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={state.selectedPipeline.enabled}
                            onChange={(e) => handleTogglePipeline(state.selectedPipeline!.id, e.target.checked)}
                          />
                        }
                        label="Enabled"
                      />
                      <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                        Trigger: {state.selectedPipeline.trigger}
                      </Typography>
                      {state.selectedPipeline.schedule && (
                        <Typography variant="body2" color="textSecondary">
                          Schedule: {state.selectedPipeline.schedule}
                        </Typography>
                      )}
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </Box>

      {/* Add/Edit Dialog */}
      <Dialog open={state.dialogOpen} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {state.editMode ? 'Edit Pipeline' : 'Add Pipeline'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Name"
                value={state.formData.name || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, name: e.target.value }
                }))}
                required
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Trigger</InputLabel>
                <Select
                  value={state.formData.trigger || PipelineTrigger.MANUAL}
                  onChange={(e) => setState(prev => ({
                    ...prev,
                    formData: { ...prev.formData, trigger: e.target.value as PipelineTrigger }
                  }))}
                  label="Trigger"
                >
                  {Object.values(PipelineTrigger).map((trigger) => (
                    <MenuItem key={trigger} value={trigger}>{trigger}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={state.formData.description || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, description: e.target.value }
                }))}
                multiline
                rows={3}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Repository URL"
                value={state.formData.repository_url || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, repository_url: e.target.value }
                }))}
                required
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Branch"
                value={state.formData.branch || 'main'}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, branch: e.target.value }
                }))}
                required
              />
            </Grid>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Security Scan Types</InputLabel>
                <Select
                  multiple
                  value={state.formData.security_scan_types || []}
                  onChange={(e) => setState(prev => ({
                    ...prev,
                    formData: { ...prev.formData, security_scan_types: e.target.value as SecurityScanType[] }
                  }))}
                  label="Security Scan Types"
                >
                  {Object.values(SecurityScanType).map((scanType) => (
                    <MenuItem key={scanType} value={scanType}>{scanType}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Schedule (Cron)"
                value={state.formData.schedule || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, schedule: e.target.value }
                }))}
                placeholder="0 0 * * *"
                helperText="Leave empty for manual triggers"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={state.formData.enabled || false}
                    onChange={(e) => setState(prev => ({
                      ...prev,
                      formData: { ...prev.formData, enabled: e.target.checked }
                    }))}
                  />
                }
                label="Enabled"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button onClick={handleSubmit} variant="contained">
            {state.editMode ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Error Snackbar */}
      <Snackbar
        open={!!state.error}
        autoHideDuration={6000}
        onClose={() => setState(prev => ({ ...prev, error: null }))}
      >
        <Alert severity="error" onClose={() => setState(prev => ({ ...prev, error: null }))}>
          {state.error}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default CICD;
