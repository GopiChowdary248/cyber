import React, { useState, useEffect } from 'react';
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
  Fab,
  Tooltip,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Badge
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Schedule as ScheduleIcon,
  Flag as FlagIcon,
  Assessment as AssessmentIcon,
  Download as DownloadIcon,
  FilterList as FilterIcon,
  Refresh as RefreshIcon,
  Archive as ArchiveIcon,
  Unarchive as UnarchiveIcon
} from '@mui/icons-material';
import { qualityGoalsService, QualityGoalResponse, QualityGoalCreate, QualityGoalUpdate, QualityGoalStatus, QualityGoalType, QualityGoalPriority, QualityGoalFilter } from '../services/qualityGoalsService';

interface QualityGoalsPageState {
  goals: QualityGoalResponse[];
  loading: boolean;
  error: string | null;
  dialogOpen: boolean;
  editMode: boolean;
  currentGoal: QualityGoalResponse | null;
  formData: Partial<QualityGoalCreate>;
  filters: QualityGoalFilter;
  pagination: {
    page: number;
    limit: number;
    total: number;
  };
  metrics: any;
  showMetrics: boolean;
}

const QualityGoals: React.FC = () => {
  const [state, setState] = useState<QualityGoalsPageState>({
    goals: [],
    loading: false,
    error: null,
    dialogOpen: false,
    editMode: false,
    currentGoal: null,
    formData: {
      name: '',
      description: '',
      type: QualityGoalType.SECURITY,
      priority: QualityGoalPriority.MEDIUM,
      target_value: 0,
      current_value: 0,
      unit: '',
      status: QualityGoalStatus.ACTIVE
    },
    filters: {},
    pagination: {
      page: 1,
      limit: 20,
      total: 0
    },
    metrics: null,
    showMetrics: false
  });

  useEffect(() => {
    loadGoals();
    loadMetrics();
  }, [state.pagination.page, state.filters]);

  const loadGoals = async () => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    try {
      const response = await qualityGoalsService.getQualityGoals(
        state.pagination.page,
        state.pagination.limit,
        state.filters
      );
      setState(prev => ({
        ...prev,
        goals: response.goals,
        pagination: {
          ...prev.pagination,
          total: response.total
        },
        loading: false
      }));
    } catch (error) {
      setState(prev => ({
        ...prev,
        error: 'Failed to load quality goals',
        loading: false
      }));
    }
  };

  const loadMetrics = async () => {
    try {
      const metrics = await qualityGoalsService.getQualityGoalMetrics();
      setState(prev => ({ ...prev, metrics }));
    } catch (error) {
      console.error('Failed to load metrics:', error);
    }
  };

  const handleOpenDialog = (goal?: QualityGoalResponse) => {
    if (goal) {
      setState(prev => ({
        ...prev,
        editMode: true,
        currentGoal: goal,
        formData: { ...goal },
        dialogOpen: true
      }));
    } else {
      setState(prev => ({
        ...prev,
        editMode: false,
        currentGoal: null,
        formData: {
          name: '',
          description: '',
          type: QualityGoalType.SECURITY,
          priority: QualityGoalPriority.MEDIUM,
          target_value: 0,
          current_value: 0,
          unit: '',
          status: QualityGoalStatus.ACTIVE
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
      if (state.editMode && state.currentGoal) {
        await qualityGoalsService.updateQualityGoal(state.currentGoal.id, state.formData as QualityGoalUpdate);
      } else {
        await qualityGoalsService.createQualityGoal(state.formData as QualityGoalCreate);
      }
      handleCloseDialog();
      loadGoals();
      loadMetrics();
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Failed to save quality goal' }));
    }
  };

  const handleDelete = async (goalId: string) => {
    if (window.confirm('Are you sure you want to delete this quality goal?')) {
      try {
        await qualityGoalsService.deleteQualityGoal(goalId);
        loadGoals();
        loadMetrics();
      } catch (error) {
        setState(prev => ({ ...prev, error: 'Failed to delete quality goal' }));
      }
    }
  };

  const handleProgressUpdate = async (goalId: string, currentValue: number) => {
    try {
      await qualityGoalsService.updateGoalProgress(goalId, currentValue);
      loadGoals();
      loadMetrics();
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Failed to update progress' }));
    }
  };

  const getPriorityColor = (priority: QualityGoalPriority) => {
    switch (priority) {
      case QualityGoalPriority.CRITICAL: return 'error';
      case QualityGoalPriority.HIGH: return 'warning';
      case QualityGoalPriority.MEDIUM: return 'info';
      case QualityGoalPriority.LOW: return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status: QualityGoalStatus) => {
    switch (status) {
      case QualityGoalStatus.ACTIVE: return 'success';
      case QualityGoalStatus.INACTIVE: return 'warning';
      case QualityGoalStatus.ARCHIVED: return 'default';
      default: return 'default';
    }
  };

  const getProgressColor = (progress: number) => {
    if (progress >= 80) return 'success';
    if (progress >= 60) return 'info';
    if (progress >= 40) return 'warning';
    return 'error';
  };

  const calculateProgress = (current: number, target: number) => {
    if (target === 0) return 0;
    return Math.min((current / target) * 100, 100);
  };

  const handleFilterChange = (filter: Partial<QualityGoalFilter>) => {
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

  const handleExport = async (format: 'csv' | 'pdf' | 'excel') => {
    try {
      const blob = await qualityGoalsService.exportQualityGoalsReport(format, state.filters);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `quality-goals-report.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Failed to export report' }));
    }
  };

  if (state.loading && state.goals.length === 0) {
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
            Quality Goals
          </Typography>
          <Box>
            <Button
              variant="outlined"
              startIcon={<AssessmentIcon />}
              onClick={() => setState(prev => ({ ...prev, showMetrics: !prev.showMetrics }))}
              sx={{ mr: 2 }}
            >
              {state.showMetrics ? 'Hide' : 'Show'} Metrics
            </Button>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => handleOpenDialog()}
            >
              Add Quality Goal
            </Button>
          </Box>
        </Box>

        {/* Metrics Section */}
        {state.showMetrics && state.metrics && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Quality Goals Overview
              </Typography>
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="primary">
                      {state.metrics.total_goals}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Total Goals
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="success.main">
                      {state.metrics.active_goals}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Active Goals
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="warning.main">
                      {state.metrics.overdue_goals}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Overdue Goals
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box textAlign="center">
                    <Typography variant="h4" color="info.main">
                      {state.metrics.average_progress.toFixed(1)}%
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Average Progress
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
                  <InputLabel>Type</InputLabel>
                  <Select
                    value={state.filters.type || ''}
                    onChange={(e) => handleFilterChange({ type: e.target.value as QualityGoalType })}
                    label="Type"
                  >
                    <MenuItem value="">All Types</MenuItem>
                    {Object.values(QualityGoalType).map((type) => (
                      <MenuItem key={type} value={type}>{type}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Priority</InputLabel>
                  <Select
                    value={state.filters.priority || ''}
                    onChange={(e) => handleFilterChange({ priority: e.target.value as QualityGoalPriority })}
                    label="Priority"
                  >
                    <MenuItem value="">All Priorities</MenuItem>
                    {Object.values(QualityGoalPriority).map((priority) => (
                      <MenuItem key={priority} value={priority}>{priority}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={state.filters.status || ''}
                    onChange={(e) => handleFilterChange({ status: e.target.value as QualityGoalStatus })}
                    label="Status"
                  >
                    <MenuItem value="">All Statuses</MenuItem>
                    {Object.values(QualityGoalStatus).map((status) => (
                      <MenuItem key={status} value={status}>{status}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={loadGoals}
                  fullWidth
                >
                  Refresh
                </Button>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Goals Table */}
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Quality Goals ({state.pagination.total})
              </Typography>
              <Box>
                <Button
                  size="small"
                  startIcon={<DownloadIcon />}
                  onClick={() => handleExport('csv')}
                  sx={{ mr: 1 }}
                >
                  CSV
                </Button>
                <Button
                  size="small"
                  startIcon={<DownloadIcon />}
                  onClick={() => handleExport('pdf')}
                  sx={{ mr: 1 }}
                >
                  PDF
                </Button>
                <Button
                  size="small"
                  startIcon={<DownloadIcon />}
                  onClick={() => handleExport('excel')}
                >
                  Excel
                </Button>
              </Box>
            </Box>

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Progress</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Current</TableCell>
                    <TableCell>Deadline</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {state.goals.map((goal) => {
                    const progress = calculateProgress(goal.current_value, goal.target_value);
                    return (
                      <TableRow key={goal.id}>
                        <TableCell>
                          <Box>
                            <Typography variant="subtitle2">{goal.name}</Typography>
                            <Typography variant="body2" color="textSecondary">
                              {goal.description}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip label={goal.type} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={goal.priority}
                            color={getPriorityColor(goal.priority) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={goal.status}
                            color={getStatusColor(goal.status) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Box sx={{ width: '100%', mr: 1 }}>
                              <LinearProgress
                                variant="determinate"
                                value={progress}
                                color={getProgressColor(progress) as any}
                                sx={{ height: 8, borderRadius: 4 }}
                              />
                            </Box>
                            <Typography variant="body2" color="textSecondary">
                              {progress.toFixed(1)}%
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {goal.target_value} {goal.unit}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {goal.current_value} {goal.unit}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {goal.deadline ? (
                            <Typography variant="body2">
                              {new Date(goal.deadline).toLocaleDateString()}
                            </Typography>
                          ) : (
                            <Typography variant="body2" color="textSecondary">
                              No deadline
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Box>
                            <IconButton
                              size="small"
                              onClick={() => handleOpenDialog(goal)}
                              color="primary"
                            >
                              <EditIcon />
                            </IconButton>
                            <IconButton
                              size="small"
                              onClick={() => handleDelete(goal.id)}
                              color="error"
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Box>
                        </TableCell>
                      </TableRow>
                    );
                  })}
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
      </Box>

      {/* Add/Edit Dialog */}
      <Dialog open={state.dialogOpen} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {state.editMode ? 'Edit Quality Goal' : 'Add Quality Goal'}
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
                <InputLabel>Type</InputLabel>
                <Select
                  value={state.formData.type || QualityGoalType.SECURITY}
                  onChange={(e) => setState(prev => ({
                    ...prev,
                    formData: { ...prev.formData, type: e.target.value as QualityGoalType }
                  }))}
                  label="Type"
                >
                  {Object.values(QualityGoalType).map((type) => (
                    <MenuItem key={type} value={type}>{type}</MenuItem>
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
              <FormControl fullWidth>
                <InputLabel>Priority</InputLabel>
                <Select
                  value={state.formData.priority || QualityGoalPriority.MEDIUM}
                  onChange={(e) => setState(prev => ({
                    ...prev,
                    formData: { ...prev.formData, priority: e.target.value as QualityGoalPriority }
                  }))}
                  label="Priority"
                >
                  {Object.values(QualityGoalPriority).map((priority) => (
                    <MenuItem key={priority} value={priority}>{priority}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={state.formData.status || QualityGoalStatus.ACTIVE}
                  onChange={(e) => setState(prev => ({
                    ...prev,
                    formData: { ...prev.formData, status: e.target.value as QualityGoalStatus }
                  }))}
                  label="Status"
                >
                  {Object.values(QualityGoalStatus).map((status) => (
                    <MenuItem key={status} value={status}>{status}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="Target Value"
                type="number"
                value={state.formData.target_value || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, target_value: parseFloat(e.target.value) || 0 }
                }))}
                required
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="Current Value"
                type="number"
                value={state.formData.current_value || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, current_value: parseFloat(e.target.value) || 0 }
                }))}
                required
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="Unit"
                value={state.formData.unit || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, unit: e.target.value }
                }))}
                required
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Deadline"
                type="date"
                value={state.formData.deadline || ''}
                onChange={(e) => setState(prev => ({
                  ...prev,
                  formData: { ...prev.formData, deadline: e.target.value }
                }))}
                InputLabelProps={{ shrink: true }}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={state.formData.status === QualityGoalStatus.ACTIVE}
                    onChange={(e) => setState(prev => ({
                      ...prev,
                      formData: { ...prev.formData, status: e.target.checked ? QualityGoalStatus.ACTIVE : QualityGoalStatus.INACTIVE }
                    }))}
                  />
                }
                label="Active"
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

export default QualityGoals;
