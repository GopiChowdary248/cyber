import React, { useState, useEffect } from 'react';
import { Card, CardContent, Typography, Grid, Box, Chip, LinearProgress } from '@mui/material';
import { 
  Security, 
  Cloud, 
  Code, 
  BugReport, 
  Shield, 
  Warning,
  CheckCircle,
  Error
} from '@mui/icons-material';

interface SecurityMetric {
  name: string;
  value: number;
  total: number;
  status: 'success' | 'warning' | 'error';
  icon: React.ReactNode;
}

const DashboardOverview: React.FC = () => {
  const [metrics, setMetrics] = useState<SecurityMetric[]>([
    {
      name: 'Vulnerabilities',
      value: 12,
      total: 50,
      status: 'warning',
      icon: <BugReport />
    },
    {
      name: 'Security Scans',
      value: 45,
      total: 50,
      status: 'success',
      icon: <Security />
    },
    {
      name: 'Cloud Resources',
      value: 28,
      total: 35,
      status: 'success',
      icon: <Cloud />
    },
    {
      name: 'Code Quality',
      value: 85,
      total: 100,
      status: 'success',
      icon: <Code />
    },
    {
      name: 'Threat Detection',
      value: 8,
      total: 10,
      status: 'warning',
      icon: <Shield />
    },
    {
      name: 'Compliance',
      value: 92,
      total: 100,
      status: 'success',
      icon: <CheckCircle />
    }
  ]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'success';
      case 'warning': return 'warning';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  const getProgressColor = (status: string) => {
    switch (status) {
      case 'success': return '#4caf50';
      case 'warning': return '#ff9800';
      case 'error': return '#f44336';
      default: return '#e0e0e0';
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        CyberShield Security Dashboard
      </Typography>
      
      <Grid container spacing={3}>
        {metrics.map((metric, index) => (
          <Grid item xs={12} sm={6} md={4} key={index}>
            <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flexGrow: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <Box sx={{ 
                    color: getProgressColor(metric.status),
                    mr: 1,
                    display: 'flex',
                    alignItems: 'center'
                  }}>
                    {metric.icon}
                  </Box>
                  <Typography variant="h6" component="div">
                    {metric.name}
                  </Typography>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography variant="h4" component="div" sx={{ fontWeight: 'bold' }}>
                    {metric.value}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    of {metric.total} total
                  </Typography>
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <LinearProgress 
                    variant="determinate" 
                    value={(metric.value / metric.total) * 100}
                    sx={{ 
                      height: 8, 
                      borderRadius: 4,
                      backgroundColor: '#e0e0e0',
                      '& .MuiLinearProgress-bar': {
                        backgroundColor: getProgressColor(metric.status)
                      }
                    }}
                  />
                </Box>
                
                <Chip 
                  label={metric.status.toUpperCase()} 
                  color={getStatusColor(metric.status) as any}
                  size="small"
                />
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
      
      <Box sx={{ mt: 4 }}>
        <Typography variant="h5" gutterBottom>
          Recent Security Events
        </Typography>
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Warning sx={{ color: 'warning.main', mr: 1 }} />
              <Typography variant="body1">
                New vulnerability detected in production environment
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <CheckCircle sx={{ color: 'success.main', mr: 1 }} />
              <Typography variant="body1">
                Security scan completed successfully
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Error sx={{ color: 'error.main', mr: 1 }} />
              <Typography variant="body1">
                Failed login attempt detected
              </Typography>
            </Box>
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
};

export default DashboardOverview; 