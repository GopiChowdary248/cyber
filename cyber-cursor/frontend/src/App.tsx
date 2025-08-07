import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';

// Import enhanced components
import { DesignSystemProvider } from './components/UI/DesignSystem';
import EnhancedNavigation from './components/Layout/EnhancedNavigation';
import LandingPage from './components/LandingPage';

// Import pages
import EnhancedDashboard from './pages/Dashboard/EnhancedDashboard';
import EnhancedCloudSecurity from './pages/CloudSecurity/EnhancedCloudSecurity';
import ApplicationSecurity from './pages/ApplicationSecurity/ApplicationSecurity';
import NetworkSecurity from './pages/NetworkSecurity/NetworkSecurity';
import EndpointSecurity from './pages/EndpointSecurity/EndpointSecurity';
import IAMSecurity from './pages/IAMSecurity/IAMSecurity';
import DataSecurity from './pages/DataSecurity/DataSecurity';
import SIEMSOAR from './pages/SIEMSOAR/SIEMSOAR';
import SAST from './pages/SAST/SAST';
import SASTIssues from './pages/SAST/SASTIssues';
import SASTScanResults from './pages/SAST/SASTScanResults';
import Projects from './pages/Projects/Projects';
import Login from './pages/Login/Login';
import Register from './pages/Auth/Register';
import Incidents from './pages/Incidents/Incidents';
import Settings from './pages/Settings/Settings';
import UserDashboard from './pages/User/UserDashboard';
import AdminDashboard from './pages/Admin/AdminDashboard';
import SASTProjectDetails from './pages/SAST/SASTProjectDetails';

// Import contexts
import { AuthProvider, useAuth } from './contexts/AuthContext';

// Import styles
import './index.css';

// Protected Route Component - moved inside AuthProvider context
const ProtectedRoute: React.FC<{ children: React.ReactNode; allowedRoles?: string[] }> = ({ 
  children, 
  allowedRoles 
}) => {
  const { isAuthenticated, user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <>{children}</>;
};

// Default Route Component for handling root path
const DefaultRoute: React.FC = () => {
  const { isAuthenticated, loading } = useAuth();

  console.log('DefaultRoute - loading:', loading, 'isAuthenticated:', isAuthenticated);

  if (loading) {
    console.log('DefaultRoute - showing loading screen');
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <div className="h-16 w-16 text-red-500 animate-pulse">🛡️</div>
          </div>
          <h1 className="text-3xl font-bold text-white mb-4">CyberShield</h1>
          <p className="text-gray-400 mb-8">Comprehensive Cybersecurity Platform</p>
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500 mx-auto"></div>
          <p className="text-gray-500 mt-4 text-sm">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    console.log('DefaultRoute - redirecting to login');
    return <Navigate to="/login" replace />;
  }

  console.log('DefaultRoute - redirecting to dashboard');
  return <Navigate to="/dashboard" replace />;
};

// Main App Content - wrapped in AuthProvider
const AppContent: React.FC = () => {
  const { isAuthenticated, loading } = useAuth();

  // Show loading screen while checking authentication
  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <div className="h-16 w-16 text-red-500 animate-pulse">🛡️</div>
          </div>
          <h1 className="text-3xl font-bold text-white mb-4">CyberShield</h1>
          <p className="text-gray-400 mb-8">Comprehensive Cybersecurity Platform</p>
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500 mx-auto"></div>
          <p className="text-gray-500 mt-4 text-sm">Loading...</p>
        </div>
      </div>
    );
  }

  // If not authenticated, show only the main content without navigation
  if (!isAuthenticated) {
    return (
      <div className="h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <main className="h-full overflow-hidden">
          <AnimatePresence mode="wait">
            <Routes>
              {/* Public Routes */}
              <Route 
                path="/login" 
                element={
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Login />
                  </motion.div>
                } 
              />
              <Route 
                path="/register" 
                element={
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Register />
                  </motion.div>
                } 
              />

              {/* Default Route */}
              <Route 
                path="/" 
                element={<DefaultRoute />} 
              />

              {/* Fallback Route */}
              <Route 
                path="*" 
                element={<Navigate to="/login" replace />} 
              />
            </Routes>
          </AnimatePresence>
        </main>
      </div>
    );
  }

  // If authenticated, show navigation and protected routes
  return (
    <div className="flex h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Enhanced Navigation - only shown when authenticated */}
      <EnhancedNavigation />
      
      {/* Main Content */}
      <main className="flex-1 overflow-hidden">
        <AnimatePresence mode="wait">
          <Routes>
            {/* Default Route */}
            <Route 
              path="/" 
              element={<DefaultRoute />} 
            />

            {/* Protected User Routes */}
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <UserDashboard />
                  </motion.div>
                </ProtectedRoute>
              } 
            />

            {/* Protected Admin Routes */}
            <Route 
              path="/admin/dashboard" 
              element={
                <ProtectedRoute allowedRoles={['admin']}>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <AdminDashboard />
                  </motion.div>
                </ProtectedRoute>
              } 
            />

            {/* Shared Protected Routes */}
            <Route 
              path="/application-security" 
              element={
                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <ApplicationSecurity />
                </motion.div>
              } 
            />
            <Route 
              path="/projects" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Projects />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/cloud-security" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <EnhancedCloudSecurity />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/network-security" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <NetworkSecurity />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/endpoint-security" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <EndpointSecurity />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/iam-security" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <IAMSecurity />
                  </motion.div>
                </ProtectedRoute>
              } 
            />

            <Route 
              path="/data-security" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <DataSecurity />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/siem-soar" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <SIEMSOAR />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
                        <Route
              path="/sast"
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <SAST />
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route
              path="/sast/projects"
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <SAST />
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route
              path="/sast/projects/:projectId"
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <SASTProjectDetails />
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route
              path="/sast/issues"
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <SASTIssues />
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route
              path="/sast/results"
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <SASTScanResults />
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route 
              path="/sast/issues" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <SASTIssues />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/incidents" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Incidents />
                  </motion.div>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/settings" 
              element={
                <ProtectedRoute>
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Settings />
                  </motion.div>
                </ProtectedRoute>
              } 
            />

            {/* Fallback Route */}
            <Route 
              path="*" 
              element={<Navigate to="/dashboard" replace />} 
            />
          </Routes>
        </AnimatePresence>
      </main>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <DesignSystemProvider theme="dark">
      <Router>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </Router>
    </DesignSystemProvider>
  );
};

export default App; 