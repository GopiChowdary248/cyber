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
import Login from './pages/Login/Login';
import Register from './pages/Auth/Register';
import Incidents from './pages/Incidents/Incidents';
import Settings from './pages/Settings/Settings';
import UserDashboard from './pages/User/UserDashboard';
import AdminDashboard from './pages/Admin/AdminDashboard';

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
  return (
    <Router>
      <div className="flex h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        {/* Enhanced Navigation */}
        <EnhancedNavigation />
        
        {/* Main Content */}
        <main className="flex-1 overflow-hidden">
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
                element={<Navigate to="/" replace />} 
              />
            </Routes>
          </AnimatePresence>
        </main>
      </div>
    </Router>
  );
};

const App: React.FC = () => {
  return (
    <DesignSystemProvider theme="dark">
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </DesignSystemProvider>
  );
};

export default App; 