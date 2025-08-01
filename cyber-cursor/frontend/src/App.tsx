import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';

// Import enhanced components
import { DesignSystemProvider } from './components/UI/DesignSystem';
import EnhancedNavigation from './components/Layout/EnhancedNavigation';

// Import pages
import EnhancedDashboard from './pages/Dashboard/EnhancedDashboard';
import EnhancedCloudSecurity from './pages/CloudSecurity/EnhancedCloudSecurity';
import EnhancedLogin from './pages/Auth/EnhancedLogin';
import LoginPreview from './pages/Auth/LoginPreview';
import Register from './pages/Auth/Register';
import Incidents from './pages/Incidents/Incidents';
import Settings from './pages/Settings/Settings';
import UserDashboard from './pages/User/UserDashboard';
import AdminDashboard from './pages/Admin/AdminDashboard';

// Import contexts
import { AuthProvider, useAuth } from './contexts/AuthContext';

// Import styles
import './index.css';

// Protected Route Component
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

const App: React.FC = () => {
  return (
    <DesignSystemProvider theme="dark">
      <AuthProvider>
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
                        <EnhancedLogin />
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

                  {/* Protected User Routes */}
                  <Route 
                    path="/" 
                    element={
                      <ProtectedRoute>
                        <motion.div
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 0.3 }}
                        >
                          <UserDashboard />
                        </motion.div>
                      </ProtectedRoute>
                    } 
                  />
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
      </AuthProvider>
    </DesignSystemProvider>
  );
};

export default App; 