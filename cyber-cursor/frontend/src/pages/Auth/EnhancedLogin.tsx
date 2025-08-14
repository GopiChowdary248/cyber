import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import {
  ShieldCheckIcon,
  EyeIcon,
  EyeSlashIcon,
  LockClosedIcon,
  UserIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ArrowRightIcon,
  KeyIcon,
  ServerIcon,
  QrCodeIcon,
  ClockIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import { useAuth } from '../../contexts/AuthContext';

interface LoginFormData {
  email: string;
  password: string;
  twoFactorCode?: string;
}

const EnhancedLogin: React.FC = () => {
  const navigate = useNavigate();
  const { login, isAuthenticated, user } = useAuth();
  
  const [formData, setFormData] = useState<LoginFormData>({
    email: '',
    password: '',
    twoFactorCode: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [step, setStep] = useState<'login' | '2fa'>('login');
  const [requires2FA, setRequires2FA] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);
  const [lockoutTime, setLockoutTime] = useState<Date | null>(null);

  // Check if user is already authenticated and redirect
  useEffect(() => {
    if (isAuthenticated && user) {
      redirectBasedOnRole(user.role);
    }
  }, [isAuthenticated, user]);

  // Check for lockout
  useEffect(() => {
    if (lockoutTime) {
      const now = new Date();
      const timeDiff = now.getTime() - lockoutTime.getTime();
      if (timeDiff >= 15 * 60 * 1000) { // 15 minutes
        setIsLocked(false);
        setLockoutTime(null);
        setLoginAttempts(0);
      }
    }
  }, [lockoutTime]);

  const redirectBasedOnRole = (role: string) => {
    if (role === 'admin') {
      navigate('/admin/dashboard');
    } else {
      navigate('/dashboard');
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    setError('');
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (isLocked) {
      setError('Account is temporarily locked. Please try again later.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      await login(formData.email, formData.password);
      
      // Check if 2FA is required (simulated)
      if (formData.email.includes('admin') || formData.email.includes('2fa')) {
        setRequires2FA(true);
        setStep('2fa');
        setSuccess('Please enter your 2FA code');
      } else {
        setSuccess('Login successful! Redirecting...');
        setTimeout(() => {
          const role = formData.email.includes('admin') ? 'admin' : 'user';
          redirectBasedOnRole(role);
        }, 1000);
      }
    } catch (error) {
      console.error('Login failed:', error);
      setLoginAttempts(prev => prev + 1);
      
      if (loginAttempts >= 4) {
        setIsLocked(true);
        setLockoutTime(new Date());
        setError('Too many failed attempts. Account locked for 15 minutes.');
      } else {
        setError('Invalid credentials. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handle2FAVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.twoFactorCode) {
      setError('Please enter your 2FA code');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      setSuccess('2FA verification successful! Redirecting...');
      setTimeout(() => {
        const role = formData.email.includes('admin') ? 'admin' : 'user';
        redirectBasedOnRole(role);
      }, 1000);
    } catch (error) {
      setError('Invalid 2FA code. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async (role: 'user' | 'admin') => {
    setFormData({
      email: role === 'admin' ? 'admin@cybershield.com' : 'user@cybershield.com',
      password: 'demo123',
      twoFactorCode: ''
    });
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      setSuccess(`Demo ${role} login successful! Redirecting...`);
      setTimeout(() => {
        redirectBasedOnRole(role);
      }, 1000);
    } catch (error) {
      setError('Demo login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const remainingLockoutTime = () => {
    if (!lockoutTime) return 0;
    const now = new Date();
    const timeDiff = now.getTime() - lockoutTime.getTime();
    const remaining = Math.max(0, 15 * 60 * 1000 - timeDiff);
    return Math.ceil(remaining / 1000 / 60);
  };

  return (
    <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <div className="relative z-10 flex items-center justify-center min-h-screen p-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="w-full max-w-md"
        >
          {/* Logo and Title */}
          <div className="text-center mb-8">
            <motion.div
              initial={{ scale: 0.8 }}
              animate={{ scale: 1 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl mb-4"
            >
              <ShieldCheckIcon className="w-8 h-8 text-white" />
            </motion.div>
            <h1 className="text-3xl font-bold text-white mb-2">CyberShield</h1>
            <p className="text-gray-400">Secure Access Portal</p>
          </div>

          {/* Login Form */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 border border-white/20 shadow-2xl"
          >
            <AnimatePresence mode="wait">
              {step === 'login' && (
                <motion.form
                  key="login"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ duration: 0.3 }}
                  onSubmit={handleLogin}
                  className="space-y-6"
                >
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                      Email Address
                    </label>
                    <div className="relative">
                      <UserIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                      <input
                        type="email"
                        id="email"
                        name="email"
                        value={formData.email}
                        onChange={handleInputChange}
                        disabled={isLocked}
                        className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                        placeholder="Enter your email"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
                      Password
                    </label>
                    <div className="relative">
                      <LockClosedIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        id="password"
                        name="password"
                        value={formData.password}
                        onChange={handleInputChange}
                        disabled={isLocked}
                        className="w-full pl-10 pr-12 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                        placeholder="Enter your password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                      >
                        {showPassword ? (
                          <EyeSlashIcon className="w-5 h-5" />
                        ) : (
                          <EyeIcon className="w-5 h-5" />
                        )}
                      </button>
                    </div>
                  </div>

                  {isLocked && (
                    <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4">
                      <div className="flex items-center text-red-400">
                        <ClockIcon className="w-5 h-5 mr-2" />
                        <span>Account locked for {remainingLockoutTime()} minutes</span>
                      </div>
                    </div>
                  )}

                  {error && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="bg-red-500/20 border border-red-500/30 rounded-lg p-4"
                    >
                      <div className="flex items-center text-red-400">
                        <ExclamationTriangleIcon className="w-5 h-5 mr-2" />
                        <span>{error}</span>
                      </div>
                    </motion.div>
                  )}

                  {success && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="bg-green-500/20 border border-green-500/30 rounded-lg p-4"
                    >
                      <div className="flex items-center text-green-400">
                        <CheckCircleIcon className="w-5 h-5 mr-2" />
                        <span>{success}</span>
                      </div>
                    </motion.div>
                  )}

                  <button
                    type="submit"
                    disabled={loading || isLocked}
                    className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 px-6 rounded-lg font-medium hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                  >
                    {loading ? (
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                        className="w-5 h-5 border-2 border-white border-t-transparent rounded-full"
                      />
                    ) : (
                      <>
                        <span>Sign In</span>
                        <ArrowRightIcon className="w-5 h-5 ml-2" />
                      </>
                    )}
                  </button>
                </motion.form>
              )}

              {step === '2fa' && (
                <motion.form
                  key="2fa"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ duration: 0.3 }}
                  onSubmit={handle2FAVerification}
                  className="space-y-6"
                >
                  <div className="text-center">
                    <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-500/20 rounded-full mb-4">
                      <QrCodeIcon className="w-8 h-8 text-blue-400" />
                    </div>
                    <h3 className="text-xl font-semibold text-white mb-2">Two-Factor Authentication</h3>
                    <p className="text-gray-400">Enter the 6-digit code from your authenticator app</p>
                  </div>

                  <div>
                    <label htmlFor="twoFactorCode" className="block text-sm font-medium text-gray-300 mb-2">
                      2FA Code
                    </label>
                    <div className="relative">
                      <KeyIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                      <input
                        type="text"
                        id="twoFactorCode"
                        name="twoFactorCode"
                        value={formData.twoFactorCode}
                        onChange={handleInputChange}
                        className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 text-center text-lg tracking-widest"
                        placeholder="000000"
                        maxLength={6}
                        required
                      />
                    </div>
                  </div>

                  {error && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="bg-red-500/20 border border-red-500/30 rounded-lg p-4"
                    >
                      <div className="flex items-center text-red-400">
                        <ExclamationTriangleIcon className="w-5 h-5 mr-2" />
                        <span>{error}</span>
                      </div>
                    </motion.div>
                  )}

                  {success && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="bg-green-500/20 border border-green-500/30 rounded-lg p-4"
                    >
                      <div className="flex items-center text-green-400">
                        <CheckCircleIcon className="w-5 h-5 mr-2" />
                        <span>{success}</span>
                      </div>
                    </motion.div>
                  )}

                  <div className="flex space-x-3">
                    <button
                      type="button"
                      onClick={() => setStep('login')}
                      className="flex-1 bg-gray-600 text-white py-3 px-6 rounded-lg font-medium hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 focus:ring-offset-slate-900 transition-all duration-200 flex items-center justify-center"
                    >
                      <XMarkIcon className="w-5 h-5 mr-2" />
                      Back
                    </button>
                    <button
                      type="submit"
                      disabled={loading}
                      className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 px-6 rounded-lg font-medium hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                    >
                      {loading ? (
                        <motion.div
                          animate={{ rotate: 360 }}
                          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                          className="w-5 h-5 border-2 border-white border-t-transparent rounded-full"
                        />
                      ) : (
                        <>
                          <span>Verify</span>
                          <CheckCircleIcon className="w-5 h-5 ml-2" />
                        </>
                      )}
                    </button>
                  </div>
                </motion.form>
              )}
            </AnimatePresence>

            {/* Demo Login Buttons */}
            {step === 'login' && !isLocked && (
              <div className="mt-6 pt-6 border-t border-white/20">
                <p className="text-center text-gray-400 text-sm mb-4">Quick Demo Access</p>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => handleDemoLogin('user')}
                    disabled={loading}
                    className="bg-green-600/20 border border-green-500/30 text-green-400 py-2 px-4 rounded-lg text-sm font-medium hover:bg-green-600/30 transition-all duration-200 disabled:opacity-50"
                  >
                    <UserIcon className="w-4 h-4 inline mr-1" />
                    User Demo
                  </button>
                  <button
                    onClick={() => handleDemoLogin('admin')}
                    disabled={loading}
                    className="bg-purple-600/20 border border-purple-500/30 text-purple-400 py-2 px-4 rounded-lg text-sm font-medium hover:bg-purple-600/30 transition-all duration-200 disabled:opacity-50"
                  >
                    <ServerIcon className="w-4 h-4 inline mr-1" />
                    Admin Demo
                  </button>
                </div>
              </div>
            )}
          </motion.div>

          {/* Footer Links */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.4 }}
            className="text-center mt-6"
          >
            <p className="text-gray-400 text-sm">
              Don't have an account?{' '}
              <Link to="/register" className="text-blue-400 hover:text-blue-300 transition-colors">
                Sign up
              </Link>
            </p>
            <p className="text-gray-500 text-xs mt-2">
              Secure access to CyberShield's comprehensive cybersecurity platform
            </p>
          </motion.div>
        </motion.div>
      </div>
    </div>
  );
};

export default EnhancedLogin; 