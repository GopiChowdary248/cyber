import React, { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import EnhancedCard from '../../components/UI/EnhancedCard';
import EnhancedButton from '../../components/UI/EnhancedButton';
import { Shield, Eye, EyeOff } from 'lucide-react';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      await login(email, password);
    } catch (error) {
      console.error('Login failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async (demoEmail: string) => {
    setEmail(demoEmail);
    setPassword('password');
    setLoading(true);
    
    try {
      await login(demoEmail, 'password');
    } catch (error) {
      console.error('Demo login failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-dark flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <EnhancedCard>
          <div className="p-8">
            {/* Header */}
            <div className="text-center mb-8">
              <div className="flex justify-center mb-4">
                <Shield className="h-12 w-12 text-red-500" />
              </div>
              <h1 className="text-2xl font-bold text-white mb-2">CyberShield</h1>
              <p className="text-gray-400">Sign in to your account</p>
            </div>

            {/* Login Form */}
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                  Email Address
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                  placeholder="Enter your email"
                  required
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent pr-10"
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-300"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <EnhancedButton
                type="submit"
                disabled={loading}
                className="w-full"
                variant="primary"
              >
                {loading ? 'Signing in...' : 'Sign In'}
              </EnhancedButton>
            </form>

            {/* Demo Accounts */}
            <div className="mt-8 pt-6 border-t border-gray-700">
              <h3 className="text-sm font-medium text-gray-300 mb-4">Demo Accounts</h3>
              <div className="space-y-2">
                <EnhancedButton
                  onClick={() => handleDemoLogin('admin@cybershield.com')}
                  variant="outline"
                  size="sm"
                  className="w-full"
                  disabled={loading}
                >
                  Admin Account
                </EnhancedButton>
                <EnhancedButton
                  onClick={() => handleDemoLogin('analyst@cybershield.com')}
                  variant="outline"
                  size="sm"
                  className="w-full"
                  disabled={loading}
                >
                  Analyst Account
                </EnhancedButton>
                <EnhancedButton
                  onClick={() => handleDemoLogin('user@cybershield.com')}
                  variant="outline"
                  size="sm"
                  className="w-full"
                  disabled={loading}
                >
                  User Account
                </EnhancedButton>
              </div>
              <p className="text-xs text-gray-500 mt-2 text-center">
                All demo accounts use password: <code className="bg-gray-800 px-1 rounded">password</code>
              </p>
            </div>

            {/* Footer */}
            <div className="mt-8 text-center">
              <p className="text-xs text-gray-500">
                This is a demo application. No real authentication is performed.
              </p>
            </div>
          </div>
        </EnhancedCard>
      </div>
    </div>
  );
};

export default Login; 