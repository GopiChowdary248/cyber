import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import MFASetup from '../../components/Auth/MFASetup';

interface MFAStatus {
  enabled: boolean;
  setup_pending: boolean;
  backup_codes_remaining: number;
  enabled_at: string | null;
  last_used: string | null;
}

const MFAManagement: React.FC = () => {
  const { user } = useAuth();
  const [mfaStatus, setMfaStatus] = useState<MFAStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [showSetup, setShowSetup] = useState(false);
  const [showDisable, setShowDisable] = useState(false);
  const [showRegenerate, setShowRegenerate] = useState(false);
  const [password, setPassword] = useState('');
  const [newBackupCodes, setNewBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchMFAStatus();
  }, []);

  const fetchMFAStatus = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/mfa/status`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setMfaStatus(data.mfa_status);
      }
    } catch (err) {
      console.error('Error fetching MFA status:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDisableMFA = async () => {
    if (!password.trim()) {
      setError('Please enter your password');
      return;
    }

    try {
      setLoading(true);
      setError('');
      
      const token = localStorage.getItem('access_token');
      const formData = new FormData();
      formData.append('password', password);

      const response = await fetch(`${API_URL}/api/v1/mfa/disable`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        setSuccess(data.message);
        setShowDisable(false);
        setPassword('');
        fetchMFAStatus();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to disable MFA');
      }
    } catch (err) {
      console.error('Error disabling MFA:', err);
      setError(err instanceof Error ? err.message : 'Failed to disable MFA');
    } finally {
      setLoading(false);
    }
  };

  const handleRegenerateBackupCodes = async () => {
    if (!password.trim()) {
      setError('Please enter your password');
      return;
    }

    try {
      setLoading(true);
      setError('');
      
      const token = localStorage.getItem('access_token');
      const formData = new FormData();
      formData.append('password', password);

      const response = await fetch(`${API_URL}/api/v1/mfa/regenerate-backup-codes`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        setNewBackupCodes(data.backup_codes);
        setSuccess(data.message);
        setShowRegenerate(false);
        setPassword('');
        fetchMFAStatus();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to regenerate backup codes');
      }
    } catch (err) {
      console.error('Error regenerating backup codes:', err);
      setError(err instanceof Error ? err.message : 'Failed to regenerate backup codes');
    } finally {
      setLoading(false);
    }
  };

  const downloadBackupCodes = (codes: string[]) => {
    const codesText = `CyberShield Backup Codes\n\n${codes.join('\n')}\n\nKeep these codes in a secure location. Each code can only be used once.`;
    const blob = new Blob([codesText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cybershield-backup-codes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading && !mfaStatus) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-accent"></div>
      </div>
    );
  }

  if (showSetup) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">🔐 Setup Two-Factor Authentication</h1>
          <button
            onClick={() => setShowSetup(false)}
            className="text-gray-400 hover:text-white"
          >
            ✕
          </button>
        </div>
        <MFASetup
          onComplete={() => {
            setShowSetup(false);
            fetchMFAStatus();
          }}
          onCancel={() => setShowSetup(false)}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900/20 to-cyan-900/20 border border-blue-700/30 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">🔐 Two-Factor Authentication</h1>
            <p className="text-gray-400">Manage your account security with 2FA</p>
          </div>
          <div className="text-right">
            <div className={`text-2xl font-bold ${mfaStatus?.enabled ? 'text-green-400' : 'text-red-400'}`}>
              {mfaStatus?.enabled ? '🟢 Enabled' : '🔴 Disabled'}
            </div>
          </div>
        </div>
      </div>

      {/* Success/Error Messages */}
      {success && (
        <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
          <p className="text-green-400">{success}</p>
        </div>
      )}

      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* MFA Status */}
      <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
        <h2 className="text-xl font-semibold text-white mb-4">📊 Current Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
              <span className="text-gray-400">Status</span>
              <span className={`font-semibold ${mfaStatus?.enabled ? 'text-green-400' : 'text-red-400'}`}>
                {mfaStatus?.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
            <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
              <span className="text-gray-400">Backup Codes</span>
              <span className="text-white">{mfaStatus?.backup_codes_remaining || 0} remaining</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
              <span className="text-gray-400">Enabled Since</span>
              <span className="text-white">{formatDate(mfaStatus?.enabled_at || null)}</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-cyber-dark rounded-lg">
              <span className="text-gray-400">Last Used</span>
              <span className="text-white">{formatDate(mfaStatus?.last_used || null)}</span>
            </div>
          </div>
          
          <div className="space-y-4">
            <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
              <h3 className="text-blue-400 font-semibold mb-2">🔒 Security Benefits</h3>
              <ul className="text-sm text-gray-300 space-y-1">
                <li>• Protection against password breaches</li>
                <li>• Secure access to sensitive data</li>
                <li>• Compliance with security standards</li>
                <li>• Account recovery options</li>
              </ul>
            </div>
            
            <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4">
              <h3 className="text-yellow-400 font-semibold mb-2">⚠️ Important Notes</h3>
              <ul className="text-sm text-gray-300 space-y-1">
                <li>• Keep backup codes in a secure location</li>
                <li>• Each backup code can only be used once</li>
                <li>• Contact support if you lose access</li>
                <li>• Regularly update your authenticator app</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {!mfaStatus?.enabled ? (
          <button
            onClick={() => setShowSetup(true)}
            className="bg-cyber-accent hover:bg-cyber-accent/80 text-white p-6 rounded-lg transition-colors text-center"
          >
            <div className="text-3xl mb-2">🔐</div>
            <div className="font-semibold">Enable 2FA</div>
            <div className="text-sm opacity-75">Setup two-factor authentication</div>
          </button>
        ) : (
          <>
            <button
              onClick={() => setShowDisable(true)}
              className="bg-red-600 hover:bg-red-700 text-white p-6 rounded-lg transition-colors text-center"
            >
              <div className="text-3xl mb-2">🚫</div>
              <div className="font-semibold">Disable 2FA</div>
              <div className="text-sm opacity-75">Remove two-factor authentication</div>
            </button>
            
            <button
              onClick={() => setShowRegenerate(true)}
              className="bg-orange-600 hover:bg-orange-700 text-white p-6 rounded-lg transition-colors text-center"
            >
              <div className="text-3xl mb-2">🔄</div>
              <div className="font-semibold">New Backup Codes</div>
              <div className="text-sm opacity-75">Generate new backup codes</div>
            </button>
          </>
        )}
        
        <button
          onClick={() => window.open('/help/mfa', '_blank')}
          className="bg-gray-600 hover:bg-gray-700 text-white p-6 rounded-lg transition-colors text-center"
        >
          <div className="text-3xl mb-2">❓</div>
          <div className="font-semibold">Help & Support</div>
          <div className="text-sm opacity-75">Get help with 2FA</div>
        </button>
      </div>

      {/* New Backup Codes Modal */}
      {newBackupCodes.length > 0 && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6 max-w-md w-full mx-4">
            <div className="text-center mb-6">
              <div className="text-4xl mb-4">🔑</div>
              <h3 className="text-xl font-bold text-white mb-2">New Backup Codes</h3>
              <p className="text-gray-400 text-sm">
                Save these new backup codes in a secure location. Your old codes are no longer valid.
              </p>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-2">
                {newBackupCodes.map((code, index) => (
                  <div key={index} className="bg-cyber-dark border border-cyber-accent/20 rounded px-3 py-2 font-mono text-sm text-center">
                    {code}
                  </div>
                ))}
              </div>
              
              <div className="flex space-x-3">
                <button
                  onClick={() => downloadBackupCodes(newBackupCodes)}
                  className="flex-1 bg-cyber-accent hover:bg-cyber-accent/80 text-white py-2 rounded-lg transition-colors"
                >
                  📥 Download
                </button>
                <button
                  onClick={() => copyToClipboard(newBackupCodes.join('\n'))}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition-colors"
                >
                  📋 Copy All
                </button>
              </div>
              
              <button
                onClick={() => setNewBackupCodes([])}
                className="w-full bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg transition-colors"
              >
                I've Saved My Codes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Disable MFA Modal */}
      {showDisable && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6 max-w-md w-full mx-4">
            <div className="text-center mb-6">
              <div className="text-4xl mb-4">⚠️</div>
              <h3 className="text-xl font-bold text-white mb-2">Disable Two-Factor Authentication</h3>
              <p className="text-gray-400 text-sm">
                This will remove 2FA from your account, making it less secure. Are you sure you want to continue?
              </p>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
                />
              </div>
              
              <div className="flex space-x-3">
                <button
                  onClick={() => {
                    setShowDisable(false);
                    setPassword('');
                    setError('');
                  }}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDisableMFA}
                  disabled={loading || !password.trim()}
                  className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white py-2 rounded-lg transition-colors"
                >
                  {loading ? 'Disabling...' : 'Disable 2FA'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Regenerate Backup Codes Modal */}
      {showRegenerate && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6 max-w-md w-full mx-4">
            <div className="text-center mb-6">
              <div className="text-4xl mb-4">🔄</div>
              <h3 className="text-xl font-bold text-white mb-2">Regenerate Backup Codes</h3>
              <p className="text-gray-400 text-sm">
                This will invalidate your current backup codes and generate new ones. Make sure to save the new codes.
              </p>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
                />
              </div>
              
              <div className="flex space-x-3">
                <button
                  onClick={() => {
                    setShowRegenerate(false);
                    setPassword('');
                    setError('');
                  }}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleRegenerateBackupCodes}
                  disabled={loading || !password.trim()}
                  className="flex-1 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white py-2 rounded-lg transition-colors"
                >
                  {loading ? 'Generating...' : 'Generate New Codes'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MFAManagement; 