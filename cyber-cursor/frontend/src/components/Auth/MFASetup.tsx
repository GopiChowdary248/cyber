import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface MFASetupData {
  qr_code: string;
  backup_codes: string[];
  secret: string;
  setup_uri: string;
}

interface MFASetupProps {
  onComplete: () => void;
  onCancel: () => void;
}

const MFASetup: React.FC<MFASetupProps> = ({ onComplete, onCancel }) => {
  const { user } = useAuth();
  const [step, setStep] = useState(1);
  const [mfaData, setMfaData] = useState<MFASetupData | null>(null);
  const [verificationToken, setVerificationToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [showSecret, setShowSecret] = useState(false);

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    if (step === 1) {
      setupMFA();
    }
  }, [step]);

  const setupMFA = async () => {
    try {
      setLoading(true);
      setError('');
      
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_URL}/api/v1/mfa/setup`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to setup MFA');
      }

      const data = await response.json();
      setMfaData(data);
    } catch (err) {
      console.error('Error setting up MFA:', err);
      setError('Failed to setup MFA. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const verifySetup = async () => {
    if (!verificationToken.trim()) {
      setError('Please enter the verification code');
      return;
    }

    try {
      setLoading(true);
      setError('');
      
      const token = localStorage.getItem('access_token');
      const formData = new FormData();
      formData.append('token', verificationToken);

      const response = await fetch(`${API_URL}/api/v1/mfa/verify-setup`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to verify MFA setup');
      }

      const data = await response.json();
      if (data.success) {
        setStep(3); // Success step
      }
    } catch (err) {
      console.error('Error verifying MFA setup:', err);
      setError(err instanceof Error ? err.message : 'Failed to verify MFA setup');
    } finally {
      setLoading(false);
    }
  };

  const downloadBackupCodes = () => {
    if (!mfaData?.backup_codes) return;

    const codesText = `CyberShield Backup Codes\n\n${mfaData.backup_codes.join('\n')}\n\nKeep these codes in a secure location. Each code can only be used once.`;
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

  const renderStep1 = () => (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-white mb-2">🔐 Setup Two-Factor Authentication</h2>
        <p className="text-gray-400">Enhance your account security with 2FA</p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyber-accent"></div>
        </div>
      ) : mfaData ? (
        <div className="space-y-6">
          {/* QR Code Section */}
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">📱 Scan QR Code</h3>
            <div className="flex flex-col items-center space-y-4">
              <div className="bg-white p-4 rounded-lg">
                <img 
                  src={mfaData.qr_code} 
                  alt="MFA QR Code" 
                  className="w-48 h-48"
                />
              </div>
              <p className="text-gray-400 text-sm text-center">
                Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
              </p>
            </div>
          </div>

          {/* Manual Entry Section */}
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">⌨️ Manual Entry</h3>
            <div className="space-y-4">
              <div className="flex items-center space-x-3">
                <span className="text-gray-400">Secret Key:</span>
                <div className="flex-1 bg-cyber-dark border border-cyber-accent/30 rounded px-3 py-2 font-mono text-sm">
                  {showSecret ? mfaData.secret : '••••••••••••••••'}
                </div>
                <button
                  onClick={() => setShowSecret(!showSecret)}
                  className="text-cyber-accent hover:text-white"
                >
                  {showSecret ? '👁️' : '👁️‍🗨️'}
                </button>
                <button
                  onClick={() => copyToClipboard(mfaData.secret)}
                  className="text-cyber-accent hover:text-white"
                  title="Copy to clipboard"
                >
                  📋
                </button>
              </div>
              <p className="text-gray-400 text-sm">
                If you can't scan the QR code, manually enter this secret key in your authenticator app
              </p>
            </div>
          </div>

          {/* Backup Codes Section */}
          <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">🔑 Backup Codes</h3>
            <div className="space-y-4">
              <p className="text-gray-400 text-sm">
                Save these backup codes in a secure location. You can use them to access your account if you lose your authenticator device.
              </p>
              
              {showBackupCodes ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    {mfaData.backup_codes.map((code, index) => (
                      <div key={index} className="bg-cyber-dark border border-cyber-accent/20 rounded px-3 py-2 font-mono text-sm text-center">
                        {code}
                      </div>
                    ))}
                  </div>
                  <div className="flex space-x-3">
                    <button
                      onClick={downloadBackupCodes}
                      className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
                    >
                      📥 Download Codes
                    </button>
                    <button
                      onClick={() => copyToClipboard(mfaData.backup_codes.join('\n'))}
                      className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors"
                    >
                      📋 Copy All
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setShowBackupCodes(true)}
                  className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
                >
                  👁️ Show Backup Codes
                </button>
              )}
            </div>
          </div>

          <div className="flex justify-between">
            <button
              onClick={onCancel}
              className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={() => setStep(2)}
              className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-6 py-2 rounded-lg transition-colors"
            >
              Next: Verify Setup
            </button>
          </div>
        </div>
      ) : (
        <div className="text-center py-8">
          <p className="text-red-400">Failed to load MFA setup data</p>
          <button
            onClick={setupMFA}
            className="mt-4 bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
          >
            Retry
          </button>
        </div>
      )}
    </div>
  );

  const renderStep2 = () => (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-white mb-2">✅ Verify Setup</h2>
        <p className="text-gray-400">Enter the code from your authenticator app to complete setup</p>
      </div>

      <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Verification Code
            </label>
            <input
              type="text"
              value={verificationToken}
              onChange={(e) => setVerificationToken(e.target.value)}
              placeholder="Enter 6-digit code"
              className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white text-center text-2xl tracking-widest"
              maxLength={6}
              autoFocus
            />
          </div>
          
          {error && (
            <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          <div className="text-center space-y-2">
            <p className="text-gray-400 text-sm">
              Open your authenticator app and enter the 6-digit code
            </p>
            <p className="text-gray-500 text-xs">
              Can't find the code? Make sure you've added the account to your authenticator app
            </p>
          </div>
        </div>
      </div>

      <div className="flex justify-between">
        <button
          onClick={() => setStep(1)}
          className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Back
        </button>
        <button
          onClick={verifySetup}
          disabled={loading || !verificationToken.trim()}
          className="bg-cyber-accent hover:bg-cyber-accent/80 disabled:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors"
        >
          {loading ? 'Verifying...' : 'Verify & Complete'}
        </button>
      </div>
    </div>
  );

  const renderStep3 = () => (
    <div className="space-y-6">
      <div className="text-center">
        <div className="text-6xl mb-4">🎉</div>
        <h2 className="text-2xl font-bold text-white mb-2">Setup Complete!</h2>
        <p className="text-gray-400">Your account is now protected with two-factor authentication</p>
      </div>

      <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-green-400 mb-4">✅ What's Next?</h3>
        <div className="space-y-3 text-sm">
          <div className="flex items-start space-x-3">
            <span className="text-green-400">1</span>
            <span className="text-gray-300">Save your backup codes in a secure location</span>
          </div>
          <div className="flex items-start space-x-3">
            <span className="text-green-400">2</span>
            <span className="text-gray-300">You'll need to enter a code from your authenticator app each time you log in</span>
          </div>
          <div className="flex items-start space-x-3">
            <span className="text-green-400">3</span>
            <span className="text-gray-300">Use backup codes if you lose access to your authenticator device</span>
          </div>
        </div>
      </div>

      <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">🔧 MFA Management</h3>
        <p className="text-gray-400 text-sm mb-4">
          You can manage your MFA settings, regenerate backup codes, or disable 2FA from your profile settings.
        </p>
        <div className="flex space-x-3">
          <button
            onClick={() => window.location.href = '/user/profile'}
            className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
          >
            Go to Profile
          </button>
          <button
            onClick={() => window.location.href = '/user'}
            className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors"
          >
            Go to Dashboard
          </button>
        </div>
      </div>

      <div className="flex justify-center">
        <button
          onClick={onComplete}
          className="bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg transition-colors font-semibold"
        >
          Complete Setup
        </button>
      </div>
    </div>
  );

  return (
    <div className="max-w-2xl mx-auto">
      {step === 1 && renderStep1()}
      {step === 2 && renderStep2()}
      {step === 3 && renderStep3()}
    </div>
  );
};

export default MFASetup; 