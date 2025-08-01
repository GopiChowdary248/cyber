import React, { useState, useEffect } from 'react';

interface MFAVerificationProps {
  userId: number;
  onSuccess: () => void;
  onCancel: () => void;
  onUseBackupCode: () => void;
}

const MFAVerification: React.FC<MFAVerificationProps> = ({ 
  userId, 
  onSuccess, 
  onCancel, 
  onUseBackupCode 
}) => {
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [attempts, setAttempts] = useState(0);
  const [showBackupCodeInput, setShowBackupCodeInput] = useState(false);
  const [backupCode, setBackupCode] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  const MAX_ATTEMPTS = 5;

  useEffect(() => {
    // Auto-focus on input when component mounts
    const input = document.getElementById('mfa-token-input');
    if (input) {
      input.focus();
    }
  }, []);

  const verifyToken = async (verificationToken: string) => {
    try {
      setLoading(true);
      setError('');
      
      const formData = new FormData();
      formData.append('token', verificationToken);

      const response = await fetch(`${API_URL}/api/v1/mfa/verify-login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          user_id: userId.toString(),
          token: verificationToken
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Invalid verification code');
      }

      const data = await response.json();
      if (data.success) {
        onSuccess();
      }
    } catch (err) {
      console.error('Error verifying MFA token:', err);
      setError(err instanceof Error ? err.message : 'Invalid verification code');
      setAttempts(prev => prev + 1);
    } finally {
      setLoading(false);
    }
  };

  const handleTokenSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (token.trim() && attempts < MAX_ATTEMPTS) {
      verifyToken(token);
    }
  };

  const handleBackupCodeSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (backupCode.trim() && attempts < MAX_ATTEMPTS) {
      verifyToken(backupCode);
    }
  };

  const formatBackupCode = (value: string) => {
    // Remove all non-alphanumeric characters
    const cleaned = value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    
    // Format as XXXX-XXXX
    if (cleaned.length <= 4) {
      return cleaned;
    } else {
      return `${cleaned.slice(0, 4)}-${cleaned.slice(4, 8)}`;
    }
  };

  const handleBackupCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const formatted = formatBackupCode(e.target.value);
    setBackupCode(formatted);
  };

  if (attempts >= MAX_ATTEMPTS) {
    return (
      <div className="max-w-md mx-auto">
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-6">
          <div className="text-center">
            <div className="text-4xl mb-4">🚫</div>
            <h2 className="text-xl font-bold text-white mb-2">Too Many Attempts</h2>
            <p className="text-gray-400 mb-4">
              You've exceeded the maximum number of verification attempts. Please try again later or contact support.
            </p>
            <div className="space-y-3">
              <button
                onClick={onCancel}
                className="w-full bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors"
              >
                Try Again Later
              </button>
              <button
                onClick={onUseBackupCode}
                className="w-full bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg transition-colors"
              >
                Use Backup Code
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto">
      <div className="bg-cyber-darker border border-cyber-accent/30 rounded-lg p-6">
        <div className="text-center mb-6">
          <div className="text-4xl mb-4">🔐</div>
          <h2 className="text-xl font-bold text-white mb-2">Two-Factor Authentication</h2>
          <p className="text-gray-400">
            {showBackupCodeInput 
              ? 'Enter your backup code to access your account'
              : 'Enter the 6-digit code from your authenticator app'
            }
          </p>
        </div>

        {!showBackupCodeInput ? (
          /* TOTP Token Input */
          <form onSubmit={handleTokenSubmit} className="space-y-4">
            <div>
              <label htmlFor="mfa-token-input" className="block text-sm font-medium text-gray-400 mb-2">
                Verification Code
              </label>
              <input
                id="mfa-token-input"
                type="text"
                value={token}
                onChange={(e) => setToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white text-center text-2xl tracking-widest font-mono"
                maxLength={6}
                autoFocus
              />
            </div>

            {error && (
              <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
                <p className="text-red-400 text-sm">{error}</p>
                <p className="text-gray-400 text-xs mt-1">
                  Attempts remaining: {MAX_ATTEMPTS - attempts}
                </p>
              </div>
            )}

            <div className="space-y-3">
              <button
                type="submit"
                disabled={loading || !token.trim() || token.length !== 6}
                className="w-full bg-cyber-accent hover:bg-cyber-accent/80 disabled:bg-gray-600 text-white py-2 rounded-lg transition-colors"
              >
                {loading ? 'Verifying...' : 'Verify'}
              </button>
              
              <button
                type="button"
                onClick={() => setShowBackupCodeInput(true)}
                className="w-full bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition-colors"
              >
                Use Backup Code
              </button>
              
              <button
                type="button"
                onClick={onCancel}
                className="w-full bg-transparent border border-gray-600 hover:border-gray-500 text-gray-400 hover:text-white py-2 rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        ) : (
          /* Backup Code Input */
          <form onSubmit={handleBackupCodeSubmit} className="space-y-4">
            <div>
              <label htmlFor="backup-code-input" className="block text-sm font-medium text-gray-400 mb-2">
                Backup Code
              </label>
              <input
                id="backup-code-input"
                type="text"
                value={backupCode}
                onChange={handleBackupCodeChange}
                placeholder="XXXX-XXXX"
                className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white text-center text-lg tracking-wider font-mono"
                maxLength={9}
                autoFocus
              />
            </div>

            {error && (
              <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
                <p className="text-red-400 text-sm">{error}</p>
                <p className="text-gray-400 text-xs mt-1">
                  Attempts remaining: {MAX_ATTEMPTS - attempts}
                </p>
              </div>
            )}

            <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-3">
              <p className="text-yellow-400 text-sm">
                ⚠️ Backup codes can only be used once. Make sure to save your new backup codes after logging in.
              </p>
            </div>

            <div className="space-y-3">
              <button
                type="submit"
                disabled={loading || !backupCode.trim() || backupCode.length !== 9}
                className="w-full bg-cyber-accent hover:bg-cyber-accent/80 disabled:bg-gray-600 text-white py-2 rounded-lg transition-colors"
              >
                {loading ? 'Verifying...' : 'Verify Backup Code'}
              </button>
              
              <button
                type="button"
                onClick={() => setShowBackupCodeInput(false)}
                className="w-full bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition-colors"
              >
                Use Authenticator App
              </button>
              
              <button
                type="button"
                onClick={onCancel}
                className="w-full bg-transparent border border-gray-600 hover:border-gray-500 text-gray-400 hover:text-white py-2 rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        <div className="mt-6 pt-4 border-t border-cyber-accent/20">
          <div className="text-center space-y-2">
            <p className="text-gray-400 text-sm">
              {showBackupCodeInput 
                ? 'Lost your backup codes? Contact your administrator for assistance.'
                : 'Having trouble? You can use a backup code instead.'
              }
            </p>
            <div className="flex justify-center space-x-4 text-xs">
              <button
                onClick={() => window.open('/help/mfa', '_blank')}
                className="text-cyber-accent hover:text-white"
              >
                Help & Support
              </button>
              <button
                onClick={() => window.open('/help/authenticator-apps', '_blank')}
                className="text-cyber-accent hover:text-white"
              >
                Authenticator Apps
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MFAVerification; 