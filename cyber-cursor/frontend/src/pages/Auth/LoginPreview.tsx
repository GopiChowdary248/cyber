import React, { useEffect } from 'react';

const LoginPreview: React.FC = () => {
  useEffect(() => {
    // Redirect to the login_preview.html file
    window.location.href = '/login_preview.html';
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center">
      <div className="text-center text-white">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <p className="text-lg">Redirecting to login preview...</p>
      </div>
    </div>
  );
};

export default LoginPreview; 