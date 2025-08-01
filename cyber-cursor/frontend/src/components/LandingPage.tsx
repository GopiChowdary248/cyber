import React from 'react';
import { Shield } from 'lucide-react';

const LandingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
      <div className="text-center">
        <div className="flex justify-center mb-6">
          <Shield className="h-16 w-16 text-red-500 animate-pulse" />
        </div>
        <h1 className="text-3xl font-bold text-white mb-4">CyberShield</h1>
        <p className="text-gray-400 mb-8">Comprehensive Cybersecurity Platform</p>
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500 mx-auto"></div>
        <p className="text-gray-500 mt-4 text-sm">Loading...</p>
      </div>
    </div>
  );
};

export default LandingPage; 