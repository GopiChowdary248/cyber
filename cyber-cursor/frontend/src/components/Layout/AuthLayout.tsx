import React from 'react';

const AuthLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="min-h-screen bg-cyber-dark">
      {children}
    </div>
  );
};

export default AuthLayout; 