import React from 'react';
import RASPProjects from '../../components/RASP/RASPProjects';

const RASPProjectsPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <RASPProjects />
      </div>
    </div>
  );
};

export default RASPProjectsPage;
