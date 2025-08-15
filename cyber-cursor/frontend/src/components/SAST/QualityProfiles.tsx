import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Settings,
  Filter,
  Search,
  Eye,
  Edit,
  Save,
  X,
  Plus,
  Trash2,
  Code,
  Bug,
  Lock,
  Unlock,
  RefreshCw,
  Copy,
  Download,
  Upload,
  Clock
} from 'lucide-react';

interface QualityProfile {
  id: string;
  name: string;
  description: string;
  language: string;
  is_default: boolean;
  active_rule_count: number;
  deprecated_rule_count: number;
  created_at: string;
  updated_at: string;
  rules: QualityRule[];
}

interface QualityRule {
  id: string;
  rule_id: string;
  name: string;
  severity: string;
  category: string;
  enabled: boolean;
  effort: string;
}

interface QualityProfilesProps {
  projectId?: string;
}

const QualityProfiles: React.FC<QualityProfilesProps> = ({ projectId }) => {
  const [profiles, setProfiles] = useState<QualityProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [filteredProfiles, setFilteredProfiles] = useState<QualityProfile[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDuplicateModal, setShowDuplicateModal] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState<QualityProfile | null>(null);
  const [editingProfile, setEditingProfile] = useState<QualityProfile | null>(null);
  const [error, setError] = useState<string | null>(null);

  const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchProfiles();
  }, [projectId]);

  useEffect(() => {
    filterProfiles();
  }, [profiles, searchTerm, selectedLanguage]);

  const fetchProfiles = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      if (!token) {
        setError('Authentication token not found');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/sast/quality-profiles`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setProfiles((data && data.profiles) ? data.profiles : []);
      setError(null);
    } catch (error) {
      console.error('Error fetching quality profiles:', error);
      setError('Failed to fetch quality profiles');
      setProfiles(getMockProfiles());
    } finally {
      setLoading(false);
    }
  };

  const getMockProfiles = (): QualityProfile[] => [
    {
      id: '1',
      name: 'Sonar way',
      description: 'Default profile for most languages with common security and quality rules',
      language: 'java',
      is_default: true,
      active_rule_count: 156,
      deprecated_rule_count: 12,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-15T00:00:00Z',
      rules: [
        { id: '1', rule_id: 'S1488', name: 'Local variables should not be declared and then immediately returned', severity: 'minor', category: 'Code Smell', enabled: true, effort: '5min' },
        { id: '2', rule_id: 'S1172', name: 'Unused function parameters should be removed', severity: 'major', category: 'Code Smell', enabled: true, effort: '5min' },
        { id: '3', rule_id: 'S1135', name: 'Track uses of "FIXME" tags', severity: 'info', category: 'Code Smell', enabled: false, effort: '10min' }
      ]
    },
    {
      id: '2',
      name: 'Security Profile',
      description: 'High-security profile with strict security rules enabled',
      language: 'java',
      is_default: false,
      active_rule_count: 89,
      deprecated_rule_count: 5,
      created_at: '2024-01-05T00:00:00Z',
      updated_at: '2024-01-15T00:00:00Z',
      rules: [
        { id: '4', rule_id: 'S5146', name: 'HTTP request redirections should not be open to forging attacks', severity: 'critical', category: 'Vulnerability', enabled: true, effort: '30min' },
        { id: '5', rule_id: 'S5144', name: 'Server-side requests should not be able to access arbitrary network systems', severity: 'critical', category: 'Vulnerability', enabled: true, effort: '1h' }
      ]
    },
    {
      id: '3',
      name: 'Python Best Practices',
      description: 'Profile optimized for Python development with PEP 8 compliance',
      language: 'python',
      is_default: false,
      active_rule_count: 78,
      deprecated_rule_count: 3,
      created_at: '2024-01-10T00:00:00Z',
      updated_at: '2024-01-15T00:00:00Z',
      rules: [
        { id: '6', rule_id: 'S101', name: 'Class names should comply with a naming convention', severity: 'minor', category: 'Code Smell', enabled: true, effort: '5min' },
        { id: '7', rule_id: 'S106', name: 'Standard output should not be used directly to log anything', severity: 'major', category: 'Code Smell', enabled: true, effort: '10min' }
      ]
    },
    {
      id: '4',
      name: 'JavaScript ES6+',
      description: 'Modern JavaScript profile with ES6+ and security rules',
      language: 'javascript',
      is_default: false,
      active_rule_count: 92,
      deprecated_rule_count: 8,
      created_at: '2024-01-12T00:00:00Z',
      updated_at: '2024-01-15T00:00:00Z',
      rules: [
        { id: '8', rule_id: 'S1488', name: 'Local variables should not be declared and then immediately returned', severity: 'minor', category: 'Code Smell', enabled: true, effort: '5min' },
        { id: '9', rule_id: 'S1172', name: 'Unused function parameters should be removed', severity: 'major', category: 'Code Smell', enabled: true, effort: '5min' }
      ]
    }
  ];

  const filterProfiles = () => {
    let filtered = [...profiles];

    if (searchTerm) {
      filtered = filtered.filter(profile =>
        profile.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        profile.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (selectedLanguage !== 'all') {
      filtered = filtered.filter(profile => profile.language === selectedLanguage);
    }

    setFilteredProfiles(filtered);
  };

  const handleCreateProfile = async (profileData: Partial<QualityProfile>) => {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        setError('Authentication token not found');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/sast/quality-profiles`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: profileData.name,
          description: profileData.description,
          language: profileData.language
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data && data.profile) {
        setProfiles(prev => [
          { ...data.profile, rules: [] } as QualityProfile,
          ...prev
        ]);
      }
      setShowCreateModal(false);
      setError(null);
    } catch (error) {
      console.error('Error creating profile:', error);
      setError('Failed to create profile');
    }
  };

  const handleDuplicateProfile = async (profile: QualityProfile, newName: string) => {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        setError('Authentication token not found');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/sast/quality-profiles/${profile.id}/duplicate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name: newName, language: profile.language })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data && data.profile) {
        setProfiles(prev => [
          { ...data.profile, rules: [] } as QualityProfile,
          ...prev
        ]);
      }
      setShowDuplicateModal(false);
      setSelectedProfile(null);
      setError(null);
    } catch (error) {
      console.error('Error duplicating profile:', error);
      setError('Failed to duplicate profile');
    }
  };

  const handleDeleteProfile = async (profileId: string) => {
    if (!window.confirm('Are you sure you want to delete this profile? This action cannot be undone.')) {
      return;
    }

    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        setError('Authentication token not found');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/sast/quality-profiles/${profileId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      setProfiles(prev => prev.filter(p => p.id !== profileId));
      setError(null);
    } catch (error) {
      console.error('Error deleting profile:', error);
      setError('Failed to delete profile');
    }
  };

  const handleSetDefault = async (profileId: string) => {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        setError('Authentication token not found');
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/sast/quality-profiles/${profileId}/set-default`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      setProfiles(prev => prev.map(p => ({
        ...p,
        is_default: p.id === profileId
      })));
      setError(null);
    } catch (error) {
      console.error('Error setting default profile:', error);
      setError('Failed to set default profile');
    }
  };

  const getLanguageColor = (language: string) => {
    switch (language.toLowerCase()) {
      case 'java':
        return 'text-orange-700 bg-orange-100';
      case 'python':
        return 'text-blue-700 bg-blue-100';
      case 'javascript':
        return 'text-yellow-700 bg-yellow-100';
      case 'typescript':
        return 'text-blue-600 bg-blue-100';
      case 'csharp':
        return 'text-purple-700 bg-purple-100';
      case 'php':
        return 'text-indigo-700 bg-indigo-100';
      default:
        return 'text-gray-700 bg-gray-100';
    }
  };

  const getLanguageIcon = (language: string) => {
    switch (language.toLowerCase()) {
      case 'java':
        return '☕';
      case 'python':
        return '🐍';
      case 'javascript':
        return 'JS';
      case 'typescript':
        return 'TS';
      case 'csharp':
        return 'C#';
      case 'php':
        return 'PHP';
      default:
        return '📝';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Quality Profiles</h2>
          <p className="text-gray-600">Manage and configure SAST quality profiles</p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={fetchProfiles}
            className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <Plus className="w-4 h-4 mr-2" />
            Create Profile
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search profiles..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <select
              value={selectedLanguage}
              onChange={(e) => setSelectedLanguage(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Languages</option>
              <option value="java">Java</option>
              <option value="python">Python</option>
              <option value="javascript">JavaScript</option>
              <option value="typescript">TypeScript</option>
              <option value="csharp">C#</option>
              <option value="php">PHP</option>
            </select>
          </div>
        </div>
      </div>

      {/* Profiles List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-medium text-gray-900">
              Profiles ({filteredProfiles.length})
            </h3>
            <div className="text-sm text-gray-500">
              {profiles.filter(p => p.is_default).length} default profile(s)
            </div>
          </div>
        </div>
        
        <div className="divide-y divide-gray-200">
          {filteredProfiles.map((profile) => (
            <div key={profile.id} className="p-6 hover:bg-gray-50">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h4 className="text-lg font-medium text-gray-900">{profile.name}</h4>
                    {profile.is_default && (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        Default
                      </span>
                    )}
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getLanguageColor(profile.language)}`}>
                      {getLanguageIcon(profile.language)} {profile.language}
                    </span>
                  </div>
                  
                  <p className="text-gray-600 mb-3">{profile.description}</p>
                  
                  <div className="flex items-center space-x-6 text-sm text-gray-500">
                    <div className="flex items-center space-x-1">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>{profile.active_rule_count} active rules</span>
                    </div>
                    {profile.deprecated_rule_count > 0 && (
                      <div className="flex items-center space-x-1">
                        <AlertTriangle className="w-4 h-4 text-yellow-500" />
                        <span>{profile.deprecated_rule_count} deprecated rules</span>
                      </div>
                    )}
                    <div className="flex items-center space-x-1">
                      <Clock className="w-4 h-4" />
                      <span>Updated {new Date(profile.updated_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2 ml-4">
                  {!profile.is_default && (
                    <button
                      onClick={() => handleSetDefault(profile.id)}
                      className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    >
                      <CheckCircle className="w-4 h-4 mr-2" />
                      Set Default
                    </button>
                  )}
                  
                  <button
                    onClick={() => {
                      setSelectedProfile(profile);
                      setShowDuplicateModal(true);
                    }}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                  >
                    <Copy className="w-4 h-4 mr-2" />
                    Duplicate
                  </button>
                  
                  <button
                    onClick={() => {
                      setEditingProfile(profile);
                      setShowEditModal(true);
                    }}
                    className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                  >
                    <Edit className="w-4 h-4 mr-2" />
                    Edit
                  </button>
                  
                  {!profile.is_default && (
                    <button
                      onClick={() => handleDeleteProfile(profile.id)}
                      className="inline-flex items-center px-3 py-2 border border-red-300 shadow-sm text-sm leading-4 font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                    >
                      <Trash2 className="w-4 h-4 mr-2" />
                      Delete
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
        
        {filteredProfiles.length === 0 && (
          <div className="p-8 text-center">
            <Shield className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No profiles found</h3>
            <p className="mt-1 text-sm text-gray-500">
              Try adjusting your search criteria or create a new profile.
            </p>
          </div>
        )}
      </div>

      {/* Create Profile Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Create New Quality Profile</h3>
              <form onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                handleCreateProfile({
                  name: formData.get('name') as string,
                  description: formData.get('description') as string,
                  language: formData.get('language') as string
                });
              }} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Profile Name</label>
                  <input
                    type="text"
                    name="name"
                    required
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter profile name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Description</label>
                  <textarea
                    name="description"
                    rows={3}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter profile description"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Programming Language</label>
                  <select 
                    name="language"
                    required
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">Select language</option>
                    <option value="java">Java</option>
                    <option value="python">Python</option>
                    <option value="javascript">JavaScript</option>
                    <option value="typescript">TypeScript</option>
                    <option value="csharp">C#</option>
                    <option value="php">PHP</option>
                  </select>
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Create Profile
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Duplicate Profile Modal */}
      {showDuplicateModal && selectedProfile && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Duplicate Profile</h3>
              <p className="text-sm text-gray-600 mb-4">
                Create a copy of "{selectedProfile.name}" with its rules and configuration.
              </p>
              <form onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                handleDuplicateProfile(selectedProfile, formData.get('name') as string);
              }} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Profile Name</label>
                  <input
                    type="text"
                    name="name"
                    required
                    defaultValue={`${selectedProfile.name} - Copy`}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowDuplicateModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Duplicate Profile
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default QualityProfiles;
