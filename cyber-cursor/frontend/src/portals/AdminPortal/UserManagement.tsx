import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface User {
  id: number;
  email: string;
  username: string;
  full_name: string;
  role: string;
  is_active: boolean;
  is_verified: boolean;
  department: string;
  last_login: string;
  created_at: string;
}

const UserManagement: React.FC = () => {
  const { user } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showUserModal, setShowUserModal] = useState(false);
  const [filterRole, setFilterRole] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/admin/users`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch users');
      }

      const data = await response.json();
      setUsers(data);
    } catch (err) {
      console.error('Error fetching users:', err);
      // Use mock data for development
      setUsers([
        {
          id: 1,
          email: 'admin@cybershield.local',
          username: 'admin',
          full_name: 'System Administrator',
          role: 'admin',
          is_active: true,
          is_verified: true,
          department: 'IT',
          last_login: '2024-01-15T10:30:00Z',
          created_at: '2024-01-01T00:00:00Z'
        },
        {
          id: 2,
          email: 'analyst@cybershield.local',
          username: 'analyst',
          full_name: 'Security Analyst',
          role: 'analyst',
          is_active: true,
          is_verified: true,
          department: 'Security',
          last_login: '2024-01-15T09:15:00Z',
          created_at: '2024-01-02T00:00:00Z'
        },
        {
          id: 3,
          email: 'user@cybershield.local',
          username: 'user',
          full_name: 'Regular User',
          role: 'user',
          is_active: true,
          is_verified: false,
          department: 'Marketing',
          last_login: '2024-01-14T16:45:00Z',
          created_at: '2024-01-03T00:00:00Z'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleApproveUser = async (userId: number) => {
    try {
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/admin/users/${userId}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        fetchUsers(); // Refresh the list
      }
    } catch (err) {
      console.error('Error approving user:', err);
    }
  };

  const handleSuspendUser = async (userId: number) => {
    try {
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/admin/users/${userId}/suspend`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ reason: 'Administrative action' }),
      });

      if (response.ok) {
        fetchUsers(); // Refresh the list
      }
    } catch (err) {
      console.error('Error suspending user:', err);
    }
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'text-red-400 bg-red-900/20';
      case 'analyst': return 'text-orange-400 bg-orange-900/20';
      case 'user': return 'text-blue-400 bg-blue-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getStatusColor = (isActive: boolean) => {
    return isActive 
      ? 'text-green-400 bg-green-900/20' 
      : 'text-red-400 bg-red-900/20';
  };

  const filteredUsers = users.filter(user => {
    if (filterRole && user.role !== filterRole) return false;
    if (filterStatus === 'active' && !user.is_active) return false;
    if (filterStatus === 'inactive' && user.is_active) return false;
    if (filterStatus === 'unverified' && user.is_verified) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-accent"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">User Management</h1>
          <p className="text-gray-400">Manage users, roles, and permissions</p>
        </div>
        <button className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-4 py-2 rounded-lg">
          Add New User
        </button>
      </div>

      {/* Filters */}
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Role</label>
            <select
              value={filterRole}
              onChange={(e) => setFilterRole(e.target.value)}
              className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            >
              <option value="">All Roles</option>
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="user">User</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Status</label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            >
              <option value="">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="unverified">Unverified</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => { setFilterRole(''); setFilterStatus(''); }}
              className="w-full bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-cyber-dark">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  User
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Role
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Department
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Last Login
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-accent/20">
              {filteredUsers.map((user) => (
                <tr key={user.id} className="hover:bg-cyber-dark/50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-8 h-8 bg-cyber-accent rounded-full flex items-center justify-center">
                        <span className="text-white text-sm font-semibold">
                          {user.username.charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-white">
                          {user.full_name}
                        </div>
                        <div className="text-sm text-gray-400">
                          {user.email}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRoleColor(user.role)}`}>
                      {user.role.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="space-y-1">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(user.is_active)}`}>
                        {user.is_active ? 'Active' : 'Inactive'}
                      </span>
                      {!user.is_verified && (
                        <span className="block px-2 py-1 rounded-full text-xs font-medium text-yellow-400 bg-yellow-900/20">
                          Unverified
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {user.department || 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {new Date(user.last_login).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      {!user.is_verified && (
                        <button
                          onClick={() => handleApproveUser(user.id)}
                          className="text-green-400 hover:text-green-300"
                        >
                          Approve
                        </button>
                      )}
                      {user.is_active && user.id !== 1 && (
                        <button
                          onClick={() => handleSuspendUser(user.id)}
                          className="text-red-400 hover:text-red-300"
                        >
                          Suspend
                        </button>
                      )}
                      <button
                        onClick={() => { setSelectedUser(user); setShowUserModal(true); }}
                        className="text-cyber-accent hover:text-cyber-accent/80"
                      >
                        Edit
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-white">{users.length}</div>
          <div className="text-gray-400">Total Users</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">
            {users.filter(u => u.is_active).length}
          </div>
          <div className="text-gray-400">Active Users</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-yellow-400">
            {users.filter(u => !u.is_verified).length}
          </div>
          <div className="text-gray-400">Pending Approval</div>
        </div>
        <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
          <div className="text-2xl font-bold text-red-400">
            {users.filter(u => !u.is_active).length}
          </div>
          <div className="text-gray-400">Suspended Users</div>
        </div>
      </div>
    </div>
  );
};

export default UserManagement; 