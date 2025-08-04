import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  Alert,
  Dimensions,
} from 'react-native';
import {
  Card,
  Title,
  Paragraph,
  Button,
  Chip,
  Avatar,
  Searchbar,
  FAB,
  Portal,
  Modal,
  TextInput,
  List,
  Divider,
  Menu,
  IconButton,
  ActivityIndicator,
} from 'react-native-paper';
import { LinearGradient } from 'react-native-linear-gradient';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { APIService, IAMUser } from '../../services/APIService';

const { width } = Dimensions.get('window');

interface UserManagementScreenProps {
  navigation: any;
}

const UserManagementScreen: React.FC<UserManagementScreenProps> = ({ navigation }) => {
  const [users, setUsers] = useState<IAMUser[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<IAMUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRole, setSelectedRole] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [visible, setVisible] = useState(false);
  const [menuVisible, setMenuVisible] = useState<number | null>(null);
  const [totalUsers, setTotalUsers] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);

  const roles = ['admin', 'analyst', 'user'];
  const statuses = ['active', 'inactive', 'locked'];

  useEffect(() => {
    loadUsers();
  }, []);

  useEffect(() => {
    filterUsers();
  }, [users, searchQuery, selectedRole, selectedStatus]);

  const loadUsers = async (page = 1, append = false) => {
    try {
      setLoading(true);
      const response = await APIService.getIAMUsers(20, searchQuery);
      
      if (append) {
        setUsers(prev => [...prev, ...response.users]);
      } else {
        setUsers(response.users);
      }
      
      setTotalUsers(response.total);
      setHasMore(response.users.length === 20);
      setCurrentPage(page);
    } catch (error) {
      console.error('Failed to load users:', error);
      Alert.alert('Error', 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadUsers(1, false);
    setRefreshing(false);
  };

  const filterUsers = () => {
    let filtered = users;

    if (searchQuery) {
      filtered = filtered.filter(user =>
        user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
        user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
        user.full_name?.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    if (selectedRole) {
      filtered = filtered.filter(user => user.role === selectedRole);
    }

    if (selectedStatus) {
      filtered = filtered.filter(user => {
        if (selectedStatus === 'active') return user.is_active;
        if (selectedStatus === 'inactive') return !user.is_active;
        if (selectedStatus === 'locked') return user.status === 'locked';
        return true;
      });
    }

    setFilteredUsers(filtered);
  };

  const handleCreateUser = () => {
    navigation.navigate('CreateUser');
  };

  const handleEditUser = (userId: number) => {
    navigation.navigate('EditUser', { userId });
  };

  const handleViewUser = (userId: number) => {
    navigation.navigate('UserDetails', { userId });
  };

  const handleToggleUserStatus = async (userId: number, currentStatus: boolean) => {
    try {
      if (currentStatus) {
        await APIService.post(`/iam/users/${userId}/lock`);
        Alert.alert('Success', 'User locked successfully');
      } else {
        await APIService.post(`/iam/users/${userId}/unlock`);
        Alert.alert('Success', 'User unlocked successfully');
      }
      loadUsers(currentPage, false);
    } catch (error) {
      Alert.alert('Error', 'Failed to update user status');
    }
  };

  const handleDeleteUser = async (userId: number) => {
    Alert.alert(
      'Confirm Delete',
      'Are you sure you want to delete this user? This action cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await APIService.delete(`/iam/users/${userId}`);
              Alert.alert('Success', 'User deleted successfully');
              loadUsers(currentPage, false);
            } catch (error) {
              Alert.alert('Error', 'Failed to delete user');
            }
          },
        },
      ]
    );
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return '#F44336';
      case 'analyst': return '#FF9800';
      case 'user': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  const getStatusColor = (user: IAMUser) => {
    if (user.status === 'locked') return '#F44336';
    return user.is_active ? '#4CAF50' : '#9E9E9E';
  };

  const renderUserCard = (user: IAMUser) => (
    <Card key={user.id} style={styles.userCard}>
      <Card.Content>
        <View style={styles.userHeader}>
          <Avatar.Text size={50} label={user.username.charAt(0).toUpperCase()} />
          <View style={styles.userInfo}>
            <Text style={styles.userName}>{user.full_name || user.username}</Text>
            <Text style={styles.userEmail}>{user.email}</Text>
            <Text style={styles.userDepartment}>{user.department || 'No Department'}</Text>
          </View>
          <Menu
            visible={menuVisible === user.id}
            onDismiss={() => setMenuVisible(null)}
            anchor={
              <IconButton
                icon="dots-vertical"
                onPress={() => setMenuVisible(user.id)}
              />
            }
          >
            <Menu.Item
              onPress={() => {
                setMenuVisible(null);
                handleViewUser(user.id);
              }}
              title="View Details"
              leadingIcon="eye"
            />
            <Menu.Item
              onPress={() => {
                setMenuVisible(null);
                handleEditUser(user.id);
              }}
              title="Edit User"
              leadingIcon="pencil"
            />
            <Menu.Item
              onPress={() => {
                setMenuVisible(null);
                handleToggleUserStatus(user.id, user.is_active);
              }}
              title={user.is_active ? 'Lock User' : 'Unlock User'}
              leadingIcon={user.is_active ? 'lock' : 'lock-open'}
            />
            <Menu.Item
              onPress={() => {
                setMenuVisible(null);
                handleDeleteUser(user.id);
              }}
              title="Delete User"
              leadingIcon="delete"
            />
          </Menu>
        </View>

        <View style={styles.userBadges}>
          <Chip
            mode="outlined"
            compact
            style={[styles.roleChip, { backgroundColor: getRoleColor(user.role) }]}
          >
            {user.role}
          </Chip>
          {user.mfa_enabled && (
            <Chip mode="outlined" compact icon="two-factor-authentication">
              MFA
            </Chip>
          )}
          <Chip
            mode="outlined"
            compact
            icon={user.is_active ? 'check-circle' : 'close-circle'}
            style={{ borderColor: getStatusColor(user) }}
          >
            {user.status === 'locked' ? 'Locked' : user.is_active ? 'Active' : 'Inactive'}
          </Chip>
        </View>

        <View style={styles.userDetails}>
          <Text style={styles.lastLogin}>
            Last login: {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
          </Text>
          <Text style={styles.createdAt}>
            Created: {new Date(user.created_at).toLocaleDateString()}
          </Text>
        </View>
      </Card.Content>
    </Card>
  );

  const renderFilters = () => (
    <Card style={styles.filtersCard}>
      <Card.Content>
        <Title>Filters</Title>
        
        <View style={styles.filterRow}>
          <Text style={styles.filterLabel}>Role:</Text>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            <Chip
              mode={selectedRole === '' ? 'flat' : 'outlined'}
              onPress={() => setSelectedRole('')}
              style={styles.filterChip}
            >
              All
            </Chip>
            {roles.map(role => (
              <Chip
                key={role}
                mode={selectedRole === role ? 'flat' : 'outlined'}
                onPress={() => setSelectedRole(selectedRole === role ? '' : role)}
                style={styles.filterChip}
              >
                {role}
              </Chip>
            ))}
          </ScrollView>
        </View>

        <View style={styles.filterRow}>
          <Text style={styles.filterLabel}>Status:</Text>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            <Chip
              mode={selectedStatus === '' ? 'flat' : 'outlined'}
              onPress={() => setSelectedStatus('')}
              style={styles.filterChip}
            >
              All
            </Chip>
            {statuses.map(status => (
              <Chip
                key={status}
                mode={selectedStatus === status ? 'flat' : 'outlined'}
                onPress={() => setSelectedStatus(selectedStatus === status ? '' : status)}
                style={styles.filterChip}
              >
                {status}
              </Chip>
            ))}
          </ScrollView>
        </View>
      </Card.Content>
    </Card>
  );

  return (
    <View style={styles.container}>
      {/* Header */}
      <LinearGradient colors={['#1e3c72', '#2a5298']} style={styles.header}>
        <View style={styles.headerContent}>
          <Icon name="account-group" size={32} color="white" />
          <Text style={styles.headerTitle}>User Management</Text>
        </View>
      </LinearGradient>

      {/* Search Bar */}
      <View style={styles.searchContainer}>
        <Searchbar
          placeholder="Search users..."
          onChangeText={setSearchQuery}
          value={searchQuery}
          style={styles.searchBar}
        />
      </View>

      {/* Filters */}
      {renderFilters()}

      {/* User List */}
      <ScrollView
        style={styles.content}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        <View style={styles.statsRow}>
          <Text style={styles.statsText}>
            Showing {filteredUsers.length} of {totalUsers} users
          </Text>
        </View>

        {loading && !refreshing ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color="#2196F3" />
            <Text style={styles.loadingText}>Loading users...</Text>
          </View>
        ) : filteredUsers.length === 0 ? (
          <Card style={styles.emptyCard}>
            <Card.Content>
              <Icon name="account-off" size={64} color="#ccc" style={styles.emptyIcon} />
              <Text style={styles.emptyText}>No users found</Text>
              <Text style={styles.emptySubtext}>
                Try adjusting your search or filter criteria
              </Text>
            </Card.Content>
          </Card>
        ) : (
          filteredUsers.map(renderUserCard)
        )}

        {hasMore && !loading && (
          <Button
            mode="outlined"
            onPress={() => loadUsers(currentPage + 1, true)}
            style={styles.loadMoreButton}
          >
            Load More Users
          </Button>
        )}
      </ScrollView>

      {/* FAB */}
      <FAB
        style={styles.fab}
        icon="plus"
        onPress={handleCreateUser}
        label="Add User"
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    paddingTop: 50,
    paddingBottom: 20,
    paddingHorizontal: 20,
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  headerTitle: {
    color: 'white',
    fontSize: 20,
    fontWeight: 'bold',
    marginLeft: 10,
  },
  searchContainer: {
    padding: 15,
    backgroundColor: 'white',
  },
  searchBar: {
    elevation: 2,
  },
  filtersCard: {
    marginHorizontal: 15,
    marginBottom: 15,
  },
  filterRow: {
    marginVertical: 10,
  },
  filterLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  filterChip: {
    marginRight: 8,
  },
  content: {
    flex: 1,
  },
  statsRow: {
    paddingHorizontal: 15,
    paddingVertical: 10,
  },
  statsText: {
    fontSize: 14,
    color: '#666',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingVertical: 50,
  },
  loadingText: {
    marginTop: 10,
    fontSize: 16,
    color: '#666',
  },
  emptyCard: {
    margin: 15,
  },
  emptyIcon: {
    alignSelf: 'center',
    marginBottom: 10,
  },
  emptyText: {
    textAlign: 'center',
    fontSize: 18,
    fontWeight: 'bold',
    color: '#666',
  },
  emptySubtext: {
    textAlign: 'center',
    fontSize: 14,
    color: '#999',
    marginTop: 5,
  },
  userCard: {
    marginHorizontal: 15,
    marginBottom: 10,
  },
  userHeader: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  userInfo: {
    marginLeft: 15,
    flex: 1,
  },
  userName: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  userEmail: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  userDepartment: {
    fontSize: 12,
    color: '#999',
    marginTop: 2,
  },
  userBadges: {
    flexDirection: 'row',
    marginTop: 10,
    flexWrap: 'wrap',
  },
  roleChip: {
    marginRight: 5,
    marginBottom: 5,
  },
  userDetails: {
    marginTop: 10,
  },
  lastLogin: {
    fontSize: 12,
    color: '#666',
  },
  createdAt: {
    fontSize: 12,
    color: '#999',
    marginTop: 2,
  },
  loadMoreButton: {
    margin: 15,
  },
  fab: {
    position: 'absolute',
    margin: 16,
    right: 0,
    bottom: 0,
  },
});

export default UserManagementScreen; 