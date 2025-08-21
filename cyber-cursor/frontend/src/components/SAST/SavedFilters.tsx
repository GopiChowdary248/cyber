import React, { useState, useEffect } from 'react';
import { 
  BookmarkIcon, 
  PlusIcon, 
  PencilIcon, 
  TrashIcon,
  EyeIcon,
  StarIcon
} from '@heroicons/react/24/outline';
import { sastService } from '../../services/sastService';

interface SavedFilter {
  id: number;
  name: string;
  description?: string;
  filter_type: string;
  filter_criteria: any;
  project_id?: number;
  created_at?: string;
  updated_at?: string;
}

interface SavedFiltersProps {
  filterType: string;
  projectId?: number;
  currentFilters: any;
  onApplyFilter: (criteria: any) => void;
  onSaveCurrentFilter?: () => void;
}

const SavedFilters: React.FC<SavedFiltersProps> = ({
  filterType,
  projectId,
  currentFilters,
  onApplyFilter,
  onSaveCurrentFilter
}) => {
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingFilter, setEditingFilter] = useState<SavedFilter | null>(null);
  const [newFilterName, setNewFilterName] = useState('');
  const [newFilterDescription, setNewFilterDescription] = useState('');

  useEffect(() => {
    loadSavedFilters();
  }, [filterType, projectId]);

  const loadSavedFilters = async () => {
    try {
      setLoading(true);
      const response = await sastService.getSavedFilters(filterType, projectId);
      setSavedFilters(response.filters || []);
    } catch (error) {
      console.error('Failed to load saved filters:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveFilter = async () => {
    if (!newFilterName.trim()) return;

    try {
      await sastService.createSavedFilter({
        name: newFilterName.trim(),
        description: newFilterDescription.trim() || undefined,
        filter_type: filterType,
        filter_criteria: currentFilters,
        project_id: projectId
      });

      setNewFilterName('');
      setNewFilterDescription('');
      setShowCreateModal(false);
      loadSavedFilters();
    } catch (error) {
      console.error('Failed to save filter:', error);
    }
  };

  const handleUpdateFilter = async () => {
    if (!editingFilter || !newFilterName.trim()) return;

    try {
      await sastService.updateSavedFilter(editingFilter.id, {
        name: newFilterName.trim(),
        description: newFilterDescription.trim() || undefined,
        filter_criteria: currentFilters
      });

      setNewFilterName('');
      setNewFilterDescription('');
      setShowEditModal(false);
      setEditingFilter(null);
      loadSavedFilters();
    } catch (error) {
      console.error('Failed to update filter:', error);
    }
  };

  const handleDeleteFilter = async (filterId: number) => {
    if (!window.confirm('Are you sure you want to delete this filter?')) return;

    try {
      await sastService.deleteSavedFilter(filterId);
      loadSavedFilters();
    } catch (error) {
      console.error('Failed to delete filter:', error);
    }
  };

  const handleEditFilter = (filter: SavedFilter) => {
    setEditingFilter(filter);
    setNewFilterName(filter.name);
    setNewFilterDescription(filter.description || '');
    setShowEditModal(true);
  };

  const handleApplyFilter = (filter: SavedFilter) => {
    onApplyFilter(filter.filter_criteria);
  };

  const openCreateModal = () => {
    setNewFilterName('');
    setNewFilterDescription('');
    setShowCreateModal(true);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-4">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <BookmarkIcon className="w-5 h-5 text-blue-600" />
          <h3 className="text-sm font-medium text-gray-900">Saved Filters</h3>
          <span className="text-xs text-gray-500">({savedFilters.length})</span>
        </div>
        <button
          onClick={openCreateModal}
          className="inline-flex items-center px-2 py-1 border border-transparent text-xs font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200"
        >
          <PlusIcon className="w-3 h-3 mr-1" />
          Save Current
        </button>
      </div>

      {/* Filters List */}
      {savedFilters.length === 0 ? (
        <div className="text-center py-4 text-sm text-gray-500">
          No saved filters yet. Save your current filter configuration for quick access.
        </div>
      ) : (
        <div className="space-y-2">
          {savedFilters.map((filter) => (
            <div
              key={filter.id}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200 hover:border-gray-300 transition-colors"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center space-x-2">
                  <StarIcon className="w-4 h-4 text-yellow-500" />
                  <h4 className="text-sm font-medium text-gray-900 truncate">
                    {filter.name}
                  </h4>
                  {filter.project_id && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                      Project
                    </span>
                  )}
                </div>
                {filter.description && (
                  <p className="text-xs text-gray-600 mt-1 truncate">
                    {filter.description}
                  </p>
                )}
                <p className="text-xs text-gray-500 mt-1">
                  Created {filter.created_at ? new Date(filter.created_at).toLocaleDateString() : 'Unknown'}
                </p>
              </div>
              
              <div className="flex items-center space-x-1 ml-2">
                <button
                  onClick={() => handleApplyFilter(filter)}
                  className="p-1 text-blue-600 hover:text-blue-800 hover:bg-blue-50 rounded"
                  title="Apply filter"
                >
                  <EyeIcon className="w-4 h-4" />
                </button>
                <button
                  onClick={() => handleEditFilter(filter)}
                  className="p-1 text-gray-600 hover:text-gray-800 hover:bg-gray-50 rounded"
                  title="Edit filter"
                >
                  <PencilIcon className="w-4 h-4" />
                </button>
                <button
                  onClick={() => handleDeleteFilter(filter.id)}
                  className="p-1 text-red-600 hover:text-red-800 hover:bg-red-50 rounded"
                  title="Delete filter"
                >
                  <TrashIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Filter Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Save Current Filter</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Filter Name *
                  </label>
                  <input
                    type="text"
                    value={newFilterName}
                    onChange={(e) => setNewFilterName(e.target.value)}
                    placeholder="Enter filter name"
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Description (optional)
                  </label>
                  <textarea
                    value={newFilterDescription}
                    onChange={(e) => setNewFilterDescription(e.target.value)}
                    placeholder="Enter filter description"
                    rows={3}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSaveFilter}
                  disabled={!newFilterName.trim()}
                  className="px-4 py-2 bg-blue-600 border border-transparent rounded-md text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Save Filter
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Filter Modal */}
      {showEditModal && editingFilter && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Edit Filter</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Filter Name *
                  </label>
                  <input
                    type="text"
                    value={newFilterName}
                    onChange={(e) => setNewFilterName(e.target.value)}
                    placeholder="Enter filter name"
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Description (optional)
                  </label>
                  <textarea
                    value={newFilterDescription}
                    onChange={(e) => setNewFilterDescription(e.target.value)}
                    placeholder="Enter filter description"
                    rows={3}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => {
                    setShowEditModal(false);
                    setEditingFilter(null);
                  }}
                  className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleUpdateFilter}
                  disabled={!newFilterName.trim()}
                  className="px-4 py-2 bg-blue-600 border border-transparent rounded-md text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Update Filter
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SavedFilters;
