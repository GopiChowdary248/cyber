import React, { useState, useEffect } from 'react';
import './SASTVulnerabilities.css';

interface SASTVulnerability {
  id: string;
  title: string;
  description: string;
  severity: string;
  file_path: string;
  line_number: number;
  cwe_id: string;
  vulnerable_code: string;
  created_at: string;
  status: string;
  project_id: string;
  scan_id: string;
}

const SASTVulnerabilities: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<SASTVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterModalVisible, setFilterModalVisible] = useState(false);
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<SASTVulnerability | null>(null);
  const [filters, setFilters] = useState({
    severity: '',
    project_id: '',
    status: ''
  });

  const severities = [
    { value: '', label: 'All Severities' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' }
  ];

  const statuses = [
    { value: '', label: 'All Statuses' },
    { value: 'open', label: 'Open' },
    { value: 'in_progress', label: 'In Progress' },
    { value: 'resolved', label: 'Resolved' },
    { value: 'false_positive', label: 'False Positive' }
  ];

  const fetchVulnerabilities = async () => {
    try {
      const queryParams = new URLSearchParams();
      if (filters.severity) queryParams.append('severity', filters.severity);
      if (filters.project_id) queryParams.append('project_id', filters.project_id);
      if (filters.status) queryParams.append('status', filters.status);

      const response = await fetch(`http://localhost:8000/api/v1/sast/vulnerabilities?${queryParams}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setVulnerabilities(data.vulnerabilities || []);
      } else {
        alert('Failed to fetch vulnerabilities');
      }
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
      alert('Network error occurred');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVulnerabilities();
  }, [filters]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '#dc3545';
      case 'high':
        return '#fd7e14';
      case 'medium':
        return '#ffc107';
      case 'low':
        return '#28a745';
      default:
        return '#6c757d';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'fas fa-exclamation-triangle';
      case 'high':
        return 'fas fa-exclamation-circle';
      case 'medium':
        return 'fas fa-info-circle';
      case 'low':
        return 'fas fa-check-circle';
      default:
        return 'fas fa-info';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return '#dc3545';
      case 'in_progress':
        return '#ffc107';
      case 'resolved':
        return '#28a745';
      case 'false_positive':
        return '#6c757d';
      default:
        return '#6c757d';
    }
  };

  const openVulnerabilityDetail = (vulnerability: SASTVulnerability) => {
    setSelectedVulnerability(vulnerability);
    setDetailModalVisible(true);
  };

  const applyFilters = () => {
    setFilterModalVisible(false);
    fetchVulnerabilities();
  };

  const clearFilters = () => {
    setFilters({ severity: '', project_id: '', status: '' });
  };

  if (loading) {
    return (
      <div className="sast-vulnerabilities loading">
        <div className="loading-spinner">
          <i className="fas fa-spinner fa-spin"></i>
          <p>Loading vulnerabilities...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="sast-vulnerabilities">
      <div className="vulnerabilities-header">
        <h1 className="header-title">SAST Vulnerabilities</h1>
        <button className="filter-button" onClick={() => setFilterModalVisible(true)}>
          <i className="fas fa-filter"></i>
          Filter
        </button>
      </div>

      <div className="vulnerabilities-stats">
        <div className="stat-item">
          <span className="stat-label">Total</span>
          <span className="stat-value">{vulnerabilities.length}</span>
        </div>
        <div className="stat-item critical">
          <span className="stat-label">Critical</span>
          <span className="stat-value">
            {vulnerabilities.filter(v => v.severity === 'critical').length}
          </span>
        </div>
        <div className="stat-item high">
          <span className="stat-label">High</span>
          <span className="stat-value">
            {vulnerabilities.filter(v => v.severity === 'high').length}
          </span>
        </div>
        <div className="stat-item medium">
          <span className="stat-label">Medium</span>
          <span className="stat-value">
            {vulnerabilities.filter(v => v.severity === 'medium').length}
          </span>
        </div>
        <div className="stat-item low">
          <span className="stat-label">Low</span>
          <span className="stat-value">
            {vulnerabilities.filter(v => v.severity === 'low').length}
          </span>
        </div>
      </div>

      <div className="vulnerabilities-list">
        {vulnerabilities.map((vulnerability) => (
          <div key={vulnerability.id} className="vulnerability-card">
            <div className="vulnerability-header">
              <div className="severity-indicator" style={{ backgroundColor: getSeverityColor(vulnerability.severity) }}>
                <i className={getSeverityIcon(vulnerability.severity)}></i>
              </div>
              <div className="vulnerability-info">
                <h3 className="vulnerability-title">{vulnerability.title}</h3>
                <p className="vulnerability-file">
                  {vulnerability.file_path}:{vulnerability.line_number}
                </p>
              </div>
              <div className="vulnerability-meta">
                <span className={`severity-badge ${vulnerability.severity}`}>
                  {vulnerability.severity.toUpperCase()}
                </span>
                <span className={`status-badge ${vulnerability.status}`}>
                  {vulnerability.status.replace('_', ' ')}
                </span>
              </div>
            </div>

            <div className="vulnerability-content">
              <p className="vulnerability-description">{vulnerability.description}</p>
              <div className="vulnerability-details">
                <span className="detail-item">
                  <i className="fas fa-bug"></i>
                  CWE-{vulnerability.cwe_id}
                </span>
                <span className="detail-item">
                  <i className="fas fa-calendar"></i>
                  {new Date(vulnerability.created_at).toLocaleDateString()}
                </span>
              </div>
            </div>

            <div className="vulnerability-actions">
              <button 
                className="action-btn view-btn"
                onClick={() => openVulnerabilityDetail(vulnerability)}
              >
                <i className="fas fa-eye"></i>
                View Details
              </button>
              <button className="action-btn resolve-btn">
                <i className="fas fa-check"></i>
                Mark Resolved
              </button>
            </div>
          </div>
        ))}
      </div>

      {vulnerabilities.length === 0 && (
        <div className="empty-state">
          <i className="fas fa-shield-alt"></i>
          <h3>No vulnerabilities found</h3>
          <p>Great job! No security vulnerabilities detected in your projects.</p>
        </div>
      )}

      {/* Filter Modal */}
      {filterModalVisible && (
        <div className="modal-overlay" onClick={() => setFilterModalVisible(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Filter Vulnerabilities</h2>
              <button 
                className="close-button"
                onClick={() => setFilterModalVisible(false)}
              >
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              <div className="form-group">
                <label htmlFor="severity-filter">Severity</label>
                <select
                  id="severity-filter"
                  value={filters.severity}
                  onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                >
                  {severities.map((severity) => (
                    <option key={severity.value} value={severity.value}>
                      {severity.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="status-filter">Status</label>
                <select
                  id="status-filter"
                  value={filters.status}
                  onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                >
                  {statuses.map((status) => (
                    <option key={status.value} value={status.value}>
                      {status.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="project-filter">Project ID</label>
                <input
                  type="text"
                  id="project-filter"
                  value={filters.project_id}
                  onChange={(e) => setFilters({ ...filters, project_id: e.target.value })}
                  placeholder="Enter project ID"
                />
              </div>
            </div>

            <div className="modal-footer">
              <button className="clear-button" onClick={clearFilters}>
                Clear Filters
              </button>
              <button className="apply-button" onClick={applyFilters}>
                Apply Filters
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Detail Modal */}
      {detailModalVisible && selectedVulnerability && (
        <div className="modal-overlay" onClick={() => setDetailModalVisible(false)}>
          <div className="modal-content large" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Vulnerability Details</h2>
              <button 
                className="close-button"
                onClick={() => setDetailModalVisible(false)}
              >
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              <div className="detail-section">
                <h3>{selectedVulnerability.title}</h3>
                <div className="detail-meta">
                  <span className={`severity-badge ${selectedVulnerability.severity}`}>
                    {selectedVulnerability.severity.toUpperCase()}
                  </span>
                  <span className={`status-badge ${selectedVulnerability.status}`}>
                    {selectedVulnerability.status.replace('_', ' ')}
                  </span>
                </div>
              </div>

              <div className="detail-section">
                <h4>Description</h4>
                <p>{selectedVulnerability.description}</p>
              </div>

              <div className="detail-section">
                <h4>Location</h4>
                <p className="file-location">
                  <i className="fas fa-file-code"></i>
                  {selectedVulnerability.file_path}:{selectedVulnerability.line_number}
                </p>
              </div>

              <div className="detail-section">
                <h4>Vulnerable Code</h4>
                <pre className="code-snippet">
                  <code>{selectedVulnerability.vulnerable_code}</code>
                </pre>
              </div>

              <div className="detail-section">
                <h4>Additional Information</h4>
                <div className="info-grid">
                  <div className="info-item">
                    <span className="info-label">CWE ID:</span>
                    <span className="info-value">CWE-{selectedVulnerability.cwe_id}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Created:</span>
                    <span className="info-value">
                      {new Date(selectedVulnerability.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Project ID:</span>
                    <span className="info-value">{selectedVulnerability.project_id}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Scan ID:</span>
                    <span className="info-value">{selectedVulnerability.scan_id}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button className="secondary-button">
                <i className="fas fa-flag"></i>
                Report False Positive
              </button>
              <button className="primary-button">
                <i className="fas fa-check"></i>
                Mark as Resolved
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SASTVulnerabilities; 