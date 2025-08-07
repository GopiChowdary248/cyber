import React, { useState, useEffect } from 'react';
import './SASTProjects.css';

interface SASTProject {
  id: string;
  name: string;
  repository_url: string;
  language: string;
  description: string;
  created_at: string;
  updated_at: string;
  last_scan?: {
    status: string;
    vulnerabilities_found: number;
    completed_at: string;
  };
}

const SASTProjects: React.FC = () => {
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalVisible, setModalVisible] = useState(false);
  const [newProject, setNewProject] = useState({
    name: '',
    repository_url: '',
    language: 'java',
    description: ''
  });

  const languages = [
    { value: 'java', label: 'Java' },
    { value: 'python', label: 'Python' },
    { value: 'javascript', label: 'JavaScript' },
    { value: 'php', label: 'PHP' },
    { value: 'go', label: 'Go' },
    { value: 'ruby', label: 'Ruby' },
    { value: 'csharp', label: 'C#' },
    { value: 'cpp', label: 'C++' }
  ];

  const fetchProjects = async () => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_URL}/api/v1/sast/projects`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setProjects(data.projects || []);
      } else {
        alert('Failed to fetch projects');
      }
    } catch (error) {
      console.error('Error fetching projects:', error);
      alert('Network error occurred');
    } finally {
      setLoading(false);
    }
  };

  const createProject = async () => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_URL}/api/v1/sast/projects`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newProject),
      });

      if (response.ok) {
        setModalVisible(false);
        setNewProject({ name: '', repository_url: '', language: 'java', description: '' });
        fetchProjects();
        alert('Project created successfully');
      } else {
        alert('Failed to create project');
      }
    } catch (error) {
      console.error('Error creating project:', error);
      alert('Network error occurred');
    }
  };

  const startScan = async (projectId: string) => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_URL}/api/v1/sast/projects/${projectId}/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || ''}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scan_type: 'static',
          scan_config: {}
        }),
      });

      if (response.ok) {
        alert('Scan started successfully');
        fetchProjects();
      } else {
        alert('Failed to start scan');
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      alert('Network error occurred');
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return '#28a745';
      case 'running':
        return '#ffc107';
      case 'failed':
        return '#dc3545';
      default:
        return '#6c757d';
    }
  };

  const getLanguageIcon = (language: string) => {
    const icons: { [key: string]: string } = {
      java: 'fab fa-java',
      python: 'fab fa-python',
      javascript: 'fab fa-js-square',
      php: 'fab fa-php',
      go: 'fas fa-code',
      ruby: 'fas fa-gem',
      csharp: 'fas fa-code',
      cpp: 'fas fa-code'
    };
    return icons[language] || 'fas fa-code';
  };

  if (loading) {
    return (
      <div className="sast-projects loading">
        <div className="loading-spinner">
          <i className="fas fa-spinner fa-spin"></i>
          <p>Loading projects...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="sast-projects">
      <div className="projects-header">
        <h1 className="header-title">SAST Projects</h1>
        <button className="add-button" onClick={() => setModalVisible(true)}>
          <i className="fas fa-plus"></i>
          New Project
        </button>
      </div>

      <div className="projects-grid">
        {projects.map((project) => (
          <div key={project.id} className="project-card">
            <div className="project-header">
              <div className="project-icon">
                <i className={getLanguageIcon(project.language)}></i>
              </div>
              <div className="project-info">
                <h3 className="project-name">{project.name}</h3>
                <p className="project-language">{project.language.toUpperCase()}</p>
              </div>
              <div className="project-actions">
                <button 
                  className="action-btn scan-btn"
                  onClick={() => startScan(project.id)}
                  title="Start Scan"
                >
                  <i className="fas fa-play"></i>
                </button>
                <button 
                  className="action-btn view-btn"
                  title="View Details"
                >
                  <i className="fas fa-eye"></i>
                </button>
              </div>
            </div>

            <div className="project-details">
              <p className="project-description">{project.description}</p>
              <p className="project-url">
                <i className="fas fa-link"></i>
                {project.repository_url}
              </p>
            </div>

            {project.last_scan && (
              <div className="last-scan">
                <h4>Last Scan</h4>
                <div className="scan-info">
                  <span className={`scan-status ${project.last_scan.status}`}>
                    {project.last_scan.status}
                  </span>
                  <span className="scan-vulns">
                    {project.last_scan.vulnerabilities_found} vulnerabilities found
                  </span>
                  <span className="scan-date">
                    {new Date(project.last_scan.completed_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            )}

            <div className="project-footer">
              <span className="created-date">
                Created: {new Date(project.created_at).toLocaleDateString()}
              </span>
              <span className="updated-date">
                Updated: {new Date(project.updated_at).toLocaleDateString()}
              </span>
            </div>
          </div>
        ))}
      </div>

      {projects.length === 0 && (
        <div className="empty-state">
          <i className="fas fa-folder-open"></i>
          <h3>No projects found</h3>
          <p>Create your first SAST project to start scanning for vulnerabilities</p>
          <button className="create-first-btn" onClick={() => setModalVisible(true)}>
            Create First Project
          </button>
        </div>
      )}

      {/* Create Project Modal */}
      {modalVisible && (
        <div className="modal-overlay" onClick={() => setModalVisible(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Create New SAST Project</h2>
              <button 
                className="close-button"
                onClick={() => setModalVisible(false)}
              >
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              <div className="form-group">
                <label htmlFor="project-name">Project Name</label>
                <input
                  type="text"
                  id="project-name"
                  value={newProject.name}
                  onChange={(e) => setNewProject({ ...newProject, name: e.target.value })}
                  placeholder="Enter project name"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="repository-url">Repository URL</label>
                <input
                  type="url"
                  id="repository-url"
                  value={newProject.repository_url}
                  onChange={(e) => setNewProject({ ...newProject, repository_url: e.target.value })}
                  placeholder="https://github.com/user/repo"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="language">Primary Language</label>
                <select
                  id="language"
                  value={newProject.language}
                  onChange={(e) => setNewProject({ ...newProject, language: e.target.value })}
                >
                  {languages.map((lang) => (
                    <option key={lang.value} value={lang.value}>
                      {lang.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="description">Description</label>
                <textarea
                  id="description"
                  value={newProject.description}
                  onChange={(e) => setNewProject({ ...newProject, description: e.target.value })}
                  placeholder="Enter project description"
                  rows={3}
                />
              </div>
            </div>

            <div className="modal-footer">
              <button 
                className="cancel-button"
                onClick={() => setModalVisible(false)}
              >
                Cancel
              </button>
              <button 
                className="create-button"
                onClick={createProject}
                disabled={!newProject.name || !newProject.repository_url}
              >
                Create Project
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SASTProjects; 