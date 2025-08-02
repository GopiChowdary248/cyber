import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  CloudArrowUpIcon, 
  DocumentIcon,
  XMarkIcon,
  PlayIcon,
  CogIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';

interface UploadedFile {
  name: string;
  size: number;
  type: string;
  file: File;
}

interface ScanConfig {
  tools_enabled: string[];
  severity_threshold: string;
  scan_type: string;
  include_patterns: string[];
  exclude_patterns: string[];
}

const SASTUpload: React.FC = () => {
  const navigate = useNavigate();
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [projectName, setProjectName] = useState('');
  const [projectDescription, setProjectDescription] = useState('');
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    tools_enabled: ['bandit', 'pylint', 'semgrep'],
    severity_threshold: 'low',
    scan_type: 'full',
    include_patterns: [],
    exclude_patterns: ['node_modules', '.git', '__pycache__']
  });
  const [uploading, setUploading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showHelpModal, setShowHelpModal] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFilePick = async () => {
    try {
      if (fileInputRef.current) {
        fileInputRef.current.click();
      }
    } catch (error) {
      console.error('Error picking file:', error);
      alert('Failed to pick file');
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      
      // Validate file size (max 100MB)
      if (file.size > 100 * 1024 * 1024) {
        alert('File size must be less than 100MB');
        return;
      }

      const uploadedFile: UploadedFile = {
        name: file.name,
        size: file.size,
        type: file.type,
        file: file
      };

      setUploadedFiles([uploadedFile]);
    }
  };

  const removeFile = (index: number) => {
    setUploadedFiles(uploadedFiles.filter((_, i) => i !== index));
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const validateForm = () => {
    if (!projectName.trim()) {
      alert('Please enter a project name');
      return false;
    }
    if (uploadedFiles.length === 0) {
      alert('Please select a file to upload');
      return false;
    }
    return true;
  };

  const uploadAndScan = async () => {
    if (!validateForm()) return;

    try {
      setUploading(true);
      setScanning(true);

      // Create form data
      const formData = new FormData();
      formData.append('file', uploadedFiles[0].file);
      formData.append('project_name', projectName);
      formData.append('project_description', projectDescription);
      formData.append('scan_config', JSON.stringify(scanConfig));

      // Upload and scan
      const response = await fetch('/api/v1/sast/scan/upload', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        alert('File uploaded and scan started successfully!');
        navigate(`/sast/scan/${data.id}`);
      } else {
        throw new Error('Upload failed');
      }
    } catch (error: any) {
      console.error('Error uploading and scanning:', error);
      alert('Failed to upload and scan file');
    } finally {
      setUploading(false);
      setScanning(false);
    }
  };

  const updateScanConfig = (key: keyof ScanConfig, value: any) => {
    setScanConfig(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const toggleTool = (tool: string) => {
    const currentTools = scanConfig.tools_enabled;
    const newTools = currentTools.includes(tool)
      ? currentTools.filter(t => t !== tool)
      : [...currentTools, tool];
    updateScanConfig('tools_enabled', newTools);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          {/* Header */}
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold text-gray-900">SAST Code Analysis</h1>
                <p className="text-sm text-gray-600 mt-1">
                  Upload your code for static analysis and vulnerability detection
                </p>
              </div>
              <button
                onClick={() => setShowHelpModal(true)}
                className="p-2 text-gray-400 hover:text-gray-600"
              >
                <InformationCircleIcon className="h-6 w-6" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="p-6">
            {/* Project Information */}
            <div className="mb-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Project Information</h2>
              <div className="grid grid-cols-1 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Project Name *
                  </label>
                  <input
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Enter project name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Description
                  </label>
                  <textarea
                    value={projectDescription}
                    onChange={(e) => setProjectDescription(e.target.value)}
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Enter project description"
                  />
                </div>
              </div>
            </div>

            {/* File Upload */}
            <div className="mb-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Upload Code</h2>
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
                <CloudArrowUpIcon className="mx-auto h-12 w-12 text-gray-400" />
                <div className="mt-4">
                  <button
                    onClick={handleFilePick}
                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                  >
                    <DocumentIcon className="h-5 w-5 mr-2" />
                    Select ZIP File
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".zip"
                    onChange={handleFileChange}
                    className="hidden"
                  />
                </div>
                <p className="mt-2 text-sm text-gray-600">
                  Upload a ZIP file containing your source code (max 100MB)
                </p>
              </div>

              {/* Uploaded Files */}
              {uploadedFiles.length > 0 && (
                <div className="mt-4">
                  {uploadedFiles.map((file, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-md">
                      <div className="flex items-center">
                        <DocumentIcon className="h-5 w-5 text-gray-400 mr-3" />
                        <div>
                          <p className="text-sm font-medium text-gray-900">{file.name}</p>
                          <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
                        </div>
                      </div>
                      <button
                        onClick={() => removeFile(index)}
                        className="p-1 text-gray-400 hover:text-gray-600"
                      >
                        <XMarkIcon className="h-5 w-5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Scan Configuration */}
            <div className="mb-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-gray-900">Scan Configuration</h2>
                <button
                  onClick={() => setShowConfigModal(true)}
                  className="inline-flex items-center px-3 py-1 border border-gray-300 rounded-md text-sm text-gray-700 hover:bg-gray-50"
                >
                  <CogIcon className="h-4 w-4 mr-1" />
                  Configure
                </button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-gray-50 rounded-md">
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Tools Enabled</h3>
                  <div className="space-y-2">
                    {scanConfig.tools_enabled.map(tool => (
                      <span key={tool} className="inline-block px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded">
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="p-4 bg-gray-50 rounded-md">
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Severity Threshold</h3>
                  <span className="inline-block px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded capitalize">
                    {scanConfig.severity_threshold}
                  </span>
                </div>
                <div className="p-4 bg-gray-50 rounded-md">
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Scan Type</h3>
                  <span className="inline-block px-2 py-1 text-xs bg-green-100 text-green-800 rounded capitalize">
                    {scanConfig.scan_type}
                  </span>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end space-x-4">
              <button
                onClick={() => navigate('/sast')}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={uploadAndScan}
                disabled={uploading || scanning}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
              >
                {uploading || scanning ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    {uploading ? 'Uploading...' : 'Scanning...'}
                  </>
                ) : (
                  <>
                    <PlayIcon className="h-4 w-4 mr-2" />
                    Upload & Scan
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SASTUpload; 