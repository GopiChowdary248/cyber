import React, { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';

interface IncidentForm {
  title: string;
  description: string;
  incident_type: string;
  severity: string;
  location: string;
  affected_systems: string;
  evidence: File | null;
  contact_info: string;
}

const IncidentReporting: React.FC = () => {
  const { user } = useAuth();
  const [formData, setFormData] = useState<IncidentForm>({
    title: '',
    description: '',
    incident_type: '',
    severity: 'medium',
    location: '',
    affected_systems: '',
    evidence: null,
    contact_info: ''
  });
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(1);

  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  const incidentTypes = [
    { value: 'phishing', label: 'Phishing Attempt', icon: '🎣' },
    { value: 'malware', label: 'Malware Detection', icon: '🦠' },
    { value: 'unauthorized_access', label: 'Unauthorized Access', icon: '🚪' },
    { value: 'data_breach', label: 'Data Breach', icon: '💥' },
    { value: 'suspicious_activity', label: 'Suspicious Activity', icon: '👁️' },
    { value: 'system_compromise', label: 'System Compromise', icon: '💻' },
    { value: 'social_engineering', label: 'Social Engineering', icon: '🎭' },
    { value: 'other', label: 'Other', icon: '❓' }
  ];

  const severityLevels = [
    { value: 'low', label: 'Low', color: 'text-green-400', bg: 'bg-green-900/20' },
    { value: 'medium', label: 'Medium', color: 'text-yellow-400', bg: 'bg-yellow-900/20' },
    { value: 'high', label: 'High', color: 'text-orange-400', bg: 'bg-orange-900/20' },
    { value: 'critical', label: 'Critical', color: 'text-red-400', bg: 'bg-red-900/20' }
  ];

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setFormData(prev => ({ ...prev, evidence: file }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const token = localStorage.getItem('access_token');
      const formDataToSend = new FormData();
      
      Object.entries(formData).forEach(([key, value]) => {
        if (value !== null) {
          formDataToSend.append(key, value);
        }
      });

      const response = await fetch(`${API_URL}/api/v1/user/incidents`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formDataToSend,
      });

      if (response.ok) {
        // Success - move to confirmation step
        setStep(3);
      } else {
        throw new Error('Failed to submit incident');
      }
    } catch (error) {
      console.error('Error submitting incident:', error);
    } finally {
      setLoading(false);
    }
  };

  const nextStep = () => setStep(step + 1);
  const prevStep = () => setStep(step - 1);

  const renderStep1 = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-white mb-4">Step 1: Incident Details</h3>
        <p className="text-gray-400 mb-6">Please provide basic information about the security incident.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2">
            Incident Title *
          </label>
          <input
            type="text"
            name="title"
            value={formData.title}
            onChange={handleInputChange}
            className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            placeholder="Brief description of the incident"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2">
            Incident Type *
          </label>
          <select
            name="incident_type"
            value={formData.incident_type}
            onChange={handleInputChange}
            className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            required
          >
            <option value="">Select incident type</option>
            {incidentTypes.map(type => (
              <option key={type.value} value={type.value}>
                {type.icon} {type.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2">
            Severity Level *
          </label>
          <select
            name="severity"
            value={formData.severity}
            onChange={handleInputChange}
            className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            required
          >
            {severityLevels.map(level => (
              <option key={level.value} value={level.value}>
                {level.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2">
            Location
          </label>
          <input
            type="text"
            name="location"
            value={formData.location}
            onChange={handleInputChange}
            className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
            placeholder="Where did this occur?"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Detailed Description *
        </label>
        <textarea
          name="description"
          value={formData.description}
          onChange={handleInputChange}
          rows={4}
          className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
          placeholder="Provide a detailed description of what happened, when it occurred, and any relevant details..."
          required
        />
      </div>

      <div className="flex justify-end">
        <button
          onClick={nextStep}
          disabled={!formData.title || !formData.incident_type || !formData.description}
          className="bg-cyber-accent hover:bg-cyber-accent/80 disabled:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Next Step
        </button>
      </div>
    </div>
  );

  const renderStep2 = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-white mb-4">Step 2: Additional Information</h3>
        <p className="text-gray-400 mb-6">Provide additional details and evidence to help with the investigation.</p>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Affected Systems
        </label>
        <input
          type="text"
          name="affected_systems"
          value={formData.affected_systems}
          onChange={handleInputChange}
          className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
          placeholder="Which systems, applications, or data were affected?"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Contact Information
        </label>
        <input
          type="text"
          name="contact_info"
          value={formData.contact_info}
          onChange={handleInputChange}
          className="w-full bg-cyber-dark border border-cyber-accent/30 rounded-lg px-3 py-2 text-white"
          placeholder="Best way to contact you for follow-up questions"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Evidence Upload
        </label>
        <div className="border-2 border-dashed border-cyber-accent/30 rounded-lg p-6 text-center">
          <input
            type="file"
            onChange={handleFileChange}
            className="hidden"
            id="evidence-upload"
            accept=".pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif"
          />
          <label htmlFor="evidence-upload" className="cursor-pointer">
            <div className="text-cyber-accent text-4xl mb-2">📎</div>
            <p className="text-white mb-2">Click to upload evidence</p>
            <p className="text-gray-400 text-sm">
              Supported formats: PDF, DOC, TXT, JPG, PNG (Max 10MB)
            </p>
          </label>
          {formData.evidence && (
            <div className="mt-4 p-3 bg-cyber-dark rounded-lg">
              <p className="text-white text-sm">📄 {formData.evidence.name}</p>
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-between">
        <button
          onClick={prevStep}
          className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Previous
        </button>
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors"
        >
          {loading ? 'Submitting...' : 'Submit Incident'}
        </button>
      </div>
    </div>
  );

  const renderStep3 = () => (
    <div className="text-center space-y-6">
      <div className="text-green-400 text-6xl mb-4">✅</div>
      <h3 className="text-2xl font-bold text-white">Incident Submitted Successfully!</h3>
      <p className="text-gray-400 max-w-md mx-auto">
        Your security incident has been reported and is being reviewed by our security team. 
        You will receive updates on the status of your report.
      </p>
      
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6 max-w-md mx-auto">
        <h4 className="text-white font-semibold mb-4">What happens next?</h4>
        <div className="space-y-3 text-left">
          <div className="flex items-center space-x-3">
            <span className="text-cyber-accent">1</span>
            <span className="text-gray-300">Security team review</span>
          </div>
          <div className="flex items-center space-x-3">
            <span className="text-cyber-accent">2</span>
            <span className="text-gray-300">Investigation begins</span>
          </div>
          <div className="flex items-center space-x-3">
            <span className="text-cyber-accent">3</span>
            <span className="text-gray-300">Status updates sent</span>
          </div>
          <div className="flex items-center space-x-3">
            <span className="text-cyber-accent">4</span>
            <span className="text-gray-300">Resolution and closure</span>
          </div>
        </div>
      </div>

      <div className="space-x-4">
        <button
          onClick={() => window.location.href = '/user'}
          className="bg-cyber-accent hover:bg-cyber-accent/80 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Return to Dashboard
        </button>
        <button
          onClick={() => { setStep(1); setFormData({ title: '', description: '', incident_type: '', severity: 'medium', location: '', affected_systems: '', evidence: null, contact_info: '' }); }}
          className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Report Another Incident
        </button>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-red-900/20 to-orange-900/20 border border-cyber-accent/30 rounded-lg p-6">
        <h1 className="text-3xl font-bold text-white mb-2">🚨 Report Security Incident</h1>
        <p className="text-gray-400">
          Report suspicious activities, security breaches, or any cybersecurity concerns.
        </p>
      </div>

      {/* Progress Indicator */}
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ${
              step >= 1 ? 'bg-cyber-accent text-cyber-dark' : 'bg-gray-600 text-gray-300'
            }`}>
              1
            </div>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ${
              step >= 2 ? 'bg-cyber-accent text-cyber-dark' : 'bg-gray-600 text-gray-300'
            }`}>
              2
            </div>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ${
              step >= 3 ? 'bg-cyber-accent text-cyber-dark' : 'bg-gray-600 text-gray-300'
            }`}>
              3
            </div>
          </div>
          <div className="text-gray-400 text-sm">
            Step {step} of 3
          </div>
        </div>
      </div>

      {/* Form Content */}
      <div className="bg-cyber-darker border border-cyber-accent/20 rounded-lg p-6">
        {step === 1 && renderStep1()}
        {step === 2 && renderStep2()}
        {step === 3 && renderStep3()}
      </div>

      {/* Security Tips */}
      <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-blue-400 mb-4">💡 Security Tips</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="flex items-start space-x-3">
            <span className="text-blue-400">🔒</span>
            <span className="text-gray-300">Don't share sensitive information in your report</span>
          </div>
          <div className="flex items-start space-x-3">
            <span className="text-blue-400">⏰</span>
            <span className="text-gray-300">Report incidents as soon as possible</span>
          </div>
          <div className="flex items-start space-x-3">
            <span className="text-blue-400">📸</span>
            <span className="text-gray-300">Include screenshots or evidence when possible</span>
          </div>
          <div className="flex items-start space-x-3">
            <span className="text-blue-400">📞</span>
            <span className="text-gray-300">For urgent incidents, contact security team directly</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IncidentReporting; 