import React, { useEffect, useMemo, useState } from 'react';

type Profile = { id: number; name: string; language: string; is_default?: boolean };
type RuleRow = { id: number; rule_id: string; name: string; severity: string; enabled: boolean; severity_override?: string | null };

const API_URL = process.env.REACT_APP_API_URL || '';

const languages = ['java','python','javascript','typescript','csharp','php','go','rust'];

const SASTRuleProfiles: React.FC = () => {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [selectedLanguage, setSelectedLanguage] = useState<string>('');
  const [selectedProfile, setSelectedProfile] = useState<Profile | null>(null);
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [search, setSearch] = useState('');
  const token = useMemo(() => localStorage.getItem('access_token') || '', []);

  const headers = useMemo(() => ({ 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }), [token]);

  const fetchProfiles = async (lang?: string) => {
    const qs = new URLSearchParams();
    if (lang) qs.set('language', lang);
    const res = await fetch(`${API_URL}/api/v1/sast/rule-profiles?${qs.toString()}`, { headers });
    if (res.ok) {
      const data = await res.json();
      setProfiles(data.profiles || []);
    }
  };

  const fetchRules = async (profileId: number) => {
    const res = await fetch(`${API_URL}/api/v1/sast/rule-profiles/${profileId}/rules`, { headers });
    if (res.ok) {
      const data = await res.json();
      setRules(data.rules || []);
    }
  };

  useEffect(() => { fetchProfiles(selectedLanguage || undefined); }, [selectedLanguage]);
  useEffect(() => { if (selectedProfile) fetchRules(selectedProfile.id); }, [selectedProfile]);

  const createProfile = async () => {
    const name = prompt('Profile name?');
    if (!name) return;
    const language = selectedLanguage || prompt('Language? (e.g., javascript)') || '';
    if (!language) return;
    const res = await fetch(`${API_URL}/api/v1/sast/rule-profiles`, { method: 'POST', headers, body: JSON.stringify({ name, language, is_default: false }) });
    if (res.ok) {
      await fetchProfiles(selectedLanguage || undefined);
    }
  };

  const updateProfile = async (p: Profile) => {
    const name = prompt('New profile name?', p.name) || p.name;
    const res = await fetch(`${API_URL}/api/v1/sast/rule-profiles/${p.id}`, { method: 'PUT', headers, body: JSON.stringify({ name }) });
    if (res.ok) {
      await fetchProfiles(selectedLanguage || undefined);
    }
  };

  const assignToProject = async (p: Profile) => {
    const idStr = prompt('Assign to project id?');
    if (!idStr) return;
    const projectId = Number(idStr);
    await fetch(`${API_URL}/api/v1/sast/projects/${projectId}/rule-profile/${p.id}`, { method: 'POST', headers });
    alert('Assigned');
  };

  const toggleRule = async (r: RuleRow) => {
    if (!selectedProfile) return;
    const res = await fetch(`${API_URL}/api/v1/sast/rule-profiles/${selectedProfile.id}/rules/${r.id}`, { method: 'POST', headers, body: JSON.stringify({ enabled: !r.enabled }) });
    if (res.ok) fetchRules(selectedProfile.id);
  };

  const overrideSeverity = async (r: RuleRow) => {
    if (!selectedProfile) return;
    const sev = prompt('Override severity (CRITICAL/HIGH/MEDIUM/LOW/INFO or empty to clear):', r.severity_override || '') || '';
    const payload = sev ? { severity_override: sev } : { severity_override: null } as any;
    const res = await fetch(`${API_URL}/api/v1/sast/rule-profiles/${selectedProfile.id}/rules/${r.id}`, { method: 'POST', headers, body: JSON.stringify(payload) });
    if (res.ok) fetchRules(selectedProfile.id);
  };

  const filteredRules = useMemo(() => rules.filter(r => !search || r.name.toLowerCase().includes(search.toLowerCase()) || r.rule_id.toLowerCase().includes(search.toLowerCase())), [rules, search]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <select className="border rounded px-2 py-1" value={selectedLanguage} onChange={e => setSelectedLanguage(e.target.value)}>
          <option value="">All languages</option>
          {languages.map(l => (<option key={l} value={l}>{l}</option>))}
        </select>
        <button className="px-3 py-1 bg-blue-600 text-white rounded" onClick={createProfile}>New Profile</button>
        <input className="border rounded px-2 py-1 ml-auto" placeholder="Search rules..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="border rounded p-3">
          <h3 className="font-semibold mb-2">Profiles</h3>
          <ul className="divide-y">
            {profiles.map(p => (
              <li key={p.id} className={`py-2 px-1 cursor-pointer ${selectedProfile?.id === p.id ? 'bg-blue-50' : ''}`} onClick={() => setSelectedProfile(p)}>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium">{p.name}</div>
                    <div className="text-xs text-gray-500">{p.language}</div>
                  </div>
                  <div className="flex gap-2">
                    <button className="text-xs text-blue-600" onClick={(e) => { e.stopPropagation(); updateProfile(p); }}>Rename</button>
                    <button className="text-xs text-green-600" onClick={(e) => { e.stopPropagation(); assignToProject(p); }}>Assign</button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="border rounded p-3 md:col-span-2">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-semibold">Rules {selectedProfile ? `for ${selectedProfile.name}` : ''}</h3>
          </div>
          {!selectedProfile ? (
            <div className="text-sm text-gray-500">Select a profile to view rules</div>
          ) : (
            <div className="overflow-auto max-h-[60vh]">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="text-left border-b">
                    <th className="py-2 pr-3">Rule</th>
                    <th className="py-2 pr-3">Severity</th>
                    <th className="py-2 pr-3">Enabled</th>
                    <th className="py-2 pr-3">Override</th>
                    <th className="py-2 pr-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.map(r => (
                    <tr key={r.id} className="border-b">
                      <td className="py-2 pr-3">
                        <div className="font-medium">{r.rule_id}</div>
                        <div className="text-xs text-gray-500">{r.name}</div>
                      </td>
                      <td className="py-2 pr-3">{r.severity}{r.severity_override ? ` → ${r.severity_override}` : ''}</td>
                      <td className="py-2 pr-3">
                        <button className={`px-2 py-0.5 rounded ${r.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`} onClick={() => toggleRule(r)}>
                          {r.enabled ? 'Enabled' : 'Disabled'}
                        </button>
                      </td>
                      <td className="py-2 pr-3">
                        <button className="text-blue-600" onClick={() => overrideSeverity(r)}>Set</button>
                      </td>
                      <td className="py-2 pr-3"></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SASTRuleProfiles;


