import { serviceRegistry, apiCallWithRetry } from './serviceRegistry';

const base = (projectId: string) => `/api/v1/dast/projects/${projectId}`;

export class DASTProjectToolsService {
  async getDashboardActivity(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/dashboard/activity`));
  }

  async getDashboardIssues(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/dashboard/issues`));
  }

  async getDashboardEvents(projectId: string, params?: { limit?: number }) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/dashboard/events`, { params }));
  }

  // Target
  async addTarget(projectId: string, payload: any) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/target/add`, payload));
  }
  async getSiteMap(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/target/map`));
  }
  async updateScope(projectId: string, rules: any) {
    return apiCallWithRetry(() => serviceRegistry.put(`${base(projectId)}/target/scope`, rules));
  }
  async removeTarget(projectId: string, itemId: string) {
    return apiCallWithRetry(() => serviceRegistry.delete(`${base(projectId)}/target/remove/${itemId}`));
  }
  async updateTargetNodeScope(projectId: string, nodeId: string, inScope: boolean) {
    return apiCallWithRetry(() => serviceRegistry.put(`${base(projectId)}/target/node/${nodeId}/scope`, { in_scope: inScope }));
  }
  async bulkUpdateNodeScope(projectId: string, ids: string[], inScope: boolean) {
    return apiCallWithRetry(() => serviceRegistry.put(`${base(projectId)}/target/nodes/scope`, { ids, in_scope: inScope }));
  }

  // Proxy
  async getHttpHistory(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/proxy/http-history`));
  }
  async getProxyEntry(projectId: string, entryId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/proxy/http-history/${entryId}`));
  }
  async toggleIntercept(projectId: string, enabled: boolean) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/proxy/intercept/toggle`, null, { params: { enabled } }));
  }
  async updateProxySettings(projectId: string, settings: any) {
    return apiCallWithRetry(() => serviceRegistry.put(`${base(projectId)}/proxy/settings`, settings));
  }
  async proxyForward(projectId: string, entryId: string) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/proxy/intercept/forward`, { entry_id: entryId }));
  }
  async proxyDrop(projectId: string, entryId: string) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/proxy/intercept/drop`, { entry_id: entryId }));
  }

  // Intruder
  async intruderStart(projectId: string, attack: any) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/intruder/start`, attack));
  }
  async intruderStatus(projectId: string, attackId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/intruder/status/${attackId}`));
  }
  async intruderResults(projectId: string, attackId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/intruder/results/${attackId}`));
  }
  async intruderStop(projectId: string, attackId: string) {
    return apiCallWithRetry(() => serviceRegistry.put(`${base(projectId)}/intruder/stop/${attackId}`));
  }

  // Repeater
  async repeaterSend(projectId: string, requestData: any) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/repeater/send`, requestData));
  }
  async repeaterHistory(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/repeater/history`));
  }
  async repeaterCloseSession(projectId: string, sessionId: string) {
    return apiCallWithRetry(() => serviceRegistry.delete(`${base(projectId)}/repeater/session/${sessionId}`));
  }

  // Sequencer
  async sequencerStart(projectId: string, payload: any) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/sequencer/start`, payload));
  }
  async sequencerResults(projectId: string, sequenceId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/sequencer/results/${sequenceId}`));
  }

  // Decoder
  async decoderTransform(projectId: string, payload: { mode: 'encode' | 'decode' | 'hash'; text: string }) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/decoder/transform`, payload));
  }

  // Comparer
  async comparerCompare(projectId: string, payload: { left: string; right: string; mode?: 'words' | 'bytes' }) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/comparer/compare`, payload));
  }

  // Extender
  async extenderList(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/extender/list`));
  }
  async extenderInstall(projectId: string, payload: any) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/extender/install`, payload));
  }
  async extenderRemove(projectId: string, extensionId: string) {
    return apiCallWithRetry(() => serviceRegistry.delete(`${base(projectId)}/extender/remove/${extensionId}`));
  }

  // Scanner
  async scannerStart(projectId: string, config: any) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/scanner/start`, config));
  }
  async scannerStatus(projectId: string, scanId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/scanner/status/${scanId}`));
  }
  async scannerIssues(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/scanner/issues`));
  }
  async scannerStop(projectId: string, scanId: string) {
    return apiCallWithRetry(() => serviceRegistry.put(`${base(projectId)}/scanner/stop/${scanId}`));
  }

  // Logger
  async loggerEntries(projectId: string, params?: { q?: string }) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/logger/entries`, { params }));
  }

  // Members
  async listMembers(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/members`));
  }
  async addMember(projectId: string, payload: { user_id: number; role: string }) {
    return apiCallWithRetry(() => serviceRegistry.post(`${base(projectId)}/members`, payload));
  }
  async removeMember(projectId: string, userId: number) {
    return apiCallWithRetry(() => serviceRegistry.delete(`${base(projectId)}/members/${userId}`));
  }

  // Settings
  async getSettings(projectId: string) {
    return apiCallWithRetry(() => serviceRegistry.get(`${base(projectId)}/settings`));
  }
  async updateSettings(projectId: string, settings: any) {
    return apiCallWithRetry(() => serviceRegistry.put(`${base(projectId)}/settings`, settings));
  }
}

export const dastProjectToolsService = new DASTProjectToolsService();


