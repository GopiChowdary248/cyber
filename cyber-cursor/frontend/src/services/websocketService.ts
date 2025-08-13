import { apiClient } from '../utils/apiClient';

export interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: string;
  id?: string;
}

export interface WebSocketConnection {
  id: string;
  status: 'connected' | 'disconnected' | 'connecting' | 'error';
  url: string;
  protocols?: string[];
  last_heartbeat?: string;
  reconnect_attempts: number;
  max_reconnect_attempts: number;
}

export interface WebSocketEvent {
  type: 'open' | 'message' | 'close' | 'error';
  data?: any;
  timestamp: string;
  connection_id: string;
}

export interface WebSocketChannel {
  id: string;
  name: string;
  subscribers: number;
  message_count: number;
  last_message?: string;
  created_at: string;
}

export interface WebSocketSubscription {
  channel_id: string;
  user_id: number;
  subscribed_at: string;
  last_activity: string;
  notification_preferences: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
}

class WebSocketService {
  private connections: Map<string, WebSocket> = new Map();
  private messageHandlers: Map<string, Set<(message: WebSocketMessage) => void>> = new Map();
  private connectionHandlers: Map<string, Set<(connection: WebSocketConnection) => void>> = new Map();
  private reconnectTimers: Map<string, NodeJS.Timeout> = new Map();
  private heartbeatTimers: Map<string, NodeJS.Timeout> = new Map();

  // Create a new WebSocket connection
  async createConnection(
    url: string,
    protocols?: string[],
    options: {
      autoReconnect?: boolean;
      maxReconnectAttempts?: number;
      heartbeatInterval?: number;
    } = {}
  ): Promise<string> {
    const connectionId = this.generateConnectionId();
    const connection = new WebSocket(url, protocols);
    
    const connectionConfig: WebSocketConnection = {
      id: connectionId,
      status: 'connecting',
      url,
      protocols,
      reconnect_attempts: 0,
      max_reconnect_attempts: options.maxReconnectAttempts || 5,
    };

    // Set up event handlers
    connection.onopen = () => this.handleConnectionOpen(connectionId, connectionConfig);
    connection.onmessage = (event) => this.handleMessage(connectionId, event);
    connection.onclose = (event) => this.handleConnectionClose(connectionId, event, options.autoReconnect);
    connection.onerror = (error) => this.handleConnectionError(connectionId, error);

    // Store connection
    this.connections.set(connectionId, connection);

    // Set up heartbeat if specified
    if (options.heartbeatInterval) {
      this.setupHeartbeat(connectionId, options.heartbeatInterval);
    }

    return connectionId;
  }

  // Close a WebSocket connection
  closeConnection(connectionId: string, code?: number, reason?: string): void {
    const connection = this.connections.get(connectionId);
    if (connection) {
      connection.close(code, reason);
      this.cleanupConnection(connectionId);
    }
  }

  // Send a message through a specific connection
  sendMessage(connectionId: string, message: WebSocketMessage): boolean {
    const connection = this.connections.get(connectionId);
    if (connection && connection.readyState === WebSocket.OPEN) {
      connection.send(JSON.stringify(message));
      return true;
    }
    return false;
  }

  // Subscribe to a channel
  async subscribeToChannel(channelId: string, userId: number): Promise<WebSocketSubscription> {
    const response = await apiClient.post('/ws/subscribe', {
      channel_id: channelId,
      user_id: userId,
    });
    return response.data;
  }

  // Unsubscribe from a channel
  async unsubscribeFromChannel(channelId: string, userId: number): Promise<{ success: boolean }> {
    const response = await apiClient.post('/ws/unsubscribe', {
      channel_id: channelId,
      user_id: userId,
    });
    return response.data;
  }

  // Get available channels
  async getChannels(): Promise<WebSocketChannel[]> {
    const response = await apiClient.get('/ws/channels');
    return response.data;
  }

  // Get user subscriptions
  async getUserSubscriptions(userId: number): Promise<WebSocketSubscription[]> {
    const response = await apiClient.get(`/ws/subscriptions/${userId}`);
    return response.data;
  }

  // Broadcast message to a channel
  async broadcastToChannel(channelId: string, message: WebSocketMessage): Promise<{ success: boolean }> {
    const response = await apiClient.post(`/ws/channels/${channelId}/broadcast`, message);
    return response.data;
  }

  // Get connection status
  getConnectionStatus(connectionId: string): WebSocketConnection | null {
    const connection = this.connections.get(connectionId);
    if (connection) {
      return {
        id: connectionId,
        status: this.getConnectionState(connection.readyState),
        url: connection.url,
        reconnect_attempts: 0,
        max_reconnect_attempts: 5,
      };
    }
    return null;
  }

  // Get all active connections
  getAllConnections(): WebSocketConnection[] {
    const connections: WebSocketConnection[] = [];
    this.connections.forEach((connection, id) => {
      connections.push({
        id,
        status: this.getConnectionState(connection.readyState),
        url: connection.url,
        reconnect_attempts: 0,
        max_reconnect_attempts: 5,
      });
    });
    return connections;
  }

  // Add message handler
  addMessageHandler(connectionId: string, handler: (message: WebSocketMessage) => void): void {
    if (!this.messageHandlers.has(connectionId)) {
      this.messageHandlers.set(connectionId, new Set());
    }
    this.messageHandlers.get(connectionId)!.add(handler);
  }

  // Remove message handler
  removeMessageHandler(connectionId: string, handler: (message: WebSocketMessage) => void): void {
    const handlers = this.messageHandlers.get(connectionId);
    if (handlers) {
      handlers.delete(handler);
    }
  }

  // Add connection status handler
  addConnectionHandler(connectionId: string, handler: (connection: WebSocketConnection) => void): void {
    if (!this.connectionHandlers.has(connectionId)) {
      this.connectionHandlers.set(connectionId, new Set());
    }
    this.connectionHandlers.get(connectionId)!.add(handler);
  }

  // Remove connection status handler
  removeConnectionHandler(connectionId: string, handler: (connection: WebSocketConnection) => void): void {
    const handlers = this.connectionHandlers.get(connectionId);
    if (handlers) {
      handlers.delete(handler);
    }
  }

  // Get WebSocket statistics
  async getWebSocketStats(): Promise<{
    total_connections: number;
    active_connections: number;
    total_channels: number;
    total_subscriptions: number;
    messages_sent: number;
    messages_received: number;
    errors: number;
  }> {
    const response = await apiClient.get('/ws/stats');
    return response.data;
  }

  // Get connection logs
  async getConnectionLogs(
    connectionId?: string,
    limit: number = 100
  ): Promise<WebSocketEvent[]> {
    const params: any = { limit };
    if (connectionId) {
      params.connection_id = connectionId;
    }
    
    const response = await apiClient.get('/ws/logs', { params });
    return response.data;
  }

  // Export WebSocket data
  async exportWebSocketData(
    format: 'json' | 'csv' = 'json',
    includeLogs: boolean = true
  ): Promise<Blob> {
    const response = await apiClient.get('/ws/export', {
      params: { format, include_logs: includeLogs },
      responseType: 'blob',
    });
    return response.data;
  }

  // Private methods
  private generateConnectionId(): string {
    return `ws_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private getConnectionState(readyState: number): 'connected' | 'disconnected' | 'connecting' | 'error' {
    switch (readyState) {
      case WebSocket.CONNECTING:
        return 'connecting';
      case WebSocket.OPEN:
        return 'connected';
      case WebSocket.CLOSING:
        return 'disconnected';
      case WebSocket.CLOSED:
        return 'disconnected';
      default:
        return 'error';
    }
  }

  private handleConnectionOpen(connectionId: string, connectionConfig: WebSocketConnection): void {
    connectionConfig.status = 'connected';
    connectionConfig.last_heartbeat = new Date().toISOString();
    
    // Notify connection handlers
    const handlers = this.connectionHandlers.get(connectionId);
    if (handlers) {
      handlers.forEach(handler => handler(connectionConfig));
    }

    // Send connection established message
    this.sendMessage(connectionId, {
      type: 'connection_established',
      data: { connection_id: connectionId },
      timestamp: new Date().toISOString(),
    });
  }

  private handleMessage(connectionId: string, event: MessageEvent): void {
    try {
      const message: WebSocketMessage = JSON.parse(event.data);
      
      // Notify message handlers
      const handlers = this.messageHandlers.get(connectionId);
      if (handlers) {
        handlers.forEach(handler => handler(message));
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  }

  private handleConnectionClose(
    connectionId: string,
    event: CloseEvent,
    autoReconnect?: boolean
  ): void {
    const connectionConfig = this.getConnectionStatus(connectionId);
    if (connectionConfig) {
      connectionConfig.status = 'disconnected';
      
      // Notify connection handlers
      const handlers = this.connectionHandlers.get(connectionId);
      if (handlers) {
        handlers.forEach(handler => handler(connectionConfig));
      }
    }

    if (autoReconnect) {
      this.scheduleReconnect(connectionId);
    } else {
      this.cleanupConnection(connectionId);
    }
  }

  private handleConnectionError(connectionId: string, error: Event): void {
    const connectionConfig = this.getConnectionStatus(connectionId);
    if (connectionConfig) {
      connectionConfig.status = 'error';
      
      // Notify connection handlers
      const handlers = this.connectionHandlers.get(connectionId);
      if (handlers) {
        handlers.forEach(handler => handler(connectionConfig));
      }
    }
  }

  private scheduleReconnect(connectionId: string): void {
    const connection = this.connections.get(connectionId);
    if (connection) {
      const connectionConfig = this.getConnectionStatus(connectionId);
      if (connectionConfig && connectionConfig.reconnect_attempts < connectionConfig.max_reconnect_attempts) {
        const delay = Math.min(1000 * Math.pow(2, connectionConfig.reconnect_attempts), 30000);
        
        const timer = setTimeout(() => {
          this.reconnect(connectionId);
        }, delay);
        
        this.reconnectTimers.set(connectionId, timer);
      }
    }
  }

  private async reconnect(connectionId: string): Promise<void> {
    const connection = this.connections.get(connectionId);
    if (connection) {
      const connectionConfig = this.getConnectionStatus(connectionId);
      if (connectionConfig) {
        connectionConfig.reconnect_attempts++;
        connectionConfig.status = 'connecting';
        
        try {
          const newConnection = new WebSocket(connection.url, connectionConfig.protocols);
          newConnection.onopen = () => this.handleConnectionOpen(connectionId, connectionConfig);
          newConnection.onmessage = (event) => this.handleMessage(connectionId, event);
          newConnection.onclose = (event) => this.handleConnectionClose(connectionId, event, true);
          newConnection.onerror = (error) => this.handleConnectionError(connectionId, error);
          
          this.connections.set(connectionId, newConnection);
        } catch (error) {
          console.error('Reconnection failed:', error);
          this.scheduleReconnect(connectionId);
        }
      }
    }
  }

  private setupHeartbeat(connectionId: string, interval: number): void {
    const timer = setInterval(() => {
      const connection = this.connections.get(connectionId);
      if (connection && connection.readyState === WebSocket.OPEN) {
        this.sendMessage(connectionId, {
          type: 'heartbeat',
          data: { timestamp: Date.now() },
          timestamp: new Date().toISOString(),
        });
      }
    }, interval);
    
    this.heartbeatTimers.set(connectionId, timer);
  }

  private cleanupConnection(connectionId: string): void {
    // Clear timers
    const reconnectTimer = this.reconnectTimers.get(connectionId);
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      this.reconnectTimers.delete(connectionId);
    }
    
    const heartbeatTimer = this.heartbeatTimers.get(connectionId);
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      this.heartbeatTimers.delete(connectionId);
    }
    
    // Remove handlers
    this.messageHandlers.delete(connectionId);
    this.connectionHandlers.delete(connectionId);
    
    // Remove connection
    this.connections.delete(connectionId);
  }

  // Cleanup all connections
  cleanup(): void {
    this.connections.forEach((connection, id) => {
      connection.close();
      this.cleanupConnection(id);
    });
  }
}

export const websocketService = new WebSocketService();
export default websocketService;
