import { apiClient, apiCallWithRetry } from '../utils/apiClient';
import { API_ENDPOINTS, SERVICE_MAPPING } from './integrationService';

export interface TestResult {
  service: string;
  endpoint: string;
  method: string;
  success: boolean;
  responseTime: number;
  statusCode?: number;
  error?: string;
  response?: any;
}

export interface ServiceTestResult {
  service: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  successRate: number;
  averageResponseTime: number;
  results: TestResult[];
}

export interface IntegrationTestSummary {
  overallSuccess: number;
  totalServices: number;
  totalEndpoints: number;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  overallSuccessRate: number;
  averageResponseTime: number;
  serviceResults: ServiceTestResult[];
  timestamp: Date;
}

class IntegrationTestService {
  private testResults: Map<string, ServiceTestResult> = new Map();
  private isRunning: boolean = false;

  /**
   * Run comprehensive integration tests for all services
   */
  async runAllTests(): Promise<IntegrationTestSummary> {
    if (this.isRunning) {
      throw new Error('Integration tests are already running');
    }

    this.isRunning = true;
    this.testResults.clear();

    try {
      const services = Object.keys(SERVICE_MAPPING);
      const allResults: ServiceTestResult[] = [];

      for (const service of services) {
        const serviceResult = await this.testService(service);
        this.testResults.set(service, serviceResult);
        allResults.push(serviceResult);
      }

      return this.generateSummary(allResults);
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Test a specific service
   */
  async testService(serviceName: string): Promise<ServiceTestResult> {
    const endpoints = this.getServiceEndpoints(serviceName);
    const results: TestResult[] = [];

    for (const endpoint of endpoints) {
      const result = await this.testEndpoint(endpoint, 'GET');
      results.push(result);
    }

    // Test POST endpoints if they exist
    const postEndpoints = this.getPostEndpoints(serviceName);
    for (const endpoint of postEndpoints) {
      const result = await this.testEndpoint(endpoint, 'POST');
      results.push(result);
    }

    return this.calculateServiceResult(serviceName, results);
  }

  /**
   * Test a specific endpoint
   */
  async testEndpoint(endpoint: string, method: string): Promise<TestResult> {
    const startTime = Date.now();
    let success = false;
    let statusCode: number | undefined;
    let error: string | undefined;
    let response: any;

    try {
      let result;
      switch (method.toUpperCase()) {
        case 'GET':
          result = await apiCallWithRetry(() => apiClient.get(endpoint));
          break;
        case 'POST':
          result = await apiCallWithRetry(() => apiClient.post(endpoint, {}));
          break;
        case 'PUT':
          result = await apiCallWithRetry(() => apiClient.put(endpoint, {}));
          break;
        case 'DELETE':
          result = await apiCallWithRetry(() => apiClient.delete(endpoint));
          break;
        default:
          throw new Error(`Unsupported HTTP method: ${method}`);
      }

      success = true;
      statusCode = result.status;
      response = result.data;
    } catch (err: any) {
      success = false;
      error = err.message || 'Unknown error';
      if (err.response) {
        statusCode = err.response.status;
      }
    }

    const responseTime = Date.now() - startTime;

    return {
      service: this.getServiceForEndpoint(endpoint),
      endpoint,
      method,
      success,
      responseTime,
      statusCode,
      error,
      response
    };
  }

  /**
   * Get all endpoints for a service
   */
  private getServiceEndpoints(serviceName: string): string[] {
    const serviceEndpoints = API_ENDPOINTS[serviceName as keyof typeof API_ENDPOINTS];
    if (!serviceEndpoints) return [];

    return Object.values(serviceEndpoints).filter(endpoint => 
      typeof endpoint === 'string'
    ) as string[];
  }

  /**
   * Get POST endpoints for a service (endpoints that typically accept data)
   */
  private getPostEndpoints(serviceName: string): string[] {
    const serviceEndpoints = API_ENDPOINTS[serviceName as keyof typeof API_ENDPOINTS];
    if (!serviceEndpoints) return [];

    // Define which endpoints typically use POST
    const postEndpoints = [
      'CREATE', 'REGISTER', 'LOGIN', 'SCAN', 'UPLOAD', 'IMPORT',
      'EXPORT', 'GENERATE', 'ANALYZE', 'DETECT', 'MONITOR'
    ];

    return Object.entries(serviceEndpoints)
      .filter(([key, endpoint]) => 
        typeof endpoint === 'string' && 
        postEndpoints.some(postKey => key.includes(postKey))
      )
      .map(([, endpoint]) => endpoint as string);
  }

  /**
   * Get service name for an endpoint
   */
  private getServiceForEndpoint(endpoint: string): string {
    for (const [serviceName, serviceEndpoints] of Object.entries(API_ENDPOINTS)) {
      if (Object.values(serviceEndpoints).includes(endpoint)) {
        return serviceName;
      }
    }
    return 'Unknown';
  }

  /**
   * Calculate service test results
   */
  private calculateServiceResult(serviceName: string, results: TestResult[]): ServiceTestResult {
    const totalTests = results.length;
    const passedTests = results.filter(r => r.success).length;
    const failedTests = totalTests - passedTests;
    const successRate = totalTests > 0 ? (passedTests / totalTests) * 100 : 0;
    
    const responseTimes = results.map(r => r.responseTime).filter(time => time > 0);
    const averageResponseTime = responseTimes.length > 0 
      ? responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length 
      : 0;

    return {
      service: serviceName,
      totalTests,
      passedTests,
      failedTests,
      successRate,
      averageResponseTime,
      results
    };
  }

  /**
   * Generate overall test summary
   */
  private generateSummary(serviceResults: ServiceTestResult[]): IntegrationTestSummary {
    const totalServices = serviceResults.length;
    const totalTests = serviceResults.reduce((sum, result) => sum + result.totalTests, 0);
    const passedTests = serviceResults.reduce((sum, result) => sum + result.passedTests, 0);
    const failedTests = totalTests - passedTests;
    const overallSuccessRate = totalTests > 0 ? (passedTests / totalTests) * 100 : 0;
    
    const allResponseTimes = serviceResults
      .map(result => result.results.map(r => r.responseTime))
      .flat()
      .filter(time => time > 0);
    
    const averageResponseTime = allResponseTimes.length > 0
      ? allResponseTimes.reduce((sum, time) => sum + time, 0) / allResponseTimes.length
      : 0;

    const totalEndpoints = serviceResults.reduce((sum, result) => 
      sum + result.results.length, 0
    );

    return {
      overallSuccess: passedTests,
      totalServices,
      totalEndpoints,
      totalTests,
      passedTests,
      failedTests,
      overallSuccessRate,
      averageResponseTime,
      serviceResults,
      timestamp: new Date()
    };
  }

  /**
   * Get test results for a specific service
   */
  getServiceTestResults(serviceName: string): ServiceTestResult | undefined {
    return this.testResults.get(serviceName);
  }

  /**
   * Get all test results
   */
  getAllTestResults(): Map<string, ServiceTestResult> {
    return new Map(this.testResults);
  }

  /**
   * Get failed tests
   */
  getFailedTests(): TestResult[] {
    const failedTests: TestResult[] = [];
    const results = Array.from(this.testResults.values());
    for (const result of results) {
      failedTests.push(...result.results.filter(r => !r.success));
    }
    return failedTests;
  }

  /**
   * Get slow endpoints (above threshold)
   */
  getSlowEndpoints(thresholdMs: number = 1000): TestResult[] {
    const slowTests: TestResult[] = [];
    const results = Array.from(this.testResults.values());
    for (const result of results) {
      slowTests.push(...result.results.filter(r => r.responseTime > thresholdMs));
    }
    return slowTests.sort((a, b) => b.responseTime - a.responseTime);
  }

  /**
   * Export test results as JSON
   */
  exportTestResults(): string {
    const summary = this.generateSummary(Array.from(this.testResults.values()));
    return JSON.stringify(summary, null, 2);
  }

  /**
   * Export test results as CSV
   */
  exportTestResultsCSV(): string {
    const headers = ['Service', 'Endpoint', 'Method', 'Success', 'Response Time (ms)', 'Status Code', 'Error'];
    const rows = [headers.join(',')];

    const results = Array.from(this.testResults.values());
    for (const result of results) {
      for (const test of result.results) {
        const row = [
          test.service,
          test.endpoint,
          test.method,
          test.success ? 'PASS' : 'FAIL',
          test.responseTime.toString(),
          test.statusCode?.toString() || '',
          test.error || ''
        ].map(field => `"${field}"`).join(',');
        
        rows.push(row);
      }
    }

    return rows.join('\n');
  }

  /**
   * Generate test report
   */
  generateTestReport(): string {
    const summary = this.generateSummary(Array.from(this.testResults.values()));
    
    let report = `Integration Test Report\n`;
    report += `Generated: ${summary.timestamp.toISOString()}\n`;
    report += `\nOverall Summary:\n`;
    report += `- Total Services: ${summary.totalServices}\n`;
    report += `- Total Endpoints: ${summary.totalEndpoints}\n`;
    report += `- Total Tests: ${summary.totalTests}\n`;
    report += `- Passed Tests: ${summary.passedTests}\n`;
    report += `- Failed Tests: ${summary.failedTests}\n`;
    report += `- Success Rate: ${summary.overallSuccessRate.toFixed(2)}%\n`;
    report += `- Average Response Time: ${summary.averageResponseTime.toFixed(2)}ms\n\n`;

    report += `Service Results:\n`;
    for (const serviceResult of summary.serviceResults) {
      report += `\n${serviceResult.service}:\n`;
      report += `  - Success Rate: ${serviceResult.successRate.toFixed(2)}%\n`;
      report += `  - Tests: ${serviceResult.passedTests}/${serviceResult.totalTests}\n`;
      report += `  - Average Response Time: ${serviceResult.averageResponseTime.toFixed(2)}ms\n`;
      
      if (serviceResult.failedTests > 0) {
        report += `  - Failed Endpoints:\n`;
        serviceResult.results
          .filter(r => !r.success)
          .forEach(r => {
            report += `    * ${r.method} ${r.endpoint}: ${r.error}\n`;
          });
      }
    }

    const failedTests = this.getFailedTests();
    if (failedTests.length > 0) {
      report += `\nFailed Tests Summary:\n`;
      failedTests.forEach(test => {
        report += `- ${test.method} ${test.endpoint}: ${test.error}\n`;
      });
    }

    const slowEndpoints = this.getSlowEndpoints(1000);
    if (slowEndpoints.length > 0) {
      report += `\nSlow Endpoints (>1s):\n`;
      slowEndpoints.forEach(test => {
        report += `- ${test.method} ${test.endpoint}: ${test.responseTime}ms\n`;
      });
    }

    return report;
  }

  /**
   * Check if tests are currently running
   */
  isTestRunning(): boolean {
    return this.isRunning;
  }

  /**
   * Stop running tests
   */
  stopTests(): void {
    this.isRunning = false;
  }

  /**
   * Clear test results
   */
  clearResults(): void {
    this.testResults.clear();
  }
}

export const integrationTestService = new IntegrationTestService();
export default IntegrationTestService;
