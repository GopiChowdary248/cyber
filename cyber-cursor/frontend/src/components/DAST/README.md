# DAST Security Suite

A comprehensive Dynamic Application Security Testing (DAST) application built with React and TypeScript, designed to provide Burp Suite-like functionality for web application security testing.

## Overview

The DAST Security Suite is a modern, web-based security testing platform that provides:

- **HTTP Traffic Analysis**: Complete request/response capture and analysis
- **Automated Vulnerability Scanning**: Active and passive security testing
- **Web Crawling**: Automated discovery of application endpoints
- **Manual Testing Tools**: Repeater and Intruder for manual security testing
- **Traffic Modification**: Match/replace rules for request/response manipulation
- **Site Map Management**: Visual representation of discovered endpoints

## Components

### Core Application

- **`DASTApplication.tsx`**: Main application container with unified tabbed navigation
- **`dastProjectToolsService.ts`**: Service layer for all backend API communications

### Traffic Analysis

- **`DASTHttpHistory.tsx`**: HTTP History tab for comprehensive traffic analysis
- **`DASTProxyEngine.tsx`**: Proxy engine for intercepting and modifying HTTP traffic

### Security Testing Tools

- **`DASTScanner.tsx`**: Active vulnerability scanner with configurable profiles
- **`DASTScannerIntegration.tsx`**: Enhanced scanner with scan management
- **`DASTCrawler.tsx`**: Web crawler for automated endpoint discovery
- **`DASTIntruder.tsx`**: Automated parameter testing tool (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
- **`DASTRepeater.tsx`**: Manual request manipulation and testing tool

### Management & Configuration

- **`DASTTarget.tsx`**: Site map visualization and scope management
- **`DASTMatchReplaceRules.tsx`**: Traffic modification rules management

## Features

### Phase 1 (High Priority) - ✅ Implemented
- **HTTP History Tab**: Complete traffic analysis with filtering and search
- **Repeater Tool**: Manual request manipulation and response analysis
- **Tabbed Interface**: Unified navigation across all tools
- **Context Menus**: Right-click actions for enhanced workflow

### Phase 2 (Medium Priority) - ✅ Implemented
- **Intruder Tool**: Automated testing with multiple attack types
- **Scanner Integration**: Active and passive vulnerability scanning
- **Target Management**: Site map visualization and scope configuration

### Phase 3 (Low Priority) - 🔄 In Progress
- **Virtual Scrolling**: Performance optimization for large datasets
- **WebSocket Updates**: Real-time traffic monitoring
- **Macro System**: Automation of repetitive tasks
- **Session Management**: State persistence across sessions

## Architecture

### Frontend
- **React 18+**: Modern React with hooks and functional components
- **TypeScript**: Type-safe development
- **Framer Motion**: Smooth animations and transitions
- **Tailwind CSS**: Utility-first CSS framework
- **Lucide React**: Modern icon library

### Backend Integration
- **RESTful API**: Standard HTTP endpoints for all operations
- **Real-time Updates**: WebSocket support for live traffic monitoring
- **File Export**: Multiple format support (JSON, CSV, XML)

### Data Management
- **State Management**: React hooks for local state
- **API Service Layer**: Centralized backend communication
- **Error Handling**: Comprehensive error handling and user feedback

## Usage

### Getting Started

1. **Launch the Application**: Navigate to the DAST module in your project
2. **Configure Proxy**: Set up proxy settings for traffic interception
3. **Start Crawling**: Use the Spider tab to discover application endpoints
4. **Run Scans**: Configure and execute security scans using the Scanner tab
5. **Manual Testing**: Use Repeater and Intruder tools for manual security testing

### Key Workflows

#### 1. Traffic Analysis
- Start the proxy engine
- Browse the target application
- Review captured traffic in HTTP History
- Analyze requests and responses for security issues

#### 2. Vulnerability Scanning
- Create or select a scan profile
- Configure scan parameters and modules
- Start the scan and monitor progress
- Review discovered vulnerabilities

#### 3. Manual Testing
- Use Repeater to modify and resend requests
- Use Intruder for automated parameter testing
- Analyze responses for security vulnerabilities
- Document findings and evidence

#### 4. Site Mapping
- Configure crawl scope and rules
- Start automated crawling
- Review discovered endpoints
- Manage scope inclusion/exclusion

## Configuration

### Scan Profiles
- **Quick Scan**: Fast scan with basic security checks
- **Full Scan**: Comprehensive security assessment
- **API Scan**: Specialized for API endpoint testing
- **Custom Profiles**: User-defined scan configurations

### Attack Types (Intruder)
- **Sniper**: Single payload, single position
- **Battering Ram**: Same payload, multiple positions
- **Pitchfork**: Multiple payloads, multiple positions
- **Cluster Bomb**: All payload combinations

### Scope Management
- **Include Patterns**: URLs to include in testing
- **Exclude Patterns**: URLs to exclude from testing
- **Port Restrictions**: Allowed ports for testing
- **File Type Filters**: File types to include/exclude

## Security Considerations

- **Proxy Configuration**: Ensure proxy is only accessible to authorized users
- **Scan Scope**: Carefully define testing scope to avoid unauthorized testing
- **Rate Limiting**: Implement appropriate rate limiting for automated tools
- **Data Privacy**: Handle sensitive data appropriately in logs and exports

## Development

### Prerequisites
- Node.js 16+
- React 18+
- TypeScript 4.5+

### Setup
```bash
# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

### Adding New Tools
1. Create new component in appropriate directory
2. Add to `DASTApplication.tsx` tabs array
3. Implement required interfaces and functionality
4. Add to service layer if backend integration needed

### Testing
```bash
# Run unit tests
npm test

# Run integration tests
npm run test:integration

# Run e2e tests
npm run test:e2e
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the code examples

## Roadmap

### Upcoming Features
- **Collaboration Tools**: Team workflow and sharing
- **Mobile Optimization**: Touch-friendly interface
- **Advanced Reporting**: Custom report generation
- **Integration APIs**: Third-party tool integration
- **Performance Optimization**: Large dataset handling improvements
