#!/usr/bin/env python3
"""
DAST CLI Tool
Command-line interface for Dynamic Application Security Testing
Provides comprehensive DAST functionality from the command line
"""

import argparse
import asyncio
import json
import sys
import time
from typing import Dict, Any, Optional
from datetime import datetime
import aiohttp
import yaml

class DASTCLI:
    """DAST Command Line Interface"""
    
    def __init__(self, api_url: str = "http://localhost:8000", api_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def create_project(self, name: str, target_url: str, description: str = None, 
                           auth_type: str = "none", config_file: str = None) -> Dict[str, Any]:
        """Create a new DAST project"""
        project_data = {
            "name": name,
            "target_url": target_url,
            "description": description,
            "auth_type": auth_type
        }
        
        if config_file:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                project_data.update(config)
        
        async with self.session.post(
            f"{self.api_url}/api/v1/dast/projects",
            json=project_data
        ) as response:
            if response.status == 201:
                return await response.json()
            else:
                raise Exception(f"Failed to create project: {response.status}")
    
    async def start_scan(self, project_id: str, scan_type: str = "full", 
                        config_file: str = None) -> Dict[str, Any]:
        """Start a DAST scan"""
        scan_data = {
            "project_id": project_id,
            "scan_type": scan_type
        }
        
        if config_file:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                scan_data.update(config)
        
        async with self.session.post(
            f"{self.api_url}/api/v1/dast/scans",
            json=scan_data
        ) as response:
            if response.status == 201:
                return await response.json()
            else:
                raise Exception(f"Failed to start scan: {response.status}")
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status"""
        async with self.session.get(
            f"{self.api_url}/api/v1/dast/scans/{scan_id}"
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to get scan status: {response.status}")
    
    async def get_scan_vulnerabilities(self, scan_id: str) -> Dict[str, Any]:
        """Get scan vulnerabilities"""
        async with self.session.get(
            f"{self.api_url}/api/v1/dast/scans/{scan_id}/vulnerabilities"
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to get vulnerabilities: {response.status}")
    
    async def generate_report(self, scan_id: str, format: str = "json") -> Dict[str, Any]:
        """Generate scan report"""
        async with self.session.get(
            f"{self.api_url}/api/v1/dast/reports/{scan_id}",
            params={"format": format}
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to generate report: {response.status}")
    
    async def list_projects(self) -> Dict[str, Any]:
        """List all projects"""
        async with self.session.get(
            f"{self.api_url}/api/v1/dast/projects"
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to list projects: {response.status}")
    
    async def list_scans(self, project_id: str = None) -> Dict[str, Any]:
        """List scans"""
        params = {}
        if project_id:
            params["project_id"] = project_id
        
        async with self.session.get(
            f"{self.api_url}/api/v1/dast/scans",
            params=params
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to list scans: {response.status}")
    
    async def get_overview(self) -> Dict[str, Any]:
        """Get DAST overview"""
        async with self.session.get(
            f"{self.api_url}/api/v1/dast/overview"
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to get overview: {response.status}")
    
    async def wait_for_scan_completion(self, scan_id: str, timeout: int = 3600, 
                                     check_interval: int = 10) -> Dict[str, Any]:
        """Wait for scan completion"""
        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout:
                raise Exception(f"Scan timeout after {timeout} seconds")
            
            status = await self.get_scan_status(scan_id)
            
            if status["status"] in ["completed", "failed"]:
                return status
            
            print(f"Scan {scan_id} status: {status['status']}")
            await asyncio.sleep(check_interval)
    
    def print_vulnerabilities(self, vulnerabilities: list, format: str = "table"):
        """Print vulnerabilities in specified format"""
        if format == "json":
            print(json.dumps(vulnerabilities, indent=2))
        elif format == "table":
            print("\nVulnerabilities Found:")
            print("-" * 80)
            print(f"{'Severity':<10} {'Type':<15} {'Title':<40} {'URL':<30}")
            print("-" * 80)
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown")
                vuln_type = vuln.get("vuln_type", "unknown")
                title = vuln.get("title", "")[:37] + "..." if len(vuln.get("title", "")) > 40 else vuln.get("title", "")
                url = vuln.get("url", "")[:27] + "..." if len(vuln.get("url", "")) > 30 else vuln.get("url", "")
                
                print(f"{severity:<10} {vuln_type:<15} {title:<40} {url:<30}")
        elif format == "csv":
            print("severity,type,title,url,description")
            for vuln in vulnerabilities:
                print(f"{vuln.get('severity', '')},{vuln.get('vuln_type', '')},{vuln.get('title', '')},{vuln.get('url', '')},{vuln.get('description', '')}")

async def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(description="DAST Command Line Interface")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API URL")
    parser.add_argument("--api-key", help="API key for authentication")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Create project command
    create_project_parser = subparsers.add_parser("create-project", help="Create a new DAST project")
    create_project_parser.add_argument("name", help="Project name")
    create_project_parser.add_argument("target_url", help="Target URL")
    create_project_parser.add_argument("--description", help="Project description")
    create_project_parser.add_argument("--auth-type", default="none", 
                                     choices=["none", "cookie", "jwt", "oauth2", "basic", "api_key"],
                                     help="Authentication type")
    create_project_parser.add_argument("--config", help="Configuration file (YAML)")
    
    # Start scan command
    start_scan_parser = subparsers.add_parser("start-scan", help="Start a DAST scan")
    start_scan_parser.add_argument("project_id", help="Project ID")
    start_scan_parser.add_argument("--scan-type", default="full",
                                 choices=["passive", "active", "full", "custom"],
                                 help="Scan type")
    start_scan_parser.add_argument("--config", help="Scan configuration file (YAML)")
    start_scan_parser.add_argument("--wait", action="store_true", help="Wait for scan completion")
    start_scan_parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")
    
    # Get scan status command
    status_parser = subparsers.add_parser("scan-status", help="Get scan status")
    status_parser.add_argument("scan_id", help="Scan ID")
    
    # Get vulnerabilities command
    vulns_parser = subparsers.add_parser("vulnerabilities", help="Get scan vulnerabilities")
    vulns_parser.add_argument("scan_id", help="Scan ID")
    vulns_parser.add_argument("--format", choices=["json", "table", "csv"], default="table",
                             help="Output format")
    
    # Generate report command
    report_parser = subparsers.add_parser("report", help="Generate scan report")
    report_parser.add_argument("scan_id", help="Scan ID")
    report_parser.add_argument("--format", choices=["json", "pdf", "html", "csv"], default="json",
                              help="Report format")
    
    # List projects command
    list_projects_parser = subparsers.add_parser("list-projects", help="List all projects")
    
    # List scans command
    list_scans_parser = subparsers.add_parser("list-scans", help="List scans")
    list_scans_parser.add_argument("--project-id", help="Filter by project ID")
    
    # Overview command
    overview_parser = subparsers.add_parser("overview", help="Get DAST overview")
    
    # Quick scan command
    quick_scan_parser = subparsers.add_parser("quick-scan", help="Quick scan workflow")
    quick_scan_parser.add_argument("target_url", help="Target URL")
    quick_scan_parser.add_argument("--name", help="Project name (default: auto-generated)")
    quick_scan_parser.add_argument("--scan-type", default="full",
                                 choices=["passive", "active", "full"],
                                 help="Scan type")
    quick_scan_parser.add_argument("--wait", action="store_true", help="Wait for completion")
    quick_scan_parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")
    quick_scan_parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        async with DASTCLI(args.api_url, args.api_key) as cli:
            if args.command == "create-project":
                result = await cli.create_project(
                    args.name, args.target_url, args.description,
                    args.auth_type, args.config
                )
                print(f"Project created: {result['id']}")
                
            elif args.command == "start-scan":
                result = await cli.start_scan(args.project_id, args.scan_type, args.config)
                print(f"Scan started: {result['id']}")
                
                if args.wait:
                    print("Waiting for scan completion...")
                    final_status = await cli.wait_for_scan_completion(result['id'], args.timeout)
                    print(f"Scan completed with status: {final_status['status']}")
                    
                    if final_status['status'] == 'completed':
                        vulns = await cli.get_scan_vulnerabilities(result['id'])
                        cli.print_vulnerabilities(vulns['vulnerabilities'])
                
            elif args.command == "scan-status":
                result = await cli.get_scan_status(args.scan_id)
                print(json.dumps(result, indent=2))
                
            elif args.command == "vulnerabilities":
                result = await cli.get_scan_vulnerabilities(args.scan_id)
                cli.print_vulnerabilities(result['vulnerabilities'], args.format)
                
            elif args.command == "report":
                result = await cli.generate_report(args.scan_id, args.format)
                print(f"Report generated: {result['report_id']}")
                print(f"Download URL: {result['download_url']}")
                
            elif args.command == "list-projects":
                result = await cli.list_projects()
                print("\nProjects:")
                print("-" * 60)
                for project in result['projects']:
                    print(f"ID: {project['id']}")
                    print(f"Name: {project['name']}")
                    print(f"URL: {project['target_url']}")
                    print(f"Scans: {project['total_scans']}")
                    print(f"Vulnerabilities: {project['total_vulnerabilities']}")
                    print(f"Security Score: {project['security_score']}")
                    print("-" * 60)
                
            elif args.command == "list-scans":
                result = await cli.list_scans(args.project_id)
                print("\nScans:")
                print("-" * 80)
                for scan in result['scans']:
                    print(f"ID: {scan['id']}")
                    print(f"Project: {scan['project_name']}")
                    print(f"Type: {scan['scan_type']}")
                    print(f"Status: {scan['status']}")
                    print(f"Vulnerabilities: {scan['vulnerabilities_found']}")
                    print(f"Duration: {scan['duration']}")
                    print("-" * 80)
                
            elif args.command == "overview":
                result = await cli.get_overview()
                print("\nDAST Overview:")
                print("-" * 40)
                print(f"Total Projects: {result['overview']['totalProjects']}")
                print(f"Total Scans: {result['overview']['totalScans']}")
                print(f"Active Scans: {result['overview']['activeScans']}")
                print(f"Total Vulnerabilities: {result['overview']['totalVulnerabilities']}")
                print(f"Security Score: {result['overview']['securityScore']}")
                
                print("\nVulnerabilities by Severity:")
                for severity, count in result['vulnerabilities'].items():
                    if severity != 'total':
                        print(f"  {severity.capitalize()}: {count}")
                
            elif args.command == "quick-scan":
                # Quick scan workflow
                project_name = args.name or f"Quick Scan - {datetime.now().strftime('%Y%m%d-%H%M%S')}"
                
                print(f"Creating project: {project_name}")
                project = await cli.create_project(project_name, args.target_url)
                
                print(f"Starting scan...")
                scan = await cli.start_scan(project['id'], args.scan_type)
                
                if args.wait:
                    print("Waiting for scan completion...")
                    final_status = await cli.wait_for_scan_completion(scan['id'], args.timeout)
                    
                    if final_status['status'] == 'completed':
                        vulns = await cli.get_scan_vulnerabilities(scan['id'])
                        report = await cli.generate_report(scan['id'])
                        
                        print(f"\nScan completed!")
                        print(f"Vulnerabilities found: {len(vulns['vulnerabilities'])}")
                        print(f"Report ID: {report['report_id']}")
                        
                        cli.print_vulnerabilities(vulns['vulnerabilities'])
                        
                        if args.output:
                            with open(args.output, 'w') as f:
                                json.dump({
                                    'project': project,
                                    'scan': final_status,
                                    'vulnerabilities': vulns['vulnerabilities'],
                                    'report': report
                                }, f, indent=2)
                            print(f"Results saved to: {args.output}")
                    else:
                        print(f"Scan failed with status: {final_status['status']}")
                else:
                    print(f"Scan started: {scan['id']}")
                    print(f"Use 'dast-cli scan-status {scan['id']}' to check progress")
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 