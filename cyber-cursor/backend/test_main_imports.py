#!/usr/bin/env python3
"""
Test script to check which imports in main.py are failing
"""

import sys

def test_import(module_name, description):
    try:
        __import__(module_name)
        print(f"✓ {description}: {module_name}")
        return True
    except Exception as e:
        print(f"✗ {description}: {module_name} - {e}")
        return False

print("Testing main.py imports...")

# Test each import individually
imports = [
    ("app.api.v1.endpoints.dast_project_tools", "DAST Project Tools"),
    ("app.api.v1.endpoints.sast", "SAST"),
    ("app.api.v1.endpoints.rasp_endpoints", "RASP Endpoints"),
    ("app.api.v1.endpoints.cloud_security", "Cloud Security"),
    ("app.api.v1.endpoints.endpoint_security", "Endpoint Security"),
    ("app.api.v1.endpoints.network_security", "Network Security"),
    ("app.api.v1.endpoints.iam_security", "IAM Security"),
    ("app.api.v1.endpoints.data_security", "Data Security"),
    ("app.api.v1.endpoints.incident_management", "Incident Management"),
    ("app.api.v1.endpoints.threat_intelligence", "Threat Intelligence"),
    ("app.api.v1.endpoints.compliance", "Compliance"),
    ("app.api.v1.endpoints.devsecops", "DevSecOps"),
    ("app.api.v1.endpoints.ai_ml", "AI ML"),
    ("app.api.v1.endpoints.admin", "Admin"),
    ("app.api.v1.endpoints.user_management", "User Management"),
    ("app.api.v1.endpoints.audit_logs", "Audit Logs"),
    ("app.api.v1.endpoints.reporting", "Reporting"),
    ("app.api.v1.endpoints.integrations", "Integrations"),
    ("app.api.v1.endpoints.auth", "Auth"),
]

success_count = 0
for module_name, description in imports:
    if test_import(module_name, description):
        success_count += 1

print(f"\nImport summary: {success_count}/{len(imports)} successful")
