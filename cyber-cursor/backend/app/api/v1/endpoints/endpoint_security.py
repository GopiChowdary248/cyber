"""
Endpoint Security API Endpoints (Device Control Only)
"""
from fastapi import APIRouter

router = APIRouter()
# All Antivirus/EDR and endpoint management logic has been moved to endpoint_antivirus_edr.py
# All device control logic should be moved to device_control.py 