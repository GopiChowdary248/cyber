#!/usr/bin/env python3
"""
Test JWT token decoding
"""

import jwt
import json

# Token from the previous test
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkBjeWJlcnNoaWVsZC5jb20iLCJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGN5YmVyc2hpZWxkLmNvbSIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc1NDEzNTcwNiwidHlwZSI6ImFjY2VzcyJ9.o10UksBwmGpOEmB3kfPoO4Qxv3eBbqlaWmOC_sUlBvs"

# Secret key from security.py
SECRET_KEY = "your-super-secret-key-change-in-production"
ALGORITHM = "HS256"

try:
    # Decode the token
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    print("Token decoded successfully!")
    print("Payload:")
    print(json.dumps(payload, indent=2))
    
    # Check if all required fields are present
    required_fields = ["sub", "user_id", "email", "role", "type"]
    missing_fields = [field for field in required_fields if field not in payload]
    
    if missing_fields:
        print(f"Missing fields: {missing_fields}")
    else:
        print("All required fields are present!")
        
except Exception as e:
    print(f"Error decoding token: {e}") 