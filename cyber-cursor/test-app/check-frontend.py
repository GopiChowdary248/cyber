#!/usr/bin/env python3
"""
Quick Frontend Accessibility Check
Verifies that the frontend is running and accessible.
"""

import requests
import time

def check_frontend():
    """Check if frontend is accessible"""
    
    frontend_url = "http://localhost:3000"
    
    print("🔍 Checking Frontend Accessibility")
    print(f"🌐 URL: {frontend_url}")
    print("-" * 50)
    
    try:
        # Test frontend accessibility
        response = requests.get(frontend_url, timeout=10)
        
        if response.status_code == 200:
            print("✅ Frontend is accessible!")
            print(f"📄 Status Code: {response.status_code}")
            print(f"📏 Content Length: {len(response.content)} bytes")
            
            # Check if it's a React app (should contain React-related content)
            content = response.text.lower()
            if 'react' in content or 'cybershield' in content or 'login' in content:
                print("✅ Appears to be the CyberShield application")
            else:
                print("⚠️  Content doesn't seem to match expected app")
                
        else:
            print(f"❌ Frontend returned status code: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to frontend - is it running?")
        print("💡 Try: docker-compose up -d")
        
    except requests.exceptions.Timeout:
        print("❌ Frontend request timed out")
        
    except Exception as e:
        print(f"❌ Error checking frontend: {str(e)}")
    
    print("\n" + "=" * 50)
    print("🎯 Ready for Manual Testing!")
    print("📋 Use the MANUAL_UI_TESTING_GUIDE.md for detailed testing steps")
    print("🔑 Demo accounts available:")
    print("   • admin@cybershield.com / password")
    print("   • analyst@cybershield.com / password") 
    print("   • user@cybershield.com / password")
    print("=" * 50)

if __name__ == "__main__":
    check_frontend() 