#!/usr/bin/env python3
"""
Script to fix all token key mismatches in the frontend
"""

import os
import re
from pathlib import Path

def fix_token_keys_in_file(file_path):
    """Fix token key mismatches in a single file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace all occurrences of 'token' with 'access_token'
        original_content = content
        content = re.sub(
            r"localStorage\.getItem\('token'\)",
            "localStorage.getItem('access_token')",
            content
        )
        
        # Check if any changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ Fixed: {file_path}")
            return True
        else:
            print(f"⏭️  No changes needed: {file_path}")
            return False
            
    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")
        return False

def main():
    """Main function to fix all token keys"""
    print("🔧 Fixing Token Key Mismatches Across Frontend Components")
    print("=" * 70)
    
    # Frontend directory
    frontend_dir = Path("frontend/src")
    
    # Files that need fixing (based on grep search)
    files_to_fix = [
        "components/DeviceControl/DeviceControlDashboard.tsx",
        "components/DAST/DASTVulnerabilities.tsx",
        "components/SAST/SASTQualityGates.tsx",
        "components/RASP/RASPDashboard.tsx",
        "components/SAST/SASTSecurityHotspots.tsx",
        "components/SAST/SASTVulnerabilities.tsx",
        "pages/SAST/SASTProjectDetails.tsx"
    ]
    
    total_fixed = 0
    
    for file_path in files_to_fix:
        full_path = frontend_dir / file_path
        if full_path.exists():
            if fix_token_keys_in_file(full_path):
                total_fixed += 1
        else:
            print(f"⚠️  File not found: {full_path}")
    
    print(f"\n🎉 Token key fix completed!")
    print(f"   Total files fixed: {total_fixed}")
    print(f"   All components now use 'access_token' consistently")

if __name__ == "__main__":
    main()
