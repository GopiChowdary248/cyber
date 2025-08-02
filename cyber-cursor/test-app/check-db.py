#!/usr/bin/env python3
"""
Simple script to check database for users
"""

import asyncio
import asyncpg

async def check_users():
    try:
        # Connect to database
        conn = await asyncpg.connect(
            host='localhost',
            port=5432,
            user='cybershield_user',
            password='cybershield_password',
            database='cybershield'
        )
        
        # Query users
        users = await conn.fetch('SELECT email, role FROM users')
        
        print(f"Found {len(users)} users:")
        for user in users:
            print(f"  - {user['email']} (Role: {user['role']})")
        
        await conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(check_users()) 