#!/usr/bin/env python3
"""
Update the admin user's password without deleting the user.

Sets admin@cybershield.com password to 'admin123'.
"""

import asyncio
import asyncpg
import sys
import os
from pathlib import Path

# Ensure backend package is importable
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.security import get_password_hash  # type: ignore


async def update_admin_password():
    DB_CONFIG = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "user": os.getenv("DB_USER", "cybershield_user"),
        "password": os.getenv("DB_PASSWORD", "cybershield_password"),
        "database": os.getenv("DB_NAME", "cybershield"),
    }

    email = os.getenv("ADMIN_EMAIL", "admin@cybershield.com")
    new_password = os.getenv("ADMIN_NEW_PASSWORD", "admin123")

    print("Connecting to PostgreSQL to update admin password...")
    conn = await asyncpg.connect(**DB_CONFIG)
    try:
        # Check if user exists
        user = await conn.fetchrow("SELECT id, email FROM users WHERE email=$1", email)
        if not user:
            print(f"User with email {email} not found. Aborting.")
            return False

        hashed = get_password_hash(new_password)
        await conn.execute(
            "UPDATE users SET hashed_password=$1, updated_at=NOW() WHERE email=$2",
            hashed,
            email,
        )
        print(f"Updated password for {email} successfully.")
        return True
    finally:
        await conn.close()


if __name__ == "__main__":
    try:
        ok = asyncio.run(update_admin_password())
        sys.exit(0 if ok else 1)
    except Exception as e:
        print(f"Failed to update admin password: {e}")
        sys.exit(1)


