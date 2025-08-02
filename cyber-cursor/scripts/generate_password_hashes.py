#!/usr/bin/env python3
"""
Generate bcrypt password hashes for sample users
"""

import bcrypt

def generate_hash(password):
    """Generate bcrypt hash for password"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def main():
    """Generate hashes for sample passwords"""
    passwords = {
        'admin123': 'admin@cybershield.com',
        'analyst123': 'analyst@cybershield.com', 
        'user123': 'user@cybershield.com',
        'demo123': 'demo@cybershield.com'
    }
    
    print("Generated bcrypt password hashes:")
    print()
    
    for password, email in passwords.items():
        hashed = generate_hash(password)
        print(f"Email: {email}")
        print(f"Password: {password}")
        print(f"Hash: {hashed}")
        print()
    
    print("SQL UPDATE statements:")
    print()
    
    for password, email in passwords.items():
        hashed = generate_hash(password)
        print(f"UPDATE users SET hashed_password = '{hashed}' WHERE email = '{email}';")

if __name__ == "__main__":
    main() 