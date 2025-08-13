#!/usr/bin/env python3
import sqlite3

try:
    conn = sqlite3.connect('cybershield.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table"')
    tables = cursor.fetchall()
    
    print('Database tables:')
    for table in tables:
        print(f'  - {table[0]}')
    
    # Check if sast_projects table exists
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="sast_projects"')
    sast_projects = cursor.fetchone()
    if sast_projects:
        print(f'\nSAST projects table exists: {sast_projects[0]}')
        
        # Check table structure
        cursor.execute('PRAGMA table_info(sast_projects)')
        columns = cursor.fetchall()
        print('\nSAST projects table structure:')
        for col in columns:
            print(f'  - {col[1]} ({col[2]})')
    else:
        print('\nSAST projects table does not exist!')
    
    conn.close()
    
except Exception as e:
    print(f'Error: {e}')
