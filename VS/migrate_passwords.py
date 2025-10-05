#!/usr/bin/env python3
"""
Password Migration Script
Migrates existing plaintext passwords to hashed versions
"""
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

def migrate_passwords():
    """Migrate all plaintext passwords to hashed versions"""
    print("Starting password migration...")
    
    # Connect to database
    conn = sqlite3.connect('vulnerabilities.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Get all users
        cursor.execute("SELECT username, password_hash FROM users")
        users = cursor.fetchall()
        
        migrated_count = 0
        
        for user in users:
            username = user['username']
            current_password = user['password_hash']
            
            # Check if the password is already hashed (Werkzeug hashes start with specific patterns)
            # If it doesn't start with pbkdf2, scrypt, or argon2, it's likely plaintext
            if not (current_password.startswith('pbkdf2:') or 
                   current_password.startswith('scrypt:') or 
                   current_password.startswith('argon2:')):
                
                print(f"Migrating password for user: {username}")
                
                # Hash the plaintext password
                hashed_password = generate_password_hash(current_password)
                
                # Update the database
                cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", 
                             (hashed_password, username))
                
                migrated_count += 1
            else:
                print(f"Password for user '{username}' is already hashed, skipping...")
        
        # Commit changes
        conn.commit()
        print(f"Password migration completed! Migrated {migrated_count} passwords.")
        
        # Verify the migration
        print("\nVerifying migration...")
        cursor.execute("SELECT username, password_hash FROM users")
        users = cursor.fetchall()
        
        for user in users:
            password_hash = user['password_hash']
            if password_hash.startswith('pbkdf2:') or password_hash.startswith('scrypt:') or password_hash.startswith('argon2:'):
                print(f"✓ User '{user['username']}' has properly hashed password")
            else:
                print(f"✗ User '{user['username']}' still has plaintext password!")
                
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    migrate_passwords()