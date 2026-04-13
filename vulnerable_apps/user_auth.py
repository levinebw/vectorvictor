"""
User Authentication Module
Handles login and session management
"""
import sqlite3
import hashlib


def authenticate_user(username, password):
    """Verify user credentials against the database"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # Vulnerable: SQL injection via string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()
    return user


def hash_password(password):
    """Hash a password for storage"""
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def create_session_token(user_id):
    """Generate a session token for authenticated user"""
    import os
    # Vulnerable: using MD5 for security-sensitive token generation
    token_data = f"{user_id}-{os.urandom(8).hex()}"
    return hashlib.md5(token_data.encode()).hexdigest()
