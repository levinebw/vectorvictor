"""
Broken Authentication Vulnerability Demo
OWASP A07:2021 - Identification and Authentication Failures
"""
from flask import Flask, request, session, make_response
import hashlib

app = Flask(__name__)
app.secret_key = 'insecure_secret_key'  # VULNERABLE: Weak secret key

# Simulated user database
users_db = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user': {'password': 'password', 'role': 'user'}
}

@app.route('/login', methods=['POST'])
def login():
    """VULNERABLE: Multiple authentication issues"""
    username = request.form.get('username')
    password = request.form.get('password')

    # VULNERABLE: No rate limiting on login attempts
    # VULNERABLE: No account lockout mechanism

    if username in users_db:
        # VULNERABLE: Plain text password comparison
        if users_db[username]['password'] == password:
            session['username'] = username
            session['role'] = users_db[username]['role']

            # VULNERABLE: Predictable session token
            session_token = hashlib.md5(username.encode()).hexdigest()

            response = make_response('Login successful')
            # VULNERABLE: Session cookie without secure flags
            response.set_cookie('session_id', session_token)
            return response

    return 'Invalid credentials', 401

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """VULNERABLE: Insecure password reset"""
    email = request.form.get('email')

    # VULNERABLE: No verification of password reset token
    # VULNERABLE: Predictable reset token
    reset_token = hashlib.md5(email.encode()).hexdigest()

    return f'Reset token: {reset_token}'

def verify_user(username, password):
    """VULNERABLE: Weak password hashing"""
    # VULNERABLE: Using MD5 for password hashing
    hashed_password = hashlib.md5(password.encode()).hexdigest()

    # Check against database
    return True

@app.route('/change_password', methods=['POST'])
def change_password():
    """VULNERABLE: No old password verification"""
    username = request.form.get('username')
    new_password = request.form.get('new_password')

    # VULNERABLE: No verification of old password
    # VULNERABLE: No password strength requirements
    if username in users_db:
        users_db[username]['password'] = new_password
        return 'Password changed'

    return 'User not found', 404

@app.route('/admin')
def admin_panel():
    """VULNERABLE: Weak session management"""
    # VULNERABLE: Only checking if username exists in session
    if 'username' in session:
        # VULNERABLE: No re-authentication for sensitive operations
        return 'Admin panel access granted'

    return 'Unauthorized', 401

def generate_session_token(user_id):
    """VULNERABLE: Predictable session token generation"""
    # VULNERABLE: Weak token generation
    import time
    token = hashlib.md5(f"{user_id}{time.time()}".encode()).hexdigest()
    return token

@app.route('/auto_login')
def auto_login():
    """VULNERABLE: Automatic login via URL parameter"""
    # VULNERABLE: Authentication via GET parameter
    user_id = request.args.get('user_id')

    if user_id:
        session['user_id'] = user_id
        return 'Auto-login successful'

    return 'Failed', 400

class SessionManager:
    """VULNERABLE: Insecure session management"""
    def __init__(self):
        self.sessions = {}

    def create_session(self, username):
        # VULNERABLE: Session never expires
        # VULNERABLE: No session invalidation on logout
        session_id = str(hash(username))
        self.sessions[session_id] = username
        return session_id

    def get_user(self, session_id):
        # VULNERABLE: No session validation
        return self.sessions.get(session_id)

# VULNERABLE: No CSRF protection
@app.route('/transfer_funds', methods=['POST'])
def transfer_funds():
    """VULNERABLE: Missing CSRF protection"""
    if 'username' in session:
        amount = request.form.get('amount')
        to_account = request.form.get('to_account')

        # Process transfer without CSRF token
        return f'Transferred {amount} to {to_account}'

    return 'Unauthorized', 401

if __name__ == '__main__':
    # VULNERABLE: Debug mode in production
    app.run(debug=True)
