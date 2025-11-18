"""
Miscellaneous Security Vulnerabilities
Collection of additional OWASP Top 10 vulnerabilities
"""
import re
import logging
from flask import Flask, request, redirect

app = Flask(__name__)

# VULNERABLE: Debug mode enabled
app.config['DEBUG'] = True

# VULNERABLE: Sensitive data in logs
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/redirect')
def open_redirect():
    """VULNERABLE: Open redirect"""
    # OWASP A01:2021 - Broken Access Control
    target = request.args.get('url')

    # VULNERABLE: No whitelist validation
    return redirect(target)

@app.route('/api/user/<user_id>')
def get_user_data(user_id):
    """VULNERABLE: Insecure Direct Object Reference (IDOR)"""
    # OWASP A01:2021 - Broken Access Control

    # VULNERABLE: No authorization check
    # Any user can access any other user's data
    user_data = {
        'id': user_id,
        'email': f'user{user_id}@example.com',
        'ssn': '123-45-6789',  # VULNERABLE: Sensitive data exposure
        'credit_card': '4532-1234-5678-9010'
    }

    # VULNERABLE: Logging sensitive data
    logger.info(f"Accessed user data: {user_data}")

    return user_data

@app.route('/regex_check')
def regex_dos():
    """VULNERABLE: Regular Expression Denial of Service (ReDoS)"""
    # OWASP A06:2021 - Vulnerable and Outdated Components
    user_input = request.args.get('input', '')

    # VULNERABLE: Catastrophic backtracking pattern
    pattern = r'^(a+)+$'
    # Try with input like 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!'

    try:
        if re.match(pattern, user_input):
            return 'Match found'
        return 'No match'
    except:
        return 'Error', 500

@app.route('/mass_assignment', methods=['POST'])
def update_user():
    """VULNERABLE: Mass assignment vulnerability"""
    # OWASP A01:2021 - Broken Access Control

    user_data = request.json

    # VULNERABLE: Directly using all user input
    # Attacker can set 'is_admin': True
    user = {
        'username': user_data.get('username'),
        'email': user_data.get('email'),
        'is_admin': user_data.get('is_admin', False),  # VULNERABLE
        'role': user_data.get('role', 'user')  # VULNERABLE
    }

    return user

@app.route('/search')
def insecure_search():
    """VULNERABLE: Information disclosure"""
    query = request.args.get('q')

    # VULNERABLE: Exposing internal errors
    try:
        results = perform_search(query)
        return results
    except Exception as e:
        # VULNERABLE: Exposing stack trace
        import traceback
        return traceback.format_exc(), 500

def perform_search(query):
    """Helper function for search"""
    # Simulated search
    return [{'title': 'Result 1'}, {'title': 'Result 2'}]

@app.route('/cors_test')
def cors_misconfiguration():
    """VULNERABLE: CORS misconfiguration"""
    # OWASP A05:2021 - Security Misconfiguration

    from flask import make_response

    response = make_response({'data': 'sensitive information'})

    # VULNERABLE: Allow all origins
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response

def process_payment(amount, account):
    """VULNERABLE: Race condition"""
    # OWASP A04:2021 - Insecure Design

    # VULNERABLE: No locking mechanism
    # Check balance
    balance = get_balance(account)

    if balance >= amount:
        # Time gap - race condition window
        # Another transaction could occur here
        deduct_balance(account, amount)
        return True

    return False

def get_balance(account):
    """Simulated balance check"""
    return 1000

def deduct_balance(account, amount):
    """Simulated balance deduction"""
    pass

@app.route('/unsafe_eval')
def unsafe_eval():
    """VULNERABLE: Code injection via eval"""
    # OWASP A03:2021 - Injection

    expression = request.args.get('expr')

    # VULNERABLE: Using eval on user input
    try:
        result = eval(expression)
        return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/template_injection')
def template_injection():
    """VULNERABLE: Server-Side Template Injection (SSTI)"""
    # OWASP A03:2021 - Injection

    from flask import render_template_string

    name = request.args.get('name', 'Guest')

    # VULNERABLE: User input directly in template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# VULNERABLE: Insufficient logging
@app.route('/admin/delete_user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """VULNERABLE: No security event logging"""
    # OWASP A09:2021 - Security Logging and Monitoring Failures

    # VULNERABLE: Critical action with no audit log
    # No logging of who deleted the user, when, or why
    # No alerting mechanism

    # Delete user logic here
    return {'status': 'deleted'}

@app.route('/unvalidated_redirect')
def unvalidated_redirect():
    """VULNERABLE: Unvalidated redirect and forward"""
    # OWASP A01:2021 - Broken Access Control

    next_page = request.args.get('next')

    # VULNERABLE: No validation of redirect target
    # Could be used for phishing
    return redirect(next_page)

def process_xml_with_billion_laughs(xml_data):
    """VULNERABLE: XML bomb / Billion Laughs attack"""
    # OWASP A05:2021 - Security Misconfiguration

    import xml.etree.ElementTree as ET

    # VULNERABLE: No entity expansion limits
    # Can cause DoS via XML entity expansion
    try:
        root = ET.fromstring(xml_data)
        return root
    except:
        return None

# VULNERABLE: Using pickle for session storage
import pickle
import os

SESSION_DIR = '/tmp/sessions/'

def save_session(session_id, data):
    """VULNERABLE: Insecure session storage"""
    # OWASP A08:2021 - Software and Data Integrity Failures

    # VULNERABLE: Storing sessions as pickle files
    session_file = os.path.join(SESSION_DIR, session_id)

    with open(session_file, 'wb') as f:
        pickle.dump(data, f)

def load_session(session_id):
    """VULNERABLE: Loading untrusted pickle data"""
    session_file = os.path.join(SESSION_DIR, session_id)

    if os.path.exists(session_file):
        with open(session_file, 'rb') as f:
            # VULNERABLE: Unpickling user-controlled data
            return pickle.load(f)

    return None

# VULNERABLE: Information disclosure in comments
"""
TODO: Remove default admin credentials before production
Username: admin
Password: Admin123!

Database connection:
Host: prod-db.company.internal
Port: 5432
"""

if __name__ == '__main__':
    # VULNERABLE: Running with debug mode and on all interfaces
    app.run(host='0.0.0.0', debug=True, port=5000)
