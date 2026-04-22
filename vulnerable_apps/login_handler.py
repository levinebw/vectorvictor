"""
Login Handler — Web endpoint for user authentication
Exposes the authentication module over HTTP
"""
from flask import Flask, request, jsonify
import sqlite3
import hashlib

app = Flask(__name__)


@app.route('/login', methods=['POST'])
def login():
    """Handle login form submission"""
    username = request.form.get('username')
    password = request.form.get('password')

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    # Vulnerable: user-controlled input flows directly into SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({'status': 'success', 'user': user[0]})
    return jsonify({'status': 'unauthorized'}), 401


@app.route('/search', methods=['GET'])
def search_users():
    """Search users by name"""
    name = request.args.get('name', '')

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    # Vulnerable: query parameter unsanitized in SQL
    cursor.execute("SELECT username, email FROM users WHERE username LIKE '%" + name + "%'")

    results = cursor.fetchall()
    conn.close()
    return jsonify({'results': results})


@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    username = request.form.get('username')
    password = request.form.get('password')

    # Vulnerable: MD5 is cryptographically broken for password storage
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
    conn.commit()
    conn.close()

    return jsonify({'status': 'created'}), 201


if __name__ == '__main__':
    app.run(debug=True)
