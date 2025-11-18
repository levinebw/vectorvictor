"""
SQL Injection Vulnerability Demo
OWASP A03:2021 - Injection
"""
import sqlite3

def get_user_by_username(username):
    """Vulnerable to SQL injection - never do this!"""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Create a sample table
    cursor.execute('''CREATE TABLE users
                     (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123', 'admin@example.com')")
    cursor.execute("INSERT INTO users VALUES (2, 'user', 'password', 'user@example.com')")

    # VULNERABLE: String concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    print(f"Executing query: {query}")

    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

def login_user(username, password):
    """Another SQL injection vulnerability"""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE users
                     (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")

    # VULNERABLE: Direct string formatting in SQL
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result is not None

def search_products(product_name):
    """Yet another SQL injection point"""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE products
                     (id INTEGER PRIMARY KEY, name TEXT, price REAL)''')
    cursor.execute("INSERT INTO products VALUES (1, 'Laptop', 999.99)")

    # VULNERABLE: Using % formatting
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % product_name
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()
    return results

if __name__ == "__main__":
    # Example of exploitation:
    # get_user_by_username("admin' OR '1'='1")
    print(get_user_by_username("admin"))
