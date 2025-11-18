"""
Cross-Site Scripting (XSS) Vulnerability Demo
OWASP A03:2021 - Injection
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    """Reflected XSS vulnerability"""
    query = request.args.get('q', '')

    # VULNERABLE: Directly embedding user input in HTML
    html = f"""
    <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {query}</p>
        </body>
    </html>
    """
    return html

@app.route('/comment', methods=['POST'])
def post_comment():
    """Stored XSS vulnerability"""
    comment = request.form.get('comment', '')

    # VULNERABLE: Storing and displaying unsanitized user input
    with open('comments.txt', 'a') as f:
        f.write(comment + '\n')

    return f"<html><body><h2>Your comment:</h2><p>{comment}</p></body></html>"

@app.route('/profile')
def profile():
    """DOM-based XSS vulnerability"""
    username = request.args.get('username', 'Guest')

    # VULNERABLE: User input directly in JavaScript
    html = f"""
    <html>
        <body>
            <h1>User Profile</h1>
            <script>
                var username = "{username}";
                document.write("<p>Welcome, " + username + "!</p>");
            </script>
        </body>
    </html>
    """
    return html

@app.route('/error')
def error_page():
    """XSS in error messages"""
    error_msg = request.args.get('error', '')

    # VULNERABLE: Unescaped error message
    return render_template_string(f"""
    <html>
        <body>
            <h1>Error</h1>
            <div class="error">{error_msg}</div>
        </body>
    </html>
    """)

if __name__ == '__main__':
    # Example exploitation:
    # /search?q=<script>alert('XSS')</script>
    # /profile?username=<img src=x onerror=alert('XSS')>
    app.run(debug=True)
