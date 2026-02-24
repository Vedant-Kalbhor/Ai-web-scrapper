import os
import sqlite3
from flask import Flask, request, render_template_string, session, g

app = Flask(__name__)
app.secret_key = 'super-secret-key-that-is-easy-to-guess' # Broken Authentication/Sensitive Data Exposure

# Database setup
DATABASE = 'test_vulnerable.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.before_request
def init_db():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, secret_info TEXT)')
    db.execute('INSERT OR IGNORE INTO users (id, username, password, secret_info) VALUES (1, "admin", "admin123", "THIS_IS_THE_FLAG_SQLI")')
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- VULNERABLE ROUTES ---

@app.route('/')
def index():
    return """
    <html>
    <head><title>Vulnerable Target App</title></head>
    <body style="font-family: sans-serif; max-width: 800px; margin: 40px auto; line-height: 1.6;">
        <h1>Vulnerable Target App v1.0</h1>
        <p>This app is designed for security testing. <b>DO NOT DEPLOY IN PRODUCTION.</b></p>
        <div style="background: #f4f4f4; padding: 20px; border-radius: 8px;">
            <h3>Quick Links:</h3>
            <ul>
                <li><a href="/search?query=test">Search (XSS)</a></li>
                <li><a href="/login">Admin Login (SQLi)</a></li>
                <li><a href="/user/1">View Profile (IDOR)</a></li>
                <li><a href="/debug">Debug Info (Misconfig)</a></li>
            </ul>
        </div>
    </body>
    </html>
    """

# 1. Reflected Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    query = request.args.get('query', '')
    # VULNERABILITY: Directly rendering user input without escaping
    template = f"""
    <html>
    <body style="font-family: sans-serif; max-width: 800px; margin: 40px auto;">
        <h2>Search Results</h2>
        <p>You searched for: {query}</p>
        <a href="/">Back</a>
    </body>
    </html>
    """
    return render_template_string(template)

# 2. SQL Injection (SQLi)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        # VULNERABILITY: Using raw string formatting for SQL queries
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor = db.execute(query)
            user = cursor.fetchone()
            
            if user:
                return f"<h3>Welcome, {user[1]}!</h3><p>Secret: {user[3]}</p><a href='/'>Back</a>"
            else:
                return "<h3>Login Failed!</h3><a href='/login'>Try Again</a>"
        except Exception as e:
            return f"<h3>Database Error!</h3><p>{str(e)}</p><a href='/login'>Back</a>"
            
    return """
    <html>
    <body style="font-family: sans-serif; max-width: 800px; margin: 40px auto;">
        <h2>Login</h2>
        <form method="post">
            <div>Username: <input name="username"></div>
            <div style="margin-top:10px;">Password: <input name="password" type="password"></div>
            <button type="submit" style="margin-top:10px;">Login</button>
        </form>
    </body>
    </html>
    """

# 3. Security Misconfiguration (Information Leakage)
@app.route('/debug')
def debug_info():
    # VULNERABILITY: Exposing system environment and metadata
    import platform
    info = {
        "os": platform.system(),
        "release": platform.release(),
        "env": dict(os.environ),
        "app_root": os.getcwd()
    }
    return str(info)

# 4. Insecure Direct Object Reference (IDOR)
@app.route('/user/<int:user_id>')
def view_user(user_id):
    # VULNERABILITY: No authorization check, any user can view any ID
    db = get_db()
    user = db.execute(f"SELECT id, username, secret_info FROM users WHERE id = {user_id}").fetchone()
    if user:
        return f"<h3>Profile for User {user[0]}</h3><p>Username: {user[1]}</p><p>Private Info: {user[2]}</p>"
    return "User not found", 404

if __name__ == '__main__':
    # VULNERABILITY: Running with debug mode enabled
    app.run(port=5001, debug=True)
