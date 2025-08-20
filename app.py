from flask import Flask, request, render_template_string, session, redirect, url_for, g
import sqlite3
import base64
import re

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session'
app.config['DEBUG'] = True

# Database setup
def get_db():
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = sqlite3.connect(':memory:', check_same_thread=False)
        g.sqlite_db.row_factory = sqlite3.Row
        init_db(g.sqlite_db)
    return g.sqlite_db

def init_db(conn):
    c = conn.cursor()
    
    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        is_admin BOOLEAN,
        email TEXT
    )''')
    
    c.execute('''CREATE TABLE secrets (
        id INTEGER PRIMARY KEY,
        secret_text TEXT
    )''')
    
    # Store passwords in plaintext (Base64 encoded for slight obfuscation)
    users = [
        (1, 'whisper', base64.b64encode('Admin@Secure123!'.encode()).decode(), 1, 'whisper@company.com'),
        (2, 'alicia', base64.b64encode('Alice$Password456'.encode()).decode(), 0, 'alice@company.com'),
        (3, 'bobey', base64.b64encode('BobsVerySecurePass'.encode()).decode(), 0, 'bob@company.com')
    ]
    
    c.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?)', users)
    c.execute("INSERT INTO secrets VALUES (1, 'flag{r34l_cr3d3nt14ls_us3d}')")
    conn.commit()

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

# HTML template
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Employee Portal Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .login-form { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
        .form-group { margin-bottom: 15px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; }
        input[type="submit"] { background: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
        .warning { color: orange; }
        pre { background: #f0f0f0; padding: 10px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    </style>
</head>
<body>
    <h1>Employee Portal Login</h1>
    {% if message %}
        <div class="{{ 'success' if 'Welcome' in message else 'error' if 'Error' in message else 'warning' if 'Authentication' in message else 'error' }}">{{ message }}</div>
    {% endif %}
    
    <div class="login-form">
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <input type="submit" value="Login">
        </form>
    </div>
    
    {% if show_data_extraction %}
    <div class="data-extraction">
        <h2>Data Extraction Results</h2>
        <pre>{{ extracted_data }}</pre>
        {% if not authentication_message %}
            <p>Now use these credentials to login properly!</p>
        {% endif %}
    </div>
    {% endif %}
    
    {% if logged_in %}
        <div class="user-info">
            {% if is_admin %}
                <h2>Admin Dashboard</h2>
                <p>Secret flag: <strong>{{ secret_text }}</strong></p>
            {% else %}
                <h2>User Dashboard</h2>
                <p>Welcome {{ username }}! You don't have admin privileges.</p>
            {% endif %}
            <a href="/logout">Logout</a>
        </div>
    {% endif %}
    
    <div class="challenge-info" style="margin-top: 30px;">
        <h2>Challenge Instructions</h2>
        <ol>
            <li>Login properly with the admin credentials</li>
            <li>Access the secret flag from the admin dashboard</li>
        </ol>
        <p><strong>Note:</strong> Some tables require proper authentication to access!</p>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    secret_text = None
    if session.get('logged_in'):
        db = get_db()
        if session.get('is_admin'):
            secret_text = db.execute("SELECT secret_text FROM secrets WHERE id = 1").fetchone()["secret_text"]
    return render_template_string(LOGIN_TEMPLATE, 
                               logged_in=session.get('logged_in'),
                               is_admin=session.get('is_admin'),
                               username=session.get('username'),
                               secret_text=secret_text,
                               message=session.pop('message', None),
                               show_data_extraction=session.get('show_data_extraction', False),
                               extracted_data=session.pop('extracted_data', None),
                               authentication_message=session.pop('authentication_message', False))

def is_sqli_attempt(input_str):
    """Detect SQL injection patterns"""
    patterns = [
        r'\bOR\b.*=.*',
        r'\bAND\b.*=.*',
        r'\bUNION\b.*\bSELECT\b',
        r'--|\/\*',
        r'\bEXEC\b|\bEXECUTE\b',
        r'\bDROP\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b'
    ]
    return any(re.search(pattern, input_str, re.IGNORECASE) for pattern in patterns)

def handle_union_query(query, db):
    """Execute UNION queries and return appropriate results"""
    try:
        # Check if user is trying to access secrets table directly
        if re.search(r'\bsecrets\b', query, re.IGNORECASE):
            return None, "Authentication required: You need proper admin credentials to access the secrets table."
        
        # Check if user is exploring database structure
        if re.search(r'\bsqlite_master\b', query, re.IGNORECASE) or re.search(r'\binformation_schema\b', query, re.IGNORECASE):
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            table_info = []
            for table in tables:
                table_info.append({"table_name": table["name"], "message": "Table exists"})
            return table_info, None
        
        # Execute normal UNION queries
        results = db.execute(query).fetchall()
        extracted = []
        for row in results:
            if isinstance(row, sqlite3.Row):
                row_dict = dict(row)
                extracted.append(row_dict)
            else:
                extracted.append(row)
        return extracted, None
        
    except sqlite3.Error as e:
        # If it's a database exploration query, return table info
        if "sqlite_master" in query or "information_schema" in query:
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            table_info = []
            for table in tables:
                table_info.append({"table_name": table["name"], "message": "Table exists"})
            return table_info, None
        raise e

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Reset session flags
    session['show_data_extraction'] = False
    session['extracted_data'] = None
    session['authentication_message'] = False
    
    # Check for SQLi attempts in login
    if is_sqli_attempt(username) or is_sqli_attempt(password):
        # Special handling for UNION SELECT data extraction
        if 'UNION' in username.upper() or 'UNION' in password.upper():
            try:
                db = get_db()
                # Vulnerable query for data extraction
                query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                
                # Handle the UNION query
                extracted, auth_message = handle_union_query(query, db)
                
                if auth_message:
                    session['show_data_extraction'] = True
                    session['extracted_data'] = auth_message
                    session['authentication_message'] = True
                    session['message'] = "Access restricted!"
                    return redirect(url_for('home'))
                
                if extracted:
                    session['show_data_extraction'] = True
                    session['extracted_data'] = "\n".join(str(item) for item in extracted)
                    session['message'] = "Data extracted successfully! Now login properly with the credentials."
                    return redirect(url_for('home'))
            
            except sqlite3.Error as e:
                session['message'] = f"Extraction error: {str(e)}"
                return redirect(url_for('home'))
        
        # Block all other SQLi login attempts
        session['message'] = "‘1=1’? Cute. But this house only opens for those who know what’s inside the pantry..."
        return redirect(url_for('home'))
    
    # Normal login processing
    try:
        db = get_db()
        # Encode the provided password for comparison
        encoded_password = base64.b64encode(password.encode()).decode()
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        user = db.execute(query, (username, encoded_password)).fetchone()
        
        if user:
            session['logged_in'] = True
            session['username'] = user["username"]
            session['is_admin'] = bool(user["is_admin"])
            session['message'] = f"Welcome, {user['username']}!"
        else:
            session['message'] = "Invalid credentials!"
    
    except sqlite3.Error as e:
        session['message'] = "Login error occurred"
    
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    session['message'] = "You have been logged out."
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
