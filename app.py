import os
from flask import Flask, render_template, session, request, jsonify, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import psycopg2
import psycopg2.extras
import json
from namecheap_client import NamecheapClient

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db_connection():
    """Establishes a connection to the database."""
    conn = psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        database=os.environ.get("DB_NAME", "gbot_web_app"),
        user=os.environ.get("DB_USER", "user"),
        password=os.environ.get("DB_PASSWORD", "password"))
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('SELECT id, account_name FROM accounts')
    accounts = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('dashboard.html', accounts=accounts)

@app.route('/users')
@login_required
def users():
    return render_template('users.html')

@app.route('/whitelist')
@login_required
def whitelist():
    return render_template('whitelist.html')

@app.route('/emergency_access')
def emergency_access():
    return render_template('emergency_access.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    return render_template('settings.html')


# --- API ROUTES ---

@app.route('/api/dns/namecheap/settings', methods=['GET', 'POST'])
@login_required
def namecheap_settings():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST':
        settings = request.json
        cur.execute(
            """INSERT INTO settings (key, value) VALUES (%s, %s)
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;""",
            ('namecheap_api_settings', json.dumps(settings))
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Settings saved successfully!'})
    else:
        cur.execute("SELECT value FROM settings WHERE key = 'namecheap_api_settings'")
        settings_row = cur.fetchone()
        cur.close()
        conn.close()
        if settings_row and settings_row['value']:
            return jsonify({'success': True, 'settings': json.loads(settings_row['value'])})
        else:
            return jsonify({'success': False, 'settings': {}})

@app.route('/api/dns/namecheap/domains')
@login_required
def get_namecheap_domains():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT value FROM settings WHERE key = 'namecheap_api_settings'")
    settings_row = cur.fetchone()
    cur.close()
    conn.close()

    if not (settings_row and settings_row['value']):
        return jsonify({'success': False, 'error': 'Namecheap API settings are not configured.'}), 400

    settings = json.loads(settings_row['value'])
    
    try:
        client = NamecheapClient(
            api_user=settings.get('api_user'),
            api_key=settings.get('api_key'),
            username=settings.get('username'),
            client_ip=settings.get('client_ip'),
            sandbox=False
        )
        
        domain_list = client.get_domain_list() 

        domains = [{
            'domain': d.get('Name'),
            'expires': d.get('Expires'),
            'isOurDNS': d.get('IsOurDNS')
        } for d in domain_list]
        return jsonify({'success': True, 'domains': domains})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Error communicating with Namecheap: {e}"}), 500

# Preserve all other existing API routes...

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
