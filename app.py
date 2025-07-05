from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta, timezone
import json
import csv
from functools import wraps
import uuid
import secrets
import string
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# Load configuration
def load_config():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Default configuration if file doesn't exist
        return {
            "flask": {
                "secret_key": "your-secret-key-change-this-in-production",
                "env": "development",
                "database_folder": "user_databases"
            },
            "registration": {
                "enabled": True,
                "rate_limit": "5 per minute",
                "require_2fa": True,
                "message_when_disabled": "Registration is currently disabled. Please contact the administrator."
            },
            "security": {
                "min_processing_time": 0.1,
                "csrf_protection": True
            }
        }

config = load_config()

# Configure Flask app from config
app.secret_key = os.environ.get('FLASK_SECRET_KEY', config['flask']['secret_key'])
app.config['DATABASE_FOLDER'] = os.environ.get('DATABASE_FOLDER', config['flask']['database_folder'])
app.config['WTF_CSRF_ENABLED'] = config['security']['csrf_protection']
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Ensure database folder exists
os.makedirs(app.config['DATABASE_FOLDER'], exist_ok=True)

# Initialize main database on app startup
def init_main_db():
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            totp_enabled BOOLEAN DEFAULT 0,
            backup_codes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Migration: Add backup_codes column if it doesn't exist
    try:
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'backup_codes' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN backup_codes TEXT')
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()

# Initialize database on import
init_main_db()


# Individual user database setup
def init_user_db(user_id):
    db_path = os.path.join(app.config['DATABASE_FOLDER'], f'user_{user_id}.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            hourly_rate REAL DEFAULT 0.0,
            billing_increment TEXT DEFAULT 'minute',
            archived BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS time_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            description TEXT,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            duration_minutes INTEGER,
            earnings REAL DEFAULT 0.0,
            invoiced BOOLEAN DEFAULT 0,
            billing_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (id)
        )
    ''')
    
    # Migrate existing database if needed
    migrate_user_db(cursor)
    
    conn.commit()
    conn.close()
    return db_path

def migrate_user_db(cursor):
    """Migrate existing user databases to add new columns"""
    try:
        # Check if billing_increment column exists
        cursor.execute("PRAGMA table_info(projects)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'billing_increment' not in columns:
            print("Migrating database: Adding billing_increment column...")
            cursor.execute('ALTER TABLE projects ADD COLUMN billing_increment TEXT DEFAULT "minute"')
            # Update all existing projects to use minute billing
            cursor.execute('UPDATE projects SET billing_increment = "minute" WHERE billing_increment IS NULL')
        
        # Check if invoiced column exists in time_entries
        cursor.execute("PRAGMA table_info(time_entries)")
        time_columns = [column[1] for column in cursor.fetchall()]
        
        if 'invoiced' not in time_columns:
            print("Migrating database: Adding invoiced column...")
            cursor.execute('ALTER TABLE time_entries ADD COLUMN invoiced BOOLEAN DEFAULT 0')
            # Set all existing entries to not invoiced
            cursor.execute('UPDATE time_entries SET invoiced = 0 WHERE invoiced IS NULL')
        
        # Check if billing_status column exists and migrate to new 3-state system
        if 'billing_status' not in time_columns:
            print("Migrating database: Adding billing_status column...")
            cursor.execute('ALTER TABLE time_entries ADD COLUMN billing_status TEXT DEFAULT "pending"')
            # Migrate existing invoiced data to new billing_status system
            cursor.execute('UPDATE time_entries SET billing_status = CASE WHEN invoiced = 1 THEN "invoiced" ELSE "pending" END')
            
    except sqlite3.OperationalError as e:
        print(f"Migration warning: {e}")
        pass

def get_user_db_path(user_id):
    return os.path.join(app.config['DATABASE_FOLDER'], f'user_{user_id}.db')

def ensure_user_db_migrated(user_id):
    """Ensure user database is migrated to latest schema"""
    db_path = get_user_db_path(user_id)
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        migrate_user_db(cursor)
        conn.commit()
        conn.close()

def get_version():
    """Read version from VERSION file"""
    try:
        with open('VERSION', 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return 'unknown'

def generate_backup_codes(count=10):
    """Generate backup codes for 2FA recovery"""
    codes = []
    for _ in range(count):
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        codes.append(code)
    return codes

def verify_backup_code(stored_codes, provided_code):
    """Verify and consume a backup code"""
    if not stored_codes:
        return False, []
    
    try:
        codes = json.loads(stored_codes)
        if provided_code.upper() in codes:
            codes.remove(provided_code.upper())
            return True, codes
    except (json.JSONDecodeError, TypeError):
        pass
    
    return False, []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # If user needs to set up 2FA and this isn't the setup_2fa or verify_2fa route, redirect
        if session.get('setup_2fa') and f.__name__ not in ['setup_2fa', 'verify_2fa', 'logout']:
            return redirect(url_for('setup_2fa'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit(config['registration']['rate_limit'])
def register():
    # Check if registration is enabled
    if not config['registration']['enabled']:
        if request.method == 'POST':
            flash(config['registration']['message_when_disabled'], 'error')
        return render_template('registration_disabled.html', 
                             message=config['registration']['message_when_disabled'])
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Simulate processing time to prevent timing attacks
        start_time = time.time()
        
        conn = sqlite3.connect('main.db')
        cursor = conn.cursor()
        
        # Always hash the password to maintain consistent timing
        password_hash = generate_password_hash(password)
        
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            # Ensure consistent timing by adding delay if needed
            elapsed = time.time() - start_time
            min_time = config['security']['min_processing_time']
            if elapsed < min_time:
                time.sleep(min_time - elapsed)
            flash('Registration request processed. If the email is valid, you will receive further instructions.')
            return render_template('register.html')
        
        # Create new user with UUID
        user_id = str(uuid.uuid4())
        totp_secret = pyotp.random_base32()
        
        cursor.execute('''
            INSERT INTO users (id, email, password_hash, totp_secret)
            VALUES (?, ?, ?, ?)
        ''', (user_id, email, password_hash, totp_secret))
        
        conn.commit()
        conn.close()
        
        # Ensure consistent timing
        elapsed = time.time() - start_time
        min_time = config['security']['min_processing_time']
        if elapsed < min_time:
            time.sleep(min_time - elapsed)
        
        # Initialize user database
        init_user_db(user_id)
        
        session['user_id'] = user_id
        session['email'] = email
        session['setup_2fa'] = True
        
        return redirect(url_for('setup_2fa'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        totp_code = request.form.get('totp_code', '')
        backup_code = request.form.get('backup_code', '')
        
        # Implement uniform response timing to prevent timing attacks
        start_time = time.time()
        
        conn = sqlite3.connect('main.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, totp_secret, totp_enabled, backup_codes FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        # Always perform password hash check to maintain consistent timing
        if user:
            password_valid = check_password_hash(user[1], password)
        else:
            # Perform dummy hash check to prevent timing attacks
            check_password_hash('dummy_hash', password)
            password_valid = False
        
        if user and password_valid:
            if user[3]:  # TOTP enabled
                if backup_code:
                    # Try backup code login
                    is_valid, remaining_codes = verify_backup_code(user[4], backup_code)
                    if is_valid:
                        # Disable 2FA and update backup codes
                        cursor.execute('UPDATE users SET totp_enabled = 0, backup_codes = ? WHERE id = ?', 
                                     (json.dumps(remaining_codes), user[0]))
                        conn.commit()
                        conn.close()
                        
                        # Ensure consistent timing
                        elapsed = time.time() - start_time
                        if elapsed < 0.5:
                            time.sleep(0.5 - elapsed)
                        
                        session['user_id'] = user[0]
                        session['email'] = email
                        session['setup_2fa'] = True  # Force 2FA setup again
                        flash('2FA has been disabled. You must set up 2FA again.')
                        return redirect(url_for('setup_2fa'))
                    else:
                        conn.close()
                        # Ensure consistent timing
                        elapsed = time.time() - start_time
                        if elapsed < 0.5:
                            time.sleep(0.5 - elapsed)
                        flash('Invalid credentials')
                        return render_template('login.html', needs_totp=True, email=email, show_backup=True, 
                                             registration_enabled=config['registration']['enabled'])
                
                if not totp_code and not backup_code:
                    conn.close()
                    # Ensure consistent timing
                    elapsed = time.time() - start_time
                    if elapsed < 0.5:
                        time.sleep(0.5 - elapsed)
                    return render_template('login.html', needs_totp=True, email=email, show_backup=True, 
                                         registration_enabled=config['registration']['enabled'])
                
                if totp_code:
                    totp = pyotp.TOTP(user[2])
                    if not totp.verify(totp_code):
                        conn.close()
                        # Ensure consistent timing
                        elapsed = time.time() - start_time
                        if elapsed < 0.5:
                            time.sleep(0.5 - elapsed)
                        flash('Invalid credentials')
                        return render_template('login.html', needs_totp=True, email=email, show_backup=True, 
                                             registration_enabled=config['registration']['enabled'])
            
            conn.close()
            # Ensure consistent timing
            elapsed = time.time() - start_time
            if elapsed < 0.5:
                time.sleep(0.5 - elapsed)
            
            session['user_id'] = user[0]
            session['email'] = email
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            # Ensure consistent timing for failed login attempts
            elapsed = time.time() - start_time
            if elapsed < 0.5:
                time.sleep(0.5 - elapsed)
            flash('Invalid credentials')
    
    return render_template('login.html', registration_enabled=config['registration']['enabled'])

@app.route('/setup_2fa')
@login_required
def setup_2fa():
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute('SELECT totp_secret, totp_enabled FROM users WHERE id = ?', (session['user_id'],))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        flash('User not found')
        return redirect(url_for('dashboard'))
    
    totp_secret, totp_enabled = result
    
    # If 2FA is already enabled and this isn't a forced setup, redirect to dashboard
    if totp_enabled and not session.get('setup_2fa'):
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Generate new TOTP secret if setting up for the first time or re-enabling
    if not totp_secret or session.get('setup_2fa'):
        totp_secret = pyotp.random_base32()
        cursor.execute('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?', 
                      (totp_secret, session['user_id']))
        conn.commit()
    
    conn.close()
    
    # Generate QR code
    totp = pyotp.TOTP(totp_secret)
    qr_uri = totp.provisioning_uri(
        name=session['email'],
        issuer_name="Chronoflow"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    qr_code_data = base64.b64encode(img_buffer.getvalue()).decode()
    
    return render_template('setup_2fa.html', qr_code=qr_code_data, secret=totp_secret)

@app.route('/verify_2fa', methods=['POST'])
@login_required
def verify_2fa():
    totp_code = request.form['totp_code']
    
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute('SELECT totp_secret FROM users WHERE id = ?', (session['user_id'],))
    totp_secret = cursor.fetchone()[0]
    
    totp = pyotp.TOTP(totp_secret)
    if totp.verify(totp_code):
        # Generate backup codes
        backup_codes = generate_backup_codes()
        backup_codes_json = json.dumps(backup_codes)
        
        cursor.execute('UPDATE users SET totp_enabled = 1, backup_codes = ? WHERE id = ?', 
                      (backup_codes_json, session['user_id']))
        conn.commit()
        conn.close()
        
        session.pop('setup_2fa', None)
        flash('2FA setup successful! Save these backup codes: ' + ', '.join(backup_codes))
        return redirect(url_for('dashboard'))
    else:
        conn.close()
        flash('Invalid TOTP code')
        return redirect(url_for('setup_2fa'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Ensure user database is migrated on dashboard load
    ensure_user_db_migrated(session['user_id'])
    return render_template('dashboard.html', version=get_version())

@app.route('/api/2fa_status')
@login_required
@csrf.exempt
def get_2fa_status():
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute('SELECT totp_enabled FROM users WHERE id = ?', (session['user_id'],))
    result = cursor.fetchone()
    conn.close()
    
    return jsonify({'enabled': bool(result[0]) if result else False})

@app.route('/api/disable_2fa', methods=['POST'])
@login_required
@csrf.exempt
def disable_2fa():
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET totp_enabled = 0, backup_codes = NULL WHERE id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/verify_password_for_backup_codes', methods=['POST'])
@login_required
@csrf.exempt
def verify_password_for_backup_codes():
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({'success': False, 'error': 'Password required'}), 400
    
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, backup_codes FROM users WHERE id = ?', (session['user_id'],))
    result = cursor.fetchone()
    conn.close()
    
    if not result or not check_password_hash(result[0], password):
        return jsonify({'success': False, 'error': 'Invalid password'}), 401
    
    backup_codes = []
    if result[1]:
        try:
            backup_codes = json.loads(result[1])
        except (json.JSONDecodeError, TypeError):
            pass
    
    return jsonify({'success': True, 'backup_codes': backup_codes})

@app.route('/api/enable_2fa_setup', methods=['POST'])
@login_required
@csrf.exempt
def enable_2fa_setup():
    session['setup_2fa'] = True
    return jsonify({'success': True})

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute", methods=['POST'])
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('New passwords do not match')
            return render_template('change_password.html')
        
        # Verify current password
        conn = sqlite3.connect('main.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user[0], current_password):
            flash('Current password is incorrect')
            conn.close()
            return render_template('change_password.html')
        
        # Update password
        new_password_hash = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                      (new_password_hash, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Password updated successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# API Routes
@app.route('/api/projects')
@login_required
@csrf.exempt
def get_projects():
    # Ensure database is migrated before querying
    ensure_user_db_migrated(session['user_id'])
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if we want archived projects too
    include_archived = request.args.get('include_archived', 'false').lower() == 'true'
    
    if include_archived:
        cursor.execute('SELECT id, name, hourly_rate, billing_increment, archived FROM projects ORDER BY archived, name')
    else:
        cursor.execute('SELECT id, name, hourly_rate, billing_increment, archived FROM projects WHERE archived = 0 ORDER BY name')
    
    projects = []
    for row in cursor.fetchall():
        projects.append({
            'id': row[0], 
            'name': row[1], 
            'hourly_rate': row[2],
            'billing_increment': row[3] if len(row) > 3 and row[3] else 'minute',
            'archived': row[4] if len(row) > 4 else 0
        })
    conn.close()
    return jsonify(projects)

@app.route('/api/projects', methods=['POST'])
@login_required
@csrf.exempt
def create_project():
    data = request.json
    ensure_user_db_migrated(session['user_id'])
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('INSERT INTO projects (name, hourly_rate, billing_increment) VALUES (?, ?, ?)', 
                  (data['name'], data['hourly_rate'], data.get('billing_increment', 'minute')))
    project_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return jsonify({
        'id': project_id, 
        'name': data['name'], 
        'hourly_rate': data['hourly_rate'],
        'billing_increment': data.get('billing_increment', 'minute')
    })

@app.route('/api/projects/<int:project_id>', methods=['PUT'])
@login_required
@csrf.exempt
def update_project(project_id):
    data = request.json
    ensure_user_db_migrated(session['user_id'])
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE projects SET name = ?, hourly_rate = ?, billing_increment = ? WHERE id = ?', 
                  (data['name'], data['hourly_rate'], data.get('billing_increment', 'minute'), project_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/projects/<int:project_id>/archive', methods=['POST'])
@login_required
@csrf.exempt
def archive_project(project_id):
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('UPDATE projects SET archived = 1 WHERE id = ?', (project_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/time_entries')
@login_required
@csrf.exempt
def get_time_entries():
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get filters
    project_id = request.args.get('project_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    billing_status_filter = request.args.get('billing_status')
    billing_statuses = request.args.get('billing_statuses')
    invoiced_filter = request.args.get('invoiced')  # Keep for backward compatibility
    limit = request.args.get('limit', type=int)
    
    query = '''
        SELECT te.id, te.project_id, p.name as project_name, te.description, 
               te.start_time, te.end_time, te.duration_minutes, te.earnings, te.invoiced,
               COALESCE(te.billing_status, CASE WHEN te.invoiced = 1 THEN 'invoiced' ELSE 'pending' END) as billing_status
        FROM time_entries te
        LEFT JOIN projects p ON te.project_id = p.id
        WHERE 1=1
    '''
    params = []
    
    if project_id:
        query += ' AND te.project_id = ?'
        params.append(project_id)
    
    if date_from:
        query += ' AND date(te.start_time) >= ?'
        params.append(date_from)
    
    if date_to:
        query += ' AND date(te.start_time) <= ?'
        params.append(date_to)
    
    # Support billing_statuses (multiple), billing_status (single), and legacy invoiced filter
    if billing_statuses:
        status_list = [status.strip() for status in billing_statuses.split(',')]
        if status_list:  # Only apply filter if we have valid statuses
            placeholders = ','.join(['?' for _ in status_list])
            query += f' AND COALESCE(te.billing_status, CASE WHEN te.invoiced = 1 THEN "invoiced" ELSE "pending" END) IN ({placeholders})'
            params.extend(status_list)
    elif billing_status_filter:
        query += ' AND COALESCE(te.billing_status, CASE WHEN te.invoiced = 1 THEN "invoiced" ELSE "pending" END) = ?'
        params.append(billing_status_filter)
    elif invoiced_filter is not None:
        query += ' AND te.invoiced = ?'
        params.append(int(invoiced_filter))
    
    query += ' ORDER BY te.start_time DESC'
    
    if limit:
        query += ' LIMIT ?'
        params.append(limit)
    
    cursor.execute(query, params)
    entries = []
    for row in cursor.fetchall():
        entries.append({
            'id': row[0],
            'project_id': row[1],
            'project_name': row[2],
            'description': row[3],
            'start_time': row[4],
            'end_time': row[5],
            'duration_minutes': row[6],
            'earnings': row[7],
            'invoiced': row[8] if len(row) > 8 else 0,
            'billing_status': row[9] if len(row) > 9 else ('invoiced' if (len(row) > 8 and row[8]) else 'pending')
        })
    
    conn.close()
    return jsonify(entries)

@app.route('/api/projects/<int:project_id>/unarchive', methods=['POST'])
@login_required
@csrf.exempt
def unarchive_project(project_id):
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('UPDATE projects SET archived = 0 WHERE id = ?', (project_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/time_entries', methods=['POST'])
@login_required
@csrf.exempt
def create_time_entry():
    data = request.json
    ensure_user_db_migrated(session['user_id'])
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get project details including billing increment
    cursor.execute('SELECT hourly_rate, billing_increment FROM projects WHERE id = ?', (data['project_id'],))
    result = cursor.fetchone()
    if not result:
        conn.close()
        return jsonify({'error': 'Project not found'}), 404
        
    hourly_rate = result[0]
    billing_increment = result[1] if len(result) > 1 and result[1] else 'minute'
    
    # Calculate billable minutes based on increment
    raw_minutes = data['duration_minutes']
    billable_minutes = calculate_billable_minutes(raw_minutes, billing_increment)
    
    # Calculate earnings
    earnings = (billable_minutes / 60.0) * hourly_rate
    
    cursor.execute('''
        INSERT INTO time_entries (project_id, description, start_time, end_time, duration_minutes, earnings, billing_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (data['project_id'], data['description'], data['start_time'], 
          data['end_time'], billable_minutes, earnings, 'pending'))
    
    entry_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'id': entry_id, 'earnings': earnings, 'billable_minutes': billable_minutes})

@app.route('/api/time_entries/<int:entry_id>', methods=['DELETE'])
@login_required
@csrf.exempt
def delete_time_entry(entry_id):
    ensure_user_db_migrated(session['user_id'])
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Verify entry belongs to this user and delete it
    cursor.execute('DELETE FROM time_entries WHERE id = ?', (entry_id,))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Time entry not found'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/time_entries/<int:entry_id>', methods=['PUT'])
@login_required
@csrf.exempt
def update_time_entry(entry_id):
    data = request.json
    ensure_user_db_migrated(session['user_id'])
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if entry exists and is not invoiced
    cursor.execute('SELECT COALESCE(billing_status, CASE WHEN invoiced = 1 THEN "invoiced" ELSE "pending" END) FROM time_entries WHERE id = ?', (entry_id,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return jsonify({'error': 'Time entry not found'}), 404
    
    if result[0] in ['invoiced', 'unbilled']:  # Entry is in final state
        conn.close()
        return jsonify({'error': f'Cannot edit {result[0]} entries'}), 400
    
    # Get project details including billing increment
    cursor.execute('SELECT hourly_rate, billing_increment FROM projects WHERE id = ?', (data['project_id'],))
    project_result = cursor.fetchone()
    if not project_result:
        conn.close()
        return jsonify({'error': 'Project not found'}), 404
        
    hourly_rate = project_result[0]
    billing_increment = project_result[1] if len(project_result) > 1 and project_result[1] else 'minute'
    
    # Calculate billable minutes based on increment
    raw_minutes = data['duration_minutes']
    billable_minutes = calculate_billable_minutes(raw_minutes, billing_increment)
    
    # Calculate earnings
    earnings = (billable_minutes / 60.0) * hourly_rate
    
    # Update the time entry
    cursor.execute('''
        UPDATE time_entries 
        SET project_id = ?, description = ?, start_time = ?, end_time = ?, 
            duration_minutes = ?, earnings = ?
        WHERE id = ?
    ''', (data['project_id'], data['description'], data['start_time'], 
          data['end_time'], billable_minutes, earnings, entry_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'earnings': earnings, 'billable_minutes': billable_minutes})

@app.route('/api/time_entries/<int:entry_id>/billing_status', methods=['POST'])
@login_required
@csrf.exempt
def set_billing_status(entry_id):
    data = request.json
    ensure_user_db_migrated(session['user_id'])
    
    # Validate billing status
    valid_statuses = ['pending', 'invoiced', 'unbilled']
    new_status = data.get('status')
    if new_status not in valid_statuses:
        return jsonify({'error': 'Invalid billing status. Must be one of: ' + ', '.join(valid_statuses)}), 400
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get time entry details including project info for earnings calculation
    cursor.execute('''
        SELECT te.id, te.project_id, te.duration_minutes, p.hourly_rate, p.billing_increment 
        FROM time_entries te 
        JOIN projects p ON te.project_id = p.id 
        WHERE te.id = ?
    ''', (entry_id,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return jsonify({'error': 'Time entry not found'}), 404
    
    entry_id_db, project_id, duration_minutes, hourly_rate, billing_increment = result
    billing_increment = billing_increment if billing_increment else 'minute'
    
    # Calculate earnings based on billing status
    if new_status == 'unbilled':
        # Unbilled entries have zero earnings
        earnings = 0.0
    else:
        # Pending and invoiced entries use normal hourly rate calculation
        billable_minutes = calculate_billable_minutes(duration_minutes, billing_increment)
        earnings = (billable_minutes / 60.0) * hourly_rate
    
    # Update billing status, invoiced field, and earnings
    invoiced_value = 1 if new_status == 'invoiced' else 0
    cursor.execute('UPDATE time_entries SET billing_status = ?, invoiced = ?, earnings = ? WHERE id = ?', 
                   (new_status, invoiced_value, earnings, entry_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'billing_status': new_status, 'invoiced': bool(invoiced_value), 'earnings': earnings})

@app.route('/api/time_entries/<int:entry_id>/invoice', methods=['POST'])
@login_required
@csrf.exempt
def toggle_invoice_status(entry_id):
    """Legacy endpoint for backward compatibility"""
    ensure_user_db_migrated(session['user_id'])
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get current status
    cursor.execute('SELECT COALESCE(billing_status, CASE WHEN invoiced = 1 THEN "invoiced" ELSE "pending" END) FROM time_entries WHERE id = ?', (entry_id,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return jsonify({'error': 'Time entry not found'}), 404
    
    # Toggle between invoiced and pending (skip unbilled for legacy compatibility)
    current_status = result[0]
    new_status = 'pending' if current_status == 'invoiced' else 'invoiced'
    invoiced_value = 1 if new_status == 'invoiced' else 0
    
    cursor.execute('UPDATE time_entries SET billing_status = ?, invoiced = ? WHERE id = ?', 
                   (new_status, invoiced_value, entry_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'billing_status': new_status, 'invoiced': bool(invoiced_value)})

def calculate_billable_minutes(raw_minutes, billing_increment):
    """Calculate billable minutes based on billing increment"""
    # Ensure minimum 1 minute for any time tracked
    if raw_minutes < 1:
        raw_minutes = 1
    
    if billing_increment == 'minute':
        return raw_minutes
    elif billing_increment == '15min':
        # Round up to next 15 minute increment
        return ((raw_minutes - 1) // 15 + 1) * 15
    elif billing_increment == '30min':
        # Round up to next 30 minute increment
        return ((raw_minutes - 1) // 30 + 1) * 30
    elif billing_increment == 'hour':
        # Round up to next hour
        return ((raw_minutes - 1) // 60 + 1) * 60
    else:
        return raw_minutes

def export_to_csv(data):
    """Export data to CSV format"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Date', 'Start Time', 'End Time', 'Duration (minutes)', 'Duration (hours)', 'Description', 'Project', 'Earnings (€)'])
    
    # Write data
    for entry in data:
        # Parse UTC times and convert to local timezone
        start_time = None
        end_time = None
        
        if entry['start_time']:
            start_time = datetime.fromisoformat(entry['start_time'].replace('Z', '+00:00'))
            # Convert from UTC to local timezone
            start_time = start_time.replace(tzinfo=timezone.utc).astimezone()
            
        if entry['end_time']:
            end_time = datetime.fromisoformat(entry['end_time'].replace('Z', '+00:00'))
            # Convert from UTC to local timezone
            end_time = end_time.replace(tzinfo=timezone.utc).astimezone()
        
        writer.writerow([
            start_time.strftime('%Y-%m-%d') if start_time else '',
            start_time.strftime('%H:%M:%S') if start_time else '',
            end_time.strftime('%H:%M:%S') if end_time else '',
            entry['duration_minutes'],
            round(entry['duration_minutes'] / 60, 2),
            entry['description'],
            entry['project_name'] or 'Unknown',
            entry['earnings']
        ])
    
    output.seek(0)
    return output.getvalue()

def export_to_json(data):
    """Export data to JSON format"""
    # Convert UTC times to local timezone in the data
    converted_data = []
    for entry in data:
        converted_entry = entry.copy()
        
        # Convert start_time from UTC to local timezone
        if entry.get('start_time'):
            start_time = datetime.fromisoformat(entry['start_time'].replace('Z', '+00:00'))
            start_time = start_time.replace(tzinfo=timezone.utc).astimezone()
            converted_entry['start_time'] = start_time.isoformat()
            
        # Convert end_time from UTC to local timezone
        if entry.get('end_time'):
            end_time = datetime.fromisoformat(entry['end_time'].replace('Z', '+00:00'))
            end_time = end_time.replace(tzinfo=timezone.utc).astimezone()
            converted_entry['end_time'] = end_time.isoformat()
            
        converted_data.append(converted_entry)
    
    return json.dumps(converted_data, indent=2, default=str)


def export_customer_to_csv(data):
    """Export customer-friendly data to CSV format with limited columns"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header - customer-friendly columns only
    writer.writerow(['Date', 'Time Period', 'Duration', 'Description', 'Billing Status'])
    
    # Write data
    for entry in data:
        # Parse UTC times and convert to local timezone
        start_time = None
        end_time = None
        
        if entry['start_time']:
            start_time = datetime.fromisoformat(entry['start_time'].replace('Z', '+00:00'))
            # Convert from UTC to local timezone
            start_time = start_time.replace(tzinfo=timezone.utc).astimezone()
            
        if entry['end_time']:
            end_time = datetime.fromisoformat(entry['end_time'].replace('Z', '+00:00'))
            # Convert from UTC to local timezone
            end_time = end_time.replace(tzinfo=timezone.utc).astimezone()
        
        # Format time period
        time_period = ''
        if start_time and end_time:
            time_period = f"{start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}"
        
        # Format duration
        duration = f"{round(entry['duration_minutes'] / 60, 2)}h"
        
        # Map billing status for customer export
        billing_status = entry.get('billing_status', 'pending')
        if billing_status == 'pending':
            billing_status = 'billable'
        # unbilled and invoiced remain as-is
        
        writer.writerow([
            start_time.strftime('%Y-%m-%d') if start_time else '',
            time_period,
            duration,
            entry['description'] or '',
            billing_status
        ])
    
    output.seek(0)
    return output.getvalue()

def export_customer_to_json(data):
    """Export customer-friendly data to JSON format with limited columns"""
    customer_data = []
    
    for entry in data:
        # Parse UTC times and convert to local timezone
        start_time = None
        end_time = None
        
        if entry['start_time']:
            start_time = datetime.fromisoformat(entry['start_time'].replace('Z', '+00:00'))
            # Convert from UTC to local timezone
            start_time = start_time.replace(tzinfo=timezone.utc).astimezone()
            
        if entry['end_time']:
            end_time = datetime.fromisoformat(entry['end_time'].replace('Z', '+00:00'))
            # Convert from UTC to local timezone
            end_time = end_time.replace(tzinfo=timezone.utc).astimezone()
        
        # Format time period
        time_period = ''
        if start_time and end_time:
            time_period = f"{start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}"
        
        # Format duration
        duration = f"{round(entry['duration_minutes'] / 60, 2)}h"
        
        # Map billing status for customer export
        billing_status = entry.get('billing_status', 'pending')
        if billing_status == 'pending':
            billing_status = 'billable'
        
        customer_data.append({
            'date': start_time.strftime('%Y-%m-%d') if start_time else '',
            'time_period': time_period,
            'duration': duration,
            'description': entry['description'] or '',
            'billing_status': billing_status
        })
    
    return json.dumps(customer_data, indent=2)

def export_full_backup():
    """Export complete user data including projects and all time entries for import/export feature"""
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all projects
    cursor.execute('SELECT * FROM projects ORDER BY id')
    projects_columns = [desc[0] for desc in cursor.description]
    projects_data = []
    for row in cursor.fetchall():
        projects_data.append(dict(zip(projects_columns, row)))
    
    # Get all time entries
    cursor.execute('SELECT * FROM time_entries ORDER BY id')
    entries_columns = [desc[0] for desc in cursor.description]
    entries_data = []
    for row in cursor.fetchall():
        entries_data.append(dict(zip(entries_columns, row)))
    
    conn.close()
    
    # Create comprehensive backup data
    backup_data = {
        'export_info': {
            'version': '1.0',
            'exported_at': datetime.now().isoformat(),
            'user_email': session.get('email', 'unknown')
        },
        'projects': projects_data,
        'time_entries': entries_data
    }
    
    return json.dumps(backup_data, indent=2, default=str)

@app.route('/api/export')
@login_required
@csrf.exempt
def export_data():
    format_type = request.args.get('format', 'csv')
    project_id = request.args.get('project_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    billing_statuses = request.args.get('billing_statuses')
    customer_export = request.args.get('customer_export', 'false').lower() == 'true'
    full_backup = request.args.get('full_backup', 'false').lower() == 'true'
    
    # Handle full backup export for import/export feature
    if full_backup:
        content = export_full_backup()
        response = make_response(content)
        response.headers['Content-Type'] = 'application/json'
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        response.headers['Content-Disposition'] = f'attachment; filename=chronoflow_backup_{timestamp}.json'
        return response
    
    db_path = get_user_db_path(session['user_id'])
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = '''
        SELECT te.start_time, te.end_time, te.duration_minutes, 
               te.description, p.name as project_name, te.earnings,
               COALESCE(te.billing_status, CASE WHEN te.invoiced = 1 THEN "invoiced" ELSE "pending" END) as billing_status
        FROM time_entries te
        LEFT JOIN projects p ON te.project_id = p.id
        WHERE 1=1
    '''
    params = []
    
    if project_id:
        query += ' AND te.project_id = ?'
        params.append(project_id)
    
    if date_from:
        query += ' AND date(te.start_time) >= ?'
        params.append(date_from)
    
    if date_to:
        query += ' AND date(te.start_time) <= ?'
        params.append(date_to)
    
    # Handle billing status filtering
    if billing_statuses:
        status_list = [status.strip() for status in billing_statuses.split(',')]
        if status_list:  # Only apply filter if we have valid statuses
            placeholders = ','.join(['?' for _ in status_list])
            query += f' AND COALESCE(te.billing_status, CASE WHEN te.invoiced = 1 THEN "invoiced" ELSE "pending" END) IN ({placeholders})'
            params.extend(status_list)
    
    query += ' ORDER BY te.start_time'
    
    cursor.execute(query, params)
    
    # Convert to list of dictionaries
    columns = [desc[0] for desc in cursor.description]
    data = []
    for row in cursor.fetchall():
        data.append(dict(zip(columns, row)))
    
    conn.close()
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d")
    
    if format_type == 'json':
        content = export_to_json(data) if not customer_export else export_customer_to_json(data)
        response = make_response(content)
        response.headers['Content-Type'] = 'application/json'
        filename_prefix = 'chronoflow_customer_export' if customer_export else 'chronoflow_export'
        response.headers['Content-Disposition'] = f'attachment; filename={filename_prefix}_{timestamp}.json'
        return response
    
    else:  # CSV (default)
        content = export_customer_to_csv(data) if customer_export else export_to_csv(data)
        response = make_response(content)
        response.headers['Content-Type'] = 'text/csv'
        filename_prefix = 'chronoflow_customer_export' if customer_export else 'chronoflow_export'
        response.headers['Content-Disposition'] = f'attachment; filename={filename_prefix}_{timestamp}.csv'
        return response

@app.route('/api/import', methods=['POST'])
@login_required
@csrf.exempt
def import_data():
    """Import user data from JSON backup file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'Only JSON files are supported'}), 400
        
        # Read and parse JSON
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid JSON file'}), 400
        
        # Validate data structure
        if not isinstance(data, dict) or 'export_info' not in data:
            return jsonify({'error': 'Invalid backup file format'}), 400
        
        if 'projects' not in data or 'time_entries' not in data:
            return jsonify({'error': 'Missing required data in backup file'}), 400
        
        # Get merge strategy
        merge_strategy = request.form.get('merge_strategy', 'merge')  # 'merge' or 'replace'
        
        db_path = get_user_db_path(session['user_id'])
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        stats = {'projects_imported': 0, 'time_entries_imported': 0, 'projects_updated': 0}
        
        try:
            # Handle projects
            project_id_mapping = {}
            
            if merge_strategy == 'replace':
                # Clear existing data
                cursor.execute('DELETE FROM time_entries')
                cursor.execute('DELETE FROM projects')
                conn.commit()
            
            for project_data in data.get('projects', []):
                original_id = project_data.get('id')
                name = project_data.get('name')
                hourly_rate = project_data.get('hourly_rate', 0.0)
                billing_increment = project_data.get('billing_increment', 'minute')
                archived = project_data.get('archived', 0)
                created_at = project_data.get('created_at')
                
                if not name:
                    continue
                
                if merge_strategy == 'merge':
                    # Check if project with same name exists
                    cursor.execute('SELECT id FROM projects WHERE name = ?', (name,))
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Update existing project
                        cursor.execute('''
                            UPDATE projects 
                            SET hourly_rate = ?, billing_increment = ?, archived = ?
                            WHERE id = ?
                        ''', (hourly_rate, billing_increment, archived, existing[0]))
                        project_id_mapping[original_id] = existing[0]
                        stats['projects_updated'] += 1
                    else:
                        # Insert new project
                        cursor.execute('''
                            INSERT INTO projects (name, hourly_rate, billing_increment, archived, created_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (name, hourly_rate, billing_increment, archived, created_at))
                        project_id_mapping[original_id] = cursor.lastrowid
                        stats['projects_imported'] += 1
                else:
                    # Replace mode - insert with original structure
                    cursor.execute('''
                        INSERT INTO projects (name, hourly_rate, billing_increment, archived, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (name, hourly_rate, billing_increment, archived, created_at))
                    project_id_mapping[original_id] = cursor.lastrowid
                    stats['projects_imported'] += 1
            
            # Handle time entries
            for entry_data in data.get('time_entries', []):
                project_id = entry_data.get('project_id')
                description = entry_data.get('description')
                start_time = entry_data.get('start_time')
                end_time = entry_data.get('end_time')
                duration_minutes = entry_data.get('duration_minutes')
                earnings = entry_data.get('earnings', 0.0)
                invoiced = entry_data.get('invoiced', 0)
                billing_status = entry_data.get('billing_status', 'pending')
                created_at = entry_data.get('created_at')
                
                # Map to new project ID
                new_project_id = project_id_mapping.get(project_id)
                if not new_project_id:
                    continue  # Skip entries for projects that couldn't be imported
                
                cursor.execute('''
                    INSERT INTO time_entries 
                    (project_id, description, start_time, end_time, duration_minutes, 
                     earnings, invoiced, billing_status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (new_project_id, description, start_time, end_time, duration_minutes,
                      earnings, invoiced, billing_status, created_at))
                stats['time_entries_imported'] += 1
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Data imported successfully',
                'stats': stats
            })
            
        except Exception as e:
            conn.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({'error': f'Import failed: {str(e)}'}), 500

if __name__ == '__main__':
    init_main_db()
    app.run(debug=True)