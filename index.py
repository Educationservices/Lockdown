from flask import Flask, jsonify, request, render_template_string, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
from bson import ObjectId
import json
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import logging
import threading
import time
import re
from functools import wraps

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.permanent_session_lifetime = timedelta(hours=24)  # Session timeout

# Enable CORS for local development
CORS(app, supports_credentials=True)

# In-memory storage for verification codes, sign-in codes, and request cooldowns
verification_codes = {}  # {username: {'code': '12345', 'email': 'user@email.com', 'expires_at': datetime}}
signin_codes = {}  # {username: {'code': 'ABC123', 'expires_at': datetime, 'created_at': datetime}}
request_cooldowns = {}  # {ip_address: {'last_request': datetime, 'count': int}}
user_cooldowns = {}  # {username: {'last_request': datetime, 'count': int}}

# MongoDB connection from environment variables
MONGO_USERNAME = os.getenv('MONGO_USERNAME')
MONGO_PASSWORD = os.getenv('MONGO_PASSWORD')
MONGO_CLUSTER = os.getenv('MONGO_CLUSTER')
MONGO_DATABASE = os.getenv('MONGO_DATABASE')

# Email configuration from environment variables
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')

# Construct MongoDB URI
MONGO_URI = f"mongodb+srv://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_CLUSTER}/?retryWrites=true&w=majority&appName=Cluster0"

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[MONGO_DATABASE]
    users_collection = db['users']
    user_data_collection = db['user_data']
    
    # Test connection
    client.admin.command('ping')
    logger.info("Connected to MongoDB successfully!")
    db_connected = True
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
    client = None
    db = None
    db_connected = False

# Input validation functions
def validate_username(username):
    """Validate username format and length"""
    if not username or not isinstance(username, str):
        return False
    if not (3 <= len(username) <= 20):
        return False
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False
    return True

def validate_email(email):
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """Validate password strength"""
    if not password or not isinstance(password, str):
        return False
    return len(password) >= 6

def sanitize_username(username):
    """Sanitize username for database queries"""
    if not username:
        return ""
    return re.sub(r'[^\w-]', '', username)[:20]

def generate_signin_code():
    """Generate a 6-character alphanumeric sign-in code"""
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=6))

# Enhanced request cooldown decorator
def cooldown_required(seconds=2, per_user=False):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', '127.0.0.1'))
            current_time = datetime.utcnow()
            
            # IP-based cooldown
            if client_ip in request_cooldowns:
                last_request = request_cooldowns[client_ip]['last_request']
                if (current_time - last_request).total_seconds() < seconds:
                    return jsonify({
                        'success': False,
                        'message': f'Please wait {seconds} seconds between requests'
                    }), 429
            
            # User-based cooldown for authenticated requests
            if per_user and session.get('username'):
                username = session.get('username')
                if username in user_cooldowns:
                    last_request = user_cooldowns[username]['last_request']
                    if (current_time - last_request).total_seconds() < seconds:
                        return jsonify({
                            'success': False,
                            'message': f'Please wait {seconds} seconds between requests'
                        }), 429
                
                user_cooldowns[username] = {
                    'last_request': current_time,
                    'count': user_cooldowns.get(username, {}).get('count', 0) + 1
                }
            
            # Update IP cooldown
            request_cooldowns[client_ip] = {
                'last_request': current_time,
                'count': request_cooldowns.get(client_ip, {}).get('count', 0) + 1
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def requires_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or not session.get('username'):
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def cleanup_expired_data():
    """Background thread to clean up expired codes and old cooldowns"""
    while True:
        try:
            current_time = datetime.utcnow()
            
            # Clean up expired verification codes
            expired_verification = [username for username, data in verification_codes.items() 
                                  if current_time > data['expires_at']]
            for username in expired_verification:
                del verification_codes[username]
            
            # Clean up expired sign-in codes
            expired_signin_codes = [username for username, data in signin_codes.items() 
                                  if current_time > data['expires_at']]
            for username in expired_signin_codes:
                del signin_codes[username]
            
            # Clean up old cooldowns (older than 1 hour)
            expired_cooldowns = [ip for ip, data in request_cooldowns.items()
                               if (current_time - data['last_request']).total_seconds() > 3600]
            for ip in expired_cooldowns:
                del request_cooldowns[ip]
            
            # Clean up old user cooldowns
            expired_user_cooldowns = [username for username, data in user_cooldowns.items()
                                    if (current_time - data['last_request']).total_seconds() > 3600]
            for username in expired_user_cooldowns:
                del user_cooldowns[username]
            
            # Log cleanup stats
            if expired_verification or expired_signin_codes:
                logger.info(f"Cleaned up {len(expired_verification)} expired verification codes and {len(expired_signin_codes)} expired signin codes")
        
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        
        time.sleep(60)  # Clean up every minute

# Start background cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_data, daemon=True)
cleanup_thread.start()

def generate_verification_code():
    """Generate a 5-digit verification code"""
    return ''.join(random.choices(string.digits, k=5))

def send_verification_email(email, username, code):
    """Send verification email with the styled HTML template"""
    try:
        if not all([email, username, code, SENDER_EMAIL, SENDER_PASSWORD]):
            logger.error("Missing email configuration or parameters")
            return False
            
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Lockdown - Verify Your Account"
        msg['From'] = SENDER_EMAIL
        msg['To'] = email

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Lockdown Verification</title>
  <style>
    body {{
      background: #0f0f0f;
      color: #fff;
      font-family: "Segoe UI", sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
    }}
    .card {{
      background: #1a1a1a;
      padding: 30px;
      border-radius: 12px;
      text-align: center;
      box-shadow: 0 0 20px rgba(255,0,0,0.3);
      max-width: 600px;
    }}
    .code {{
      font-size: 2rem;
      letter-spacing: 4px;
      font-weight: bold;
      background: linear-gradient(90deg, #ff0000, #7e0000);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1 style="color: #ff0000;">Lockdown</h1>
    <div style="margin-bottom: 20px; font-size: 1.2rem; color: #ccc;">Welcome, {username}!</div>
    <div class="code">{code}</div>
    <div style="margin-top: 15px; font-size: 0.9rem; color: #ffb3b3;">Never share this code with someone else</div>
    <div style="margin-top: 20px; font-size: 0.8rem; color: #888;">This code expires in 10 minutes.</div>
  </div>
</body>
</html>
        """

        html_part = MIMEText(html, 'html')
        msg.attach(html_part)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Verification email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

# HTML Template (same as before, but I'll include a placeholder)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lockdown Account</title>
    <style>
        /* Your CSS styles here */
    </style>
</head>
<body>
    <!-- Your HTML content here -->
</body>
</html>
"""

# Authentication routes with enhanced security
@app.route('/auth/login', methods=['POST'])
@cooldown_required(2)
def auth_login():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Input validation
        if not validate_username(username) or not password:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 400
        
        # Sanitize username
        clean_username = sanitize_username(username)
        
        # Fixed MongoDB query - exact match with case insensitive
        user = users_collection.find_one({'username': {'$regex': f'^{re.escape(clean_username)}$', '$options': 'i'}})
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        if not user.get('verified', False):
            return jsonify({'success': False, 'message': 'Account not verified', 'verified': False}), 403
        
        if not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Store user in session with regeneration
        session.permanent = True
        session.clear()  # Clear existing session data
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['login_time'] = datetime.utcnow().isoformat()
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'username': user['username'],
                'email': user['email'],
                'user_id': str(user['_id'])
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Authentication failed'}), 500

@app.route('/auth/register', methods=['POST'])
@cooldown_required(3)
def auth_register():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Enhanced input validation
        if not validate_username(username):
            return jsonify({'success': False, 'message': 'Username must be 3-20 characters, alphanumeric with _ or - only'}), 400
        
        if not validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if not validate_password(password):
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        # Sanitize inputs
        clean_username = sanitize_username(username)
        
        # Check existing username/email with proper escaping
        if users_collection.find_one({'username': {'$regex': f'^{re.escape(clean_username)}$', '$options': 'i'}}):
            return jsonify({'success': False, 'message': 'Username already exists'}), 409
        
        if users_collection.find_one({'email': {'$regex': f'^{re.escape(email)}$', '$options': 'i'}}):
            return jsonify({'success': False, 'message': 'Email already registered'}), 409
        
        # Create user with additional security fields
        hashed_password = generate_password_hash(password)
        user_doc = {
            'username': clean_username,
            'email': email,
            'password': hashed_password,
            'verified': False,
            'created_at': datetime.utcnow(),
            'last_login': None,
            'login_attempts': 0
        }
        
        result = users_collection.insert_one(user_doc)
        
        # Generate and send verification code
        verification_code = generate_verification_code()
        verification_codes[clean_username] = {
            'code': verification_code,
            'email': email,
            'expires_at': datetime.utcnow() + timedelta(minutes=10),
            'attempts': 0
        }
        
        email_sent = send_verification_email(email, clean_username, verification_code)
        
        if not email_sent:
            users_collection.delete_one({'_id': result.inserted_id})
            if clean_username in verification_codes:
                del verification_codes[clean_username]
            return jsonify({'success': False, 'message': 'Failed to send verification email'}), 500
        
        return jsonify({
            'success': True,
            'message': 'Registration successful. Check your email for verification code.'
        })
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/auth/verify', methods=['POST'])
@cooldown_required(1)
def auth_verify():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        username = sanitize_username(data.get('username', '').strip())
        code = data.get('code', '').strip()
        
        if not username or not code or not code.isdigit() or len(code) != 5:
            return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
        
        if username not in verification_codes:
            return jsonify({'success': False, 'message': 'Invalid or expired verification code'}), 400
        
        verification_data = verification_codes[username]
        
        # Check expiration
        if datetime.utcnow() > verification_data['expires_at']:
            del verification_codes[username]
            return jsonify({'success': False, 'message': 'Verification code expired'}), 400
        
        # Check attempts
        if verification_data.get('attempts', 0) >= 5:
            del verification_codes[username]
            return jsonify({'success': False, 'message': 'Too many failed attempts'}), 400
        
        # Verify code
        if verification_data['code'] != code:
            verification_codes[username]['attempts'] = verification_data.get('attempts', 0) + 1
            return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
        
        # Update user as verified
        update_result = users_collection.update_one(
            {'username': {'$regex': f'^{re.escape(username)}$', '$options': 'i'}}, 
            {'$set': {'verified': True, 'verified_at': datetime.utcnow()}}
        )
        
        if update_result.matched_count == 0:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Initialize user data
        user_data_doc = {
            'username': username,
            'data': {},
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        user_data_collection.insert_one(user_data_doc)
        
        del verification_codes[username]
        
        return jsonify({'success': True, 'message': 'Account verified successfully'})
        
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return jsonify({'success': False, 'message': 'Verification failed'}), 500

@app.route('/auth/resend', methods=['POST'])
@cooldown_required(30)  # Longer cooldown for resend
def auth_resend():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        username = sanitize_username(data.get('username', '').strip()) if data else ''
        
        if not username:
            return jsonify({'success': False, 'message': 'Username required'}), 400
        
        user = users_collection.find_one({'username': {'$regex': f'^{re.escape(username)}$', '$options': 'i'}})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if user.get('verified', False):
            return jsonify({'success': False, 'message': 'Account already verified'}), 400
        
        verification_code = generate_verification_code()
        verification_codes[username] = {
            'code': verification_code,
            'email': user['email'],
            'expires_at': datetime.utcnow() + timedelta(minutes=10),
            'attempts': 0
        }
        
        email_sent = send_verification_email(user['email'], username, verification_code)
        
        if not email_sent:
            return jsonify({'success': False, 'message': 'Failed to send email'}), 500
        
        return jsonify({'success': True, 'message': 'Verification code sent'})
        
    except Exception as e:
        logger.error(f"Resend error: {e}")
        return jsonify({'success': False, 'message': 'Failed to resend verification'}), 500

@app.route('/quickgensignin', methods=['GET'])
@cooldown_required(10)  # Prevent abuse from external sources
def quick_gen_signin():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        # Get username from query parameter
        username = request.args.get('username', '').strip()
        
        if not username or not validate_username(username):
            return jsonify({'success': False, 'message': 'Valid username required'}), 400
        
        # Sanitize username
        clean_username = sanitize_username(username)
        
        # Check if user exists and is verified
        user = users_collection.find_one({'username': {'$regex': f'^{re.escape(clean_username)}$', '$options': 'i'}})
        if not user or not user.get('verified', False):
            return jsonify({'success': False, 'message': 'User not found or not verified'}), 404
        
        actual_username = user['username']
        
        # Generate signin code
        signin_code = generate_signin_code()
        signin_codes[actual_username] = {
            'code': signin_code,
            'expires_at': datetime.utcnow() + timedelta(minutes=5),
            'created_at': datetime.utcnow()
        }
        
        return jsonify({
            'success': True,
            'signin_code': signin_code,
            'username': actual_username,
            'expires_in_minutes': 5,
            'message': 'Sign-in code generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Quick gen signin error: {e}")
        return jsonify({'success': False, 'message': 'Failed to generate signin code'}), 500

@app.route('/auth/generate-signin-code', methods=['POST'])
@cooldown_required(10, per_user=True)
@requires_auth
def auth_generate_signin_code():
    """Generate a new sign-in code for the authenticated user"""
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        current_username = session.get('username')
        
        if not current_username:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        # Check if user exists and is verified
        user = users_collection.find_one({'username': {'$regex': f'^{re.escape(current_username)}$', '$options': 'i'}})
        if not user or not user.get('verified', False):
            return jsonify({'success': False, 'message': 'User not found or not verified'}), 404
        
        # Generate signin code
        signin_code = generate_signin_code()
        signin_codes[current_username] = {
            'code': signin_code,
            'expires_at': datetime.utcnow() + timedelta(minutes=5),
            'created_at': datetime.utcnow()
        }
        
        return jsonify({
            'success': True,
            'signin_code': signin_code,
            'username': current_username,
            'expires_at': signin_codes[current_username]['expires_at'].isoformat(),
            'expires_in_minutes': 5,
            'message': 'Sign-in code generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Generate signin code error: {e}")
        return jsonify({'success': False, 'message': 'Failed to generate signin code'}), 500

@app.route('/auth/verify-signin-code', methods=['POST'])
@cooldown_required(2, per_user=True)
@requires_auth
def auth_verify_signin_code():
    """Verify a signin code from the dashboard"""
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        code = data.get('code', '').strip().upper()
        current_username = session.get('username')
        
        if not code or len(code) != 6:
            return jsonify({'success': False, 'message': 'Invalid code format'}), 400
        
        if not current_username:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        # Check if the code exists for this user
        if current_username not in signin_codes:
            return jsonify({'success': False, 'message': 'No active sign-in code for your account'}), 400
        
        signin_data = signin_codes[current_username]
        
        # Check expiration
        if datetime.utcnow() > signin_data['expires_at']:
            del signin_codes[current_username]
            return jsonify({'success': False, 'message': 'Sign-in code expired'}), 400
        
        # Verify code
        if signin_data['code'].upper() != code:
            return jsonify({'success': False, 'message': 'Invalid sign-in code'}), 400
        
        # Code is valid - keep it active for external use
        return jsonify({
            'success': True,
            'message': 'Sign-in code verified successfully',
            'code': signin_data['code'],
            'expires_at': signin_data['expires_at'].isoformat()
        })
        
    except Exception as e:
        logger.error(f"Verify signin code error: {e}")
        return jsonify({'success': False, 'message': 'Failed to verify code'}), 500

@app.route('/auth/quicksignin', methods=['POST'])
@cooldown_required(2)
def auth_quicksignin():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        username = sanitize_username(data.get('username', '').strip())
        code = data.get('code', '').strip().upper()
        
        if not username or not code or len(code) != 6:
            return jsonify({'success': False, 'message': 'Username and code required'}), 400
        
        user = users_collection.find_one({'username': {'$regex': f'^{re.escape(username)}$', '$options': 'i'}})
        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 404
        
        actual_username = user['username']
        
        if actual_username not in signin_codes:
            return jsonify({'success': False, 'message': 'No active sign-in code'}), 400
        
        signin_data = signin_codes[actual_username]
        
        if datetime.utcnow() > signin_data['expires_at']:
            del signin_codes[actual_username]
            return jsonify({'success': False, 'message': 'Sign-in code expired'}), 400
        
        if signin_data['code'].upper() != code:
            return jsonify({'success': False, 'message': 'Invalid sign-in code'}), 400
        
        # Remove used code and authenticate user
        del signin_codes[actual_username]
        
        # Update last login
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )
        
        session.permanent = True
        session.clear()  # Clear existing session data
        session['user_id'] = str(user['_id'])
        session['username'] = actual_username
        session['login_time'] = datetime.utcnow().isoformat()
        
        return jsonify({
            'success': True,
            'message': 'Quick sign-in successful',
            'user': {
                'username': actual_username,
                'email': user['email'],
                'user_id': str(user['_id'])
            }
        })
        
    except Exception as e:
        logger.error(f"Quick signin error: {e}")
        return jsonify({'success': False, 'message': 'Quick sign-in failed'}), 500

@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

# Enhanced data management routes
@app.route('/data/get', methods=['POST'])
@cooldown_required(1, per_user=True)
@requires_auth
def data_get():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip() if data else ''
        
        if not username or session.get('username') != username:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        user_data_doc = user_data_collection.find_one({'username': username})
        player_data = user_data_doc['data'] if user_data_doc else {}
        
        return jsonify({
            'success': True,
            'data': player_data
        })
        
    except Exception as e:
        logger.error(f"Data get error: {e}")
        return jsonify({'success': False, 'message': 'Failed to retrieve data'}), 500

@app.route('/data/save', methods=['POST'])
@cooldown_required(1, per_user=True)
@requires_auth
def data_save():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        player_data = data.get('data')
        
        if not username or session.get('username') != username:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        if player_data is None:
            return jsonify({'success': False, 'message': 'No player data provided'}), 400
        
        # Validate data size (prevent abuse)
        if len(json.dumps(player_data)) > 1048576:  # 1MB limit
            return jsonify({'success': False, 'message': 'Data too large'}), 400
        
        user_data_collection.update_one(
            {'username': username},
            {
                '$set': {
                    'data': player_data,
                    'updated_at': datetime.utcnow()
                }
            },
            upsert=True
        )
        
        return jsonify({'success': True, 'message': 'Data saved successfully'})
        
    except Exception as e:
        logger.error(f"Data save error: {e}")
        return jsonify({'success': False, 'message': 'Failed to save data'}), 500

# Main route to serve the HTML
@app.route('/', methods=['GET'])
def serve_app():
    return render_template_string(HTML_TEMPLATE)

# Enhanced health check
@app.route('/health', methods=['GET'])
def health_check():
    db_status = 'connected' if db_connected else 'disconnected'
    
    db_info = {}
    if db_connected:
        try:
            user_count = users_collection.count_documents({})
            verified_count = users_collection.count_documents({'verified': True})
            data_count = user_data_collection.count_documents({})
            db_info = {
                'total_users': user_count,
                'verified_users': verified_count,
                'user_data_records': data_count,
                'pending_verifications': len(verification_codes),
                'active_signin_codes': len(signin_codes),
                'active_ip_sessions': len(request_cooldowns),
                'active_user_sessions': len(user_cooldowns)
            }
        except Exception as e:
            db_info = {'error': f'Database stats unavailable: {str(e)}'}
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat(),
        'database_info': db_info,
        'version': '2.0.0-secure'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    
    print("Starting Secure Lockdown Backend v2.0...")
    print(f"Database Status: {'✓ Connected' if db_connected else '✗ Disconnected'}")
    print(f"Email Config: {'✓ Configured' if all([SMTP_SERVER, SENDER_EMAIL, SENDER_PASSWORD]) else '✗ Incomplete'}")
    print(f"Session Security: {'✓ Configured' if app.secret_key != 'your-secret-key-change-this' else '⚠ Using default key'}")
    print("\nSecurity Features:")
    print("- Enhanced input validation and sanitization")
    print("- Fixed MongoDB regex injection vulnerabilities")
    print("- Session regeneration on login")
    print("- Enhanced request cooldowns (IP + user-based)")
    print("- Authentication decorators")
    print("- Rate limiting on sensitive operations")
    print("- Attempt limiting on verification codes")
    print("- Data size limits")
    print("- Proper error handling")
    print("- Enhanced logging")
    
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
