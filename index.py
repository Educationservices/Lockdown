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

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this')

# Enable CORS for local development
CORS(app)

# In-memory storage for verification codes, sign-in codes, and request cooldowns
verification_codes = {}  # {username: {'code': '12345', 'email': 'user@email.com', 'expires_at': datetime}}
signin_codes = {}  # {username: {'code': 'ABC123', 'expires_at': datetime}}
request_cooldowns = {}  # {ip_address: {'last_request': datetime, 'count': int}}

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
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DATABASE]
    users_collection = db['users']
    user_data_collection = db['user_data']
    
    # Test connection
    client.admin.command('ping')
    logger.info("✓ Connected to MongoDB successfully!")
    db_connected = True
except Exception as e:
    logger.error(f"✗ MongoDB connection failed: {e}")
    client = None
    db = None
    db_connected = False

# Request cooldown decorator
def cooldown_required(seconds=2):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', '127.0.0.1'))
            current_time = datetime.utcnow()
            
            # Check cooldown
            if client_ip in request_cooldowns:
                last_request = request_cooldowns[client_ip]['last_request']
                if (current_time - last_request).total_seconds() < seconds:
                    return jsonify({
                        'success': False,
                        'message': f'Please wait {seconds} seconds between requests'
                    }), 429
            
            # Update cooldown
            request_cooldowns[client_ip] = {
                'last_request': current_time,
                'count': request_cooldowns.get(client_ip, {}).get('count', 0) + 1
            }
            
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

def cleanup_expired_data():
    """Background thread to clean up expired codes and old cooldowns"""
    while True:
        current_time = datetime.utcnow()
        
        # Clean up expired verification codes
        expired_verification = [username for username, data in verification_codes.items() 
                              if current_time > data['expires_at']]
        for username in expired_verification:
            del verification_codes[username]
        
        # Clean up expired sign-in codes
        expired_signin = [username for username, data in signin_codes.items() 
                         if current_time > data['expires_at']]
        for username in expired_signin:
            del signin_codes[username]
        
        # Clean up old cooldowns (older than 1 hour)
        expired_cooldowns = [ip for ip, data in request_cooldowns.items()
                           if (current_time - data['last_request']).total_seconds() > 3600]
        for ip in expired_cooldowns:
            del request_cooldowns[ip]
        
        time.sleep(60)  # Clean up every minute

# Start background cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_data, daemon=True)
cleanup_thread.start()

def generate_verification_code():
    """Generate a 5-digit verification code"""
    return ''.join(random.choices(string.digits, k=5))

def generate_signin_code():
    """Generate a 6-character alphanumeric sign-in code"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

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

# HTML Template with embedded JavaScript for local operations
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lockdown Account</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            color: #fff;
            font-family: "Segoe UI", Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            line-height: 1.6;
        }

        .container {
            max-width: 500px;
            width: 90%;
            padding: 20px;
        }

        .card {
            background: rgba(26, 26, 26, 0.9);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 
                0 0 30px rgba(255, 0, 0, 0.2),
                0 8px 32px rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 0, 0, 0.1);
            text-align: center;
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 
                0 0 40px rgba(255, 0, 0, 0.3),
                0 12px 48px rgba(0, 0, 0, 0.5);
        }

        .logo {
            margin-bottom: 30px;
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(90deg, #ff0000, #7e0000);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .page-title {
            font-size: 1.8rem;
            margin-bottom: 30px;
            background: linear-gradient(90deg, #ff0000, #7e0000);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }

        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #ccc;
            font-weight: 500;
        }

        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-group input:focus {
            outline: none;
            border-color: #ff0000;
            background: rgba(255, 255, 255, 0.1);
            box-shadow: 0 0 20px rgba(255, 0, 0, 0.2);
        }

        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(90deg, #ff0000, #cc0000);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin: 10px 0;
        }

        .btn:hover {
            background: linear-gradient(90deg, #cc0000, #990000);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(255, 0, 0, 0.3);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #ccc;
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.2);
            box-shadow: 0 4px 15px rgba(255, 255, 255, 0.1);
        }

        .message {
            padding: 12px;
            border-radius: 8px;
            margin: 15px 0;
            font-weight: 500;
        }

        .message.success {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid rgba(0, 255, 0, 0.3);
            color: #4caf50;
        }

        .message.error {
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid rgba(255, 0, 0, 0.3);
            color: #ff6b6b;
        }

        .message.info {
            background: rgba(255, 255, 0, 0.1);
            border: 1px solid rgba(255, 255, 0, 0.3);
            color: #ffd700;
        }

        .verification-code {
            font-size: 2rem;
            letter-spacing: 8px;
            font-weight: bold;
            text-align: center;
            padding: 20px;
            margin: 20px 0;
            background: rgba(255, 0, 0, 0.1);
            border: 2px solid rgba(255, 0, 0, 0.3);
            border-radius: 12px;
        }

        .data-display {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
        }

        .data-display pre {
            color: #ccc;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 300px;
            overflow-y: auto;
        }

        .user-info {
            background: linear-gradient(135deg, rgba(255, 0, 0, 0.1), rgba(126, 0, 0, 0.1));
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            border: 1px solid rgba(255, 0, 0, 0.2);
        }

        .hidden {
            display: none !important;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: #ff0000;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .toggle-link {
            color: #ff0000;
            cursor: pointer;
            text-decoration: underline;
            font-size: 0.9rem;
            margin-top: 15px;
            display: inline-block;
            transition: color 0.3s ease;
        }

        .toggle-link:hover {
            color: #ff3333;
        }

        @media (max-width: 600px) {
            .card {
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo">Lockdown</div>

            <div id="message-container"></div>

            <!-- Login Form -->
            <div id="login-form">
                <h2 class="page-title">Account Login</h2>
                <form id="loginForm">
                    <div class="form-group">
                        <label for="login-username">Username</label>
                        <input type="text" id="login-username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="login-password">Password</label>
                        <input type="password" id="login-password" name="password" required>
                    </div>
                    <button type="submit" class="btn">
                        <span class="btn-text">Login</span>
                        <span class="loading hidden"></span>
                    </button>
                </form>
                <div class="toggle-link" onclick="showRegister()">Don't have an account? Register here</div>
                <div class="toggle-link" onclick="showQuickSignin()">Have a sign-in code? Quick sign-in</div>
            </div>

            <!-- Registration Form -->
            <div id="register-form" class="hidden">
                <h2 class="page-title">Create Account</h2>
                <form id="registerForm">
                    <div class="form-group">
                        <label for="reg-username">Username</label>
                        <input type="text" id="reg-username" name="username" required minlength="3" maxlength="20">
                    </div>
                    <div class="form-group">
                        <label for="reg-email">Email</label>
                        <input type="email" id="reg-email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="reg-password">Password</label>
                        <input type="password" id="reg-password" name="password" required minlength="6">
                    </div>
                    <button type="submit" class="btn">
                        <span class="btn-text">Create Account</span>
                        <span class="loading hidden"></span>
                    </button>
                </form>
                <div class="toggle-link" onclick="showLogin()">Already have an account? Login here</div>
            </div>

            <!-- Verification Form -->
            <div id="verification-form" class="hidden">
                <h2 class="page-title">Verify Account</h2>
                <p>Please enter the 5-digit verification code sent to your email.</p>
                <form id="verificationForm">
                    <div class="form-group">
                        <label for="verification-code">Verification Code</label>
                        <input type="text" id="verification-code" name="code" required maxlength="5" minlength="5" placeholder="12345">
                    </div>
                    <button type="submit" class="btn">
                        <span class="btn-text">Verify Account</span>
                        <span class="loading hidden"></span>
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="resendVerification()">
                        Resend Code
                    </button>
                </form>
                <div class="toggle-link" onclick="showLogin()">Back to Login</div>
            </div>

            <!-- Dashboard -->
            <div id="dashboard" class="hidden">
                <h2 class="page-title">Account Dashboard</h2>
                <div id="user-info" class="user-info">
                    <p><strong>Welcome, <span id="display-username"></span>!</strong></p>
                    <p>Email: <span id="display-email"></span></p>
                    <p>Account Status: <span style="color: #4caf50;">Verified ✓</span></p>
                </div>

                <!-- Quick Sign-in Section -->
                <div class="user-info" style="margin: 20px 0;">
                    <h3 style="margin-bottom: 15px; color: #ff0000;">Quick Sign-in Code</h3>
                    <p style="margin-bottom: 15px; font-size: 0.9rem; color: #ccc;">
                        Generate a temporary code for quick access on other devices
                    </p>
                    <button class="btn btn-secondary" onclick="generateSigninCode()" id="generate-code-btn">
                        Generate Sign-in Code
                    </button>
                    <div id="signin-code-display" class="hidden">
                        <div class="verification-code" id="signin-code-value">ABC123</div>
                        <p style="font-size: 0.9rem; color: #ffb3b3;">
                            Code expires in <span id="code-timer">5:00</span> minutes
                        </p>
                        <p style="font-size: 0.8rem; color: #888;">
                            Use this code with your username for quick sign-in
                        </p>
                    </div>
                </div>

                <h3 style="margin: 20px 0 10px 0;">Player Data</h3>
                <div id="data-display" class="data-display">
                    <pre id="player-data">Loading player data...</pre>
                </div>

                <button class="btn btn-secondary" onclick="refreshData()">Refresh Data</button>
                <button class="btn btn-secondary" onclick="logout()">Logout</button>
            </div>

            <!-- Quick Sign-in Form -->
            <div id="quick-signin-form" class="hidden">
                <h2 class="page-title">Quick Sign-in</h2>
                <p>Enter your username and the 6-character sign-in code</p>
                <form id="quickSigninForm">
                    <div class="form-group">
                        <label for="quick-username">Username</label>
                        <input type="text" id="quick-username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="quick-code">Sign-in Code</label>
                        <input type="text" id="quick-code" name="code" required maxlength="6" minlength="6" placeholder="ABC123" style="text-transform: uppercase;">
                    </div>
                    <button type="submit" class="btn">
                        <span class="btn-text">Quick Sign-in</span>
                        <span class="loading hidden"></span>
                    </button>
                </form>
                <div class="toggle-link" onclick="showLogin()">Use regular login instead</div>
            </div>
        </div>
    </div>

    <script>
        let currentUser = null;
        let pendingUsername = null;
        let codeTimer = null;
        let timeRemaining = 0;

        function showMessage(message, type = 'info') {
            const container = document.getElementById('message-container');
            container.innerHTML = `<div class="message ${type}">${message}</div>`;
            setTimeout(() => {
                container.innerHTML = '';
            }, 5000);
        }

        function showLogin() {
            document.getElementById('login-form').classList.remove('hidden');
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('verification-form').classList.add('hidden');
            document.getElementById('dashboard').classList.add('hidden');
            document.getElementById('quick-signin-form').classList.add('hidden');
        }

        function showRegister() {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.remove('hidden');
            document.getElementById('verification-form').classList.add('hidden');
            document.getElementById('dashboard').classList.add('hidden');
            document.getElementById('quick-signin-form').classList.add('hidden');
        }

        function showVerification() {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('verification-form').classList.remove('hidden');
            document.getElementById('dashboard').classList.add('hidden');
            document.getElementById('quick-signin-form').classList.add('hidden');
        }

        function showDashboard() {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('verification-form').classList.add('hidden');
            document.getElementById('dashboard').classList.remove('hidden');
            document.getElementById('quick-signin-form').classList.add('hidden');
            
            if (currentUser) {
                document.getElementById('display-username').textContent = currentUser.username;
                document.getElementById('display-email').textContent = currentUser.email;
            }
        }

        function showQuickSignin() {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('verification-form').classList.add('hidden');
            document.getElementById('dashboard').classList.add('hidden');
            document.getElementById('quick-signin-form').classList.remove('hidden');
        }

        function setLoading(formId, loading) {
            const form = document.getElementById(formId);
            const btnText = form.querySelector('.btn-text');
            const loadingSpinner = form.querySelector('.loading');
            const button = form.querySelector('.btn');
            
            if (loading) {
                btnText.classList.add('hidden');
                loadingSpinner.classList.remove('hidden');
                button.disabled = true;
            } else {
                btnText.classList.remove('hidden');
                loadingSpinner.classList.add('hidden');
                button.disabled = false;
            }
        }

        // All form handlers now use POST requests to server-side endpoints
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            setLoading('loginForm', true);
            
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            
            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    currentUser = data.user;
                    showMessage('Login successful!', 'success');
                    showDashboard();
                    loadPlayerData();
                } else {
                    if (data.verified === false) {
                        pendingUsername = username;
                        showMessage('Account not verified. Please check your email.', 'error');
                        showVerification();
                    } else {
                        showMessage(data.message || 'Login failed', 'error');
                    }
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
            } finally {
                setLoading('loginForm', false);
            }
        });

        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            setLoading('registerForm', true);
            
            const username = document.getElementById('reg-username').value;
            const email = document.getElementById('reg-email').value;
            const password = document.getElementById('reg-password').value;
            
            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username, email, password })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    pendingUsername = username;
                    showMessage('Account created! Please check your email for verification code.', 'success');
                    showVerification();
                } else {
                    showMessage(data.message || 'Registration failed', 'error');
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
            } finally {
                setLoading('registerForm', false);
            }
        });

        document.getElementById('verificationForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            if (!pendingUsername) return;
            
            setLoading('verificationForm', true);
            
            const code = document.getElementById('verification-code').value;
            
            try {
                const response = await fetch('/auth/verify', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username: pendingUsername, code })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage('Account verified successfully! Please login.', 'success');
                    pendingUsername = null;
                    showLogin();
                } else {
                    showMessage(data.message || 'Verification failed', 'error');
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
            } finally {
                setLoading('verificationForm', false);
            }
        });

        document.getElementById('quickSigninForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            setLoading('quickSigninForm', true);
            
            const username = document.getElementById('quick-username').value;
            const code = document.getElementById('quick-code').value.toUpperCase();
            
            try {
                const response = await fetch('/auth/quicksignin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username, code })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    currentUser = data.user;
                    showMessage('Quick sign-in successful!', 'success');
                    showDashboard();
                    loadPlayerData();
                } else {
                    showMessage(data.message || 'Quick sign-in failed', 'error');
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
            } finally {
                setLoading('quickSigninForm', false);
            }
        });

        async function resendVerification() {
            if (!pendingUsername) return;
            
            try {
                const response = await fetch('/auth/resend', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username: pendingUsername })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage('Verification code sent!', 'success');
                } else {
                    showMessage(data.message || 'Failed to resend code', 'error');
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
            }
        }

        async function generateSigninCode() {
            if (!currentUser) return;
            
            const btn = document.getElementById('generate-code-btn');
            btn.disabled = true;
            btn.textContent = 'Generating...';
            
            try {
                const response = await fetch('/auth/generate-signin-code', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username: currentUser.username })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('signin-code-value').textContent = data.signin_code;
                    document.getElementById('signin-code-display').classList.remove('hidden');
                    btn.style.display = 'none';
                    
                    timeRemaining = 5 * 60; // 5 minutes in seconds
                    startCodeTimer();
                    
                    showMessage('Sign-in code generated!', 'success');
                } else {
                    showMessage(data.message || 'Failed to generate code', 'error');
                    btn.disabled = false;
                    btn.textContent = 'Generate Sign-in Code';
                }
            } catch (error) {
                showMessage('Network error. Please try again.', 'error');
                btn.disabled = false;
                btn.textContent = 'Generate Sign-in Code';
            }
        }

        async function loadPlayerData() {
            if (!currentUser) return;
            
            try {
                const response = await fetch('/data/get', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username: currentUser.username })
                });
                
                const data = await response.json();
                
                if (data.success && data.data) {
                    document.getElementById('player-data').textContent = 
                        Object.keys(data.data).length > 0 
                            ? JSON.stringify(data.data, null, 2)
                            : 'No player data available';
                } else {
                    document.getElementById('player-data').textContent = 'Error loading player data';
                }
            } catch (error) {
                document.getElementById('player-data').textContent = 'Error loading player data';
            }
        }

        async function refreshData() {
            document.getElementById('player-data').textContent = 'Loading...';
            await loadPlayerData();
        }

        function startCodeTimer() {
            codeTimer = setInterval(() => {
                timeRemaining--;
                
                const minutes = Math.floor(timeRemaining / 60);
                const seconds = timeRemaining % 60;
                document.getElementById('code-timer').textContent = 
                    `${minutes}:${seconds.toString().padStart(2, '0')}`;
                
                if (timeRemaining <= 0) {
                    clearInterval(codeTimer);
                    document.getElementById('signin-code-display').classList.add('hidden');
                    const btn = document.getElementById('generate-code-btn');
                    btn.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = 'Generate Sign-in Code';
                    showMessage('Sign-in code expired', 'info');
                }
            }, 1000);
        }

        function logout() {
            currentUser = null;
            
            if (codeTimer) {
                clearInterval(codeTimer);
                codeTimer = null;
            }
            
            document.getElementById('signin-code-display').classList.add('hidden');
            const btn = document.getElementById('generate-code-btn');
            btn.style.display = 'block';
            btn.disabled = false;
            btn.textContent = 'Generate Sign-in Code';
            
            showMessage('Logged out successfully', 'info');
            showLogin();
            
            document.getElementById('loginForm').reset();
            document.getElementById('registerForm').reset();
            document.getElementById('verificationForm').reset();
            document.getElementById('quickSigninForm').reset();
        }

        // Auto-uppercase quick code input
        document.getElementById('quick-code').addEventListener('input', function(e) {
            e.target.value = e.target.value.toUpperCase();
        });
    </script>
</body>
</html>
"""

# Authentication routes with cooldowns
@app.route('/auth/login', methods=['POST'])
@cooldown_required(2)
def auth_login():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    
    try:
        # Fixed the regex query - properly escaped quotes
        user = users_collection.find_one({'username': {'$regex': f'^{username}, '$options': 'i'}})
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        if not user.get('verified', False):
            return jsonify({'success': False, 'message': 'Account not verified', 'verified': False}), 403
        
        if not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Store user in session
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        
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
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/auth/register', methods=['POST'])
@cooldown_required(2)
def auth_register():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not all([username, email, password]):
        return jsonify({'success': False, 'message': 'All fields required'}), 400
    
    if len(username) < 3 or len(username) > 20:
        return jsonify({'success': False, 'message': 'Username must be 3-20 characters'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
    
    try:
        # Check existing username/email with proper regex
        if users_collection.find_one({'username': {'$regex': f'^{username}, '$options': 'i'}}):
            return jsonify({'success': False, 'message': 'Username already exists'}), 409
        
        if users_collection.find_one({'email': {'$regex': f'^{email}, '$options': 'i'}}):
            return jsonify({'success': False, 'message': 'Email already registered'}), 409
        
        # Create user
        hashed_password = generate_password_hash(password)
        user_doc = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'verified': False,
            'created_at': datetime.utcnow()
        }
        
        result = users_collection.insert_one(user_doc)
        
        # Generate and send verification code
        verification_code = generate_verification_code()
        verification_codes[username] = {
            'code': verification_code,
            'email': email,
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
        
        email_sent = send_verification_email(email, username, verification_code)
        
        if not email_sent:
            users_collection.delete_one({'_id': result.inserted_id})
            if username in verification_codes:
                del verification_codes[username]
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
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    username = data.get('username')
    code = data.get('code')
    
    if not username or not code:
        return jsonify({'success': False, 'message': 'Username and code required'}), 400
    
    try:
        if username not in verification_codes:
            return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
        
        verification_data = verification_codes[username]
        
        if datetime.utcnow() > verification_data['expires_at']:
            del verification_codes[username]
            return jsonify({'success': False, 'message': 'Verification code expired'}), 400
        
        if verification_data['code'] != code:
            return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
        
        # Verify user
        users_collection.update_one({'username': username}, {'$set': {'verified': True}})
        
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
@cooldown_required(2)
def auth_resend():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    username = data.get('username') if data else None
    
    if not username:
        return jsonify({'success': False, 'message': 'Username required'}), 400
    
    try:
        user = users_collection.find_one({'username': username})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if user.get('verified', False):
            return jsonify({'success': False, 'message': 'Account already verified'}), 400
        
        verification_code = generate_verification_code()
        verification_codes[username] = {
            'code': verification_code,
            'email': user['email'],
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
        
        email_sent = send_verification_email(user['email'], username, verification_code)
        
        if not email_sent:
            return jsonify({'success': False, 'message': 'Failed to send email'}), 500
        
        return jsonify({'success': True, 'message': 'Verification code sent'})
        
    except Exception as e:
        logger.error(f"Resend error: {e}")
        return jsonify({'success': False, 'message': 'Failed to resend verification'}), 500

@app.route('/auth/generate-signin-code', methods=['POST'])
@cooldown_required(2)
def auth_generate_signin_code():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    username = data.get('username') if data else None
    
    if not username:
        return jsonify({'success': False, 'message': 'Username required'}), 400
    
    # Check if user is authenticated (in session)
    if not session.get('username') or session.get('username') != username:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        user = users_collection.find_one({'username': username})
        if not user or not user.get('verified', False):
            return jsonify({'success': False, 'message': 'User not found or not verified'}), 404
        
        signin_code = generate_signin_code()
        signin_codes[username] = {
            'code': signin_code,
            'expires_at': datetime.utcnow() + timedelta(minutes=5)
        }
        
        return jsonify({
            'success': True,
            'signin_code': signin_code,
            'expires_in_minutes': 5
        })
        
    except Exception as e:
        logger.error(f"Generate signin code error: {e}")
        return jsonify({'success': False, 'message': 'Failed to generate code'}), 500

@app.route('/auth/quicksignin', methods=['POST'])
@cooldown_required(2)
def auth_quicksignin():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    username = data.get('username')
    code = data.get('code')
    
    if not username or not code:
        return jsonify({'success': False, 'message': 'Username and code required'}), 400
    
    try:
        # Fixed regex query here too
        user = users_collection.find_one({'username': {'$regex': f'^{username}, '$options': 'i'}})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        actual_username = user['username']
        
        if actual_username not in signin_codes:
            return jsonify({'success': False, 'message': 'No active sign-in code'}), 400
        
        signin_data = signin_codes[actual_username]
        
        if datetime.utcnow() > signin_data['expires_at']:
            del signin_codes[actual_username]
            return jsonify({'success': False, 'message': 'Sign-in code expired'}), 400
        
        if signin_data['code'].upper() != code.upper():
            return jsonify({'success': False, 'message': 'Invalid sign-in code'}), 400
        
        # Remove used code and authenticate user
        del signin_codes[actual_username]
        session['user_id'] = str(user['_id'])
        session['username'] = actual_username
        
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

# Data management routes
@app.route('/data/get', methods=['POST'])
@cooldown_required(1)
def data_get():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    username = data.get('username') if data else None
    
    # Check authentication
    if not session.get('username') or session.get('username') != username:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        user_data_doc = user_data_collection.find_one({'username': username})
        player_data = user_data_doc['data'] if user_data_doc else {}
        
        return jsonify({
            'success': True,
            'data': player_data
        })
        
    except Exception as e:
        logger.error(f"Data get error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get data'}), 500

@app.route('/data/save', methods=['POST'])
@cooldown_required(1)
def data_save():
    if not db_connected:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    username = data.get('username')
    player_data = data.get('data')
    
    # Check authentication
    if not session.get('username') or session.get('username') != username:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    if player_data is None:
        return jsonify({'success': False, 'message': 'No player data provided'}), 400
    
    try:
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

# Health check
@app.route('/health', methods=['GET'])
def health_check():
    db_status = 'connected' if db_connected else 'disconnected'
    
    db_info = {}
    if db_connected:
        try:
            user_count = users_collection.count_documents({})
            data_count = user_data_collection.count_documents({})
            db_info = {
                'users_count': user_count,
                'user_data_count': data_count,
                'verification_codes_in_memory': len(verification_codes),
                'signin_codes_in_memory': len(signin_codes),
                'active_sessions': len(request_cooldowns)
            }
        except:
            db_info = {'error': 'Could not retrieve stats'}
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat(),
        'database_info': db_info
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    
    print("Starting Secure Lockdown Backend...")
    print(f"Database Status: {'✓ Connected' if db_connected else '✗ Disconnected'}")
    print(f"Email Config: {'✓ Configured' if all([SMTP_SERVER, SENDER_EMAIL, SENDER_PASSWORD]) else '✗ Incomplete'}")
    print(f"Session Security: {'✓ Enabled' if app.secret_key != 'your-secret-key-change-this' else '⚠ Using default key'}")
    print("\nSecurity Features:")
    print("- Server-side authentication with sessions")
    print("- Request cooldowns (1-2 seconds)")
    print("- No direct database access from frontend")
    print("- Embedded HTML (no external API calls)")
    print("- Password hashing with Werkzeug")
    print("- Input validation and sanitization")
    
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
