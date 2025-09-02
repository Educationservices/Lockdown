from flask import Flask, jsonify, request
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

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Enable CORS for all domains on all routes
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

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
    db = client[MONGO_DATABASE]  # Use environment variable for database name
    users_collection = db['users']  # Collection for user accounts
    user_data_collection = db['user_data']  # Collection for player data
    verification_collection = db['verification_codes']  # Collection for verification codes
    
    # Test connection
    client.admin.command('ping')
    logger.info("✓ Connected to MongoDB successfully!")
    logger.info(f"✓ Database: {MONGO_DATABASE}")
    logger.info(f"✓ Cluster: {MONGO_CLUSTER}")
    db_connected = True
except Exception as e:
    logger.error(f"✗ MongoDB connection failed: {e}")
    client = None
    db = None
    db_connected = False

class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle MongoDB ObjectId"""
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        return super().default(obj)

def generate_verification_code():
    """Generate a 5-digit verification code"""
    return ''.join(random.choices(string.digits, k=5))

def send_verification_email(email, username, code):
    """Send verification email with the styled HTML template"""
    try:
        # Validate email parameters
        if not all([email, username, code]):
            logger.error("Missing parameters for email sending")
            return False
            
        # Validate email format
        if '@' not in email or '.' not in email.split('@')[-1]:
            logger.error(f"Invalid email format: {email}")
            return False
            
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Lockdown - Verify Your Account"
        msg['From'] = SENDER_EMAIL
        msg['To'] = email

        # HTML content with the verification code
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
    .svg-title {{
      margin-bottom: 20px;
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
    .warning {{
      margin-top: 15px;
      font-size: 0.9rem;
      color: #ffb3b3;
    }}
    .username {{
      margin-bottom: 20px;
      font-size: 1.2rem;
      color: #ccc;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="svg-title">
      <svg version="1.1" xmlns="http://www.w3.org/2000/svg" width="300" height="60" viewBox="0,0,923.77757,164.55216">
        <defs>
          <linearGradient x1="25.34505" y1="304.9641" x2="938.59893" y2="304.9641"
            gradientTransform="translate(-7.39325,-100.95928) scale(0.2917,0.2917)"
            gradientUnits="userSpaceOnUse" id="color-1">
            <stop offset="0" stop-color="#ff0000"/>
            <stop offset="1" stop-color="#7e0000"/>
          </linearGradient>
          <linearGradient x1="25.34505" y1="304.9641" x2="938.59893" y2="304.9641"
            gradientUnits="userSpaceOnUse" id="color-2">
            <stop offset="0" stop-color="#ff0000"/>
            <stop offset="1" stop-color="#7e0000"/>
          </linearGradient>
        </defs>
        <g transform="translate(-19.97453,-220.06317)">
          <g fill="url(#color-2)" font-family="Ac437 IBM BIOS, Sans Serif" font-size="40">
            <text transform="translate(25.34533,346.10557) scale(3.42817,3.42817)"
              fill="url(#color-1)">
              <tspan x="0" dy="0">Lockdown</tspan>
            </text>
          </g>
        </g>
      </svg>
    </div>
    <div class="username">Welcome, {username}!</div>
    <div class="code">{code}</div>
    <div class="warning">Never share this code with someone else</div>
    <div style="margin-top: 20px; font-size: 0.8rem; color: #888;">
      This code expires in 10 minutes.
    </div>
  </div>
</body>
</html>
        """

        # Create message parts
        html_part = MIMEText(html, 'html')
        msg.attach(html_part)

        # Send email
        logger.info(f"Attempting to send email to {email} via {SMTP_SERVER}:{SMTP_PORT}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            logger.info(f"Logging in with {SENDER_EMAIL}")
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            logger.info("Login successful, sending message")
            server.send_message(msg)
            logger.info("Email sent successfully")
        
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication failed: {e}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error occurred: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

@app.route('/email-test', methods=['POST'])
def test_email_config():
    """Test endpoint to check email configuration"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    test_email = data.get('email')
    if not test_email:
        return jsonify({'error': 'Email address required'}), 400
        
    # Test email configuration
    config_status = {
        'SMTP_SERVER': SMTP_SERVER if SMTP_SERVER else 'MISSING',
        'SMTP_PORT': SMTP_PORT,
        'SENDER_EMAIL': SENDER_EMAIL if SENDER_EMAIL else 'MISSING',
        'SENDER_PASSWORD': 'SET' if SENDER_PASSWORD else 'MISSING'
    }
    
    # Try to send a test email
    test_code = generate_verification_code()
    success = send_verification_email(test_email, "TestUser", test_code)
    
    return jsonify({
        'email_config': config_status,
        'test_result': 'SUCCESS' if success else 'FAILED',
        'message': 'Test email sent successfully' if success else 'Failed to send test email'
    })

# ... [Keep all your existing routes but add more logging] ...

@app.route('/registeruser/<username>/<email>/<password>', methods=['POST'])
def register_user(username, email, password):
    """Register a new user and send verification email"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    # Validation
    if not all([username, email, password]):
        return jsonify({
            'success': False,
            'message': 'All fields are required'
        }), 400
    
    if len(username) < 3 or len(username) > 20:
        return jsonify({
            'success': False,
            'message': 'Username must be 3-20 characters long'
        }), 400
    
    if len(password) < 6:
        return jsonify({
            'success': False,
            'message': 'Password must be at least 6 characters long'
        }), 400
    
    if '@' not in email:
        return jsonify({
            'success': False,
            'message': 'Invalid email format'
        }), 400
    
    try:
        # Check if username already exists (case insensitive)
        existing_username = users_collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}})
        if existing_username:
            return jsonify({
                'success': False,
                'message': 'Username already exists'
            }), 409
        
        # Check if email already exists (case insensitive)
        existing_email = users_collection.find_one({'email': {'$regex': f'^{email}$', '$options': 'i'}})
        if existing_email:
            return jsonify({
                'success': False,
                'message': 'Email already registered'
            }), 409
        
        # Generate verification code
        verification_code = generate_verification_code()
        
        # Create user document (initially unverified)
        hashed_password = generate_password_hash(password)
        user_doc = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'verified': False,
            'created_at': datetime.utcnow()
        }
        
        # Insert user into database
        result = users_collection.insert_one(user_doc)
        
        # Store verification code
        verification_doc = {
            'username': username,
            'email': email,
            'code': verification_code,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
        verification_collection.insert_one(verification_doc)
        
        # Send verification email
        logger.info(f"Attempting to send verification email to {email}")
        email_sent = send_verification_email(email, username, verification_code)
        
        if not email_sent:
            # If email fails, remove the user and verification code
            users_collection.delete_one({'_id': result.inserted_id})
            verification_collection.delete_one({'username': username})
            return jsonify({
                'success': False,
                'message': 'Failed to send verification email. Please try again.'
            }), 500
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully. Please check your email for verification code.',
            'username': username,
            'user_id': str(result.inserted_id),
            'verification_required': True
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({
            'success': False,
            'message': f'Registration failed: {str(e)}'
        }), 500

# ... [Keep the rest of your routes] ...

if __name__ == '__main__':
    # Get port from environment variable (Render sets this)
    port = int(os.getenv('PORT', 5000))
    
    print("Starting Flask backend with MongoDB...")
    print(f"Database Status: {'✓ Connected' if db_connected else '✗ Disconnected'}")
    print(f"MongoDB Config:")
    print(f"  Username: {MONGO_USERNAME}")
    print(f"  Database: {MONGO_DATABASE}")
    print(f"  Cluster: {MONGO_CLUSTER}")
    print(f"  Password: {'✓ Set' if MONGO_PASSWORD and MONGO_PASSWORD != 'your_password_here' else '✗ Not Set'}")
    print(f"Email Config:")
    print(f"  SMTP Server: {SMTP_SERVER}")
    print(f"  Sender Email: {SENDER_EMAIL}")
    print(f"  Email Password: {'✓ Set' if SENDER_PASSWORD else '✗ Not Set'}")
    
    # Test email configuration
    if SENDER_EMAIL and SENDER_PASSWORD:
        print("\nTesting email configuration...")
        test_code = generate_verification_code()
        test_result = send_verification_email(SENDER_EMAIL, "TestUser", test_code)
        print(f"Email test: {'✓ Success' if test_result else '✗ Failed'}")
    else:
        print("\n✗ Email configuration incomplete")
    
    print("\nAvailable endpoints:")
    print("- POST /email-test (test email configuration)")
    print("- GET  /usernamecheck/<username>")
    print("- GET  /checkcode/<username>")
    print("- POST /login (secure password authentication)")
    print("- POST /registeruser/<username>/<email>/<password>")
    print("- POST /verify/<username>/<code>")
    print("- POST /resend-verification/<username>")
    print("- GET  /<username> (get user data)")
    print("- POST /<username> (save user data)")
    print("- PUT  /<username> (update user data)")
    print("- DELETE /<username> (clear user data)")
    print("- GET  /users (list all users)")
    print("- GET  /health (health check)")
    print("- GET  /stats (database statistics)")
    print(f"\nServer starting on http://0.0.0.0:{port}")
    
    # For production deployment (like Render), disable debug mode
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
