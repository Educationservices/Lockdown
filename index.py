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
import threading
import time

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

# In-memory storage for verification codes and sign-in codes
verification_codes = {}  # {username: {'code': '12345', 'email': 'user@email.com', 'expires_at': datetime}}
signin_codes = {}  # {username: {'code': 'ABC123', 'expires_at': datetime}}

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

def cleanup_expired_codes():
    """Background thread to clean up expired codes"""
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
        
        if expired_verification or expired_signin:
            logger.info(f"Cleaned up {len(expired_verification)} verification codes and {len(expired_signin)} sign-in codes")
        
        # Sleep for 1 minute before next cleanup
        time.sleep(60)

# Start background cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_codes, daemon=True)
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

@app.route('/usernamecheck/<username>', methods=['GET'])
def check_username(username):
    """Check if username is available"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
        
    if not username:
        return jsonify({
            'available': False, 
            'message': 'Username cannot be empty'
        }), 400
    
    # Basic validation
    if len(username) < 3 or len(username) > 20:
        return jsonify({
            'available': False, 
            'message': 'Username must be 3-20 characters long'
        }), 400
    
    # Check if username exists (case insensitive)
    existing_user = users_collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}})
    available = existing_user is None
    
    return jsonify({
        'username': username,
        'available': available,
        'message': 'Username available' if available else 'Username already taken'
    })

@app.route('/checkcode/<username>', methods=['GET'])
def check_code(username):
    """Check if user has a valid verification code"""
    if not username:
        return jsonify({
            'has_code': False,
            'message': 'Username cannot be empty'
        }), 400
    
    try:
        # Check in-memory verification codes
        has_code = username in verification_codes and datetime.utcnow() < verification_codes[username]['expires_at']
        
        return jsonify({
            'username': username,
            'has_code': has_code,
            'message': 'Active verification code found' if has_code else 'No active verification code',
            'expires_at': verification_codes[username]['expires_at'].isoformat() if has_code else None
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to check verification code: {str(e)}'
        }), 500

@app.route('/getsignincode/<username>', methods=['GET'])
def get_signin_code(username):
    """Generate and return a sign-in code for quick login"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    if not username:
        return jsonify({
            'success': False,
            'message': 'Username cannot be empty'
        }), 400
    
    try:
        # Find user (case insensitive)
        user = users_collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}})
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
        
        if not user.get('verified', False):
            return jsonify({
                'success': False,
                'message': 'Account not verified'
            }), 403
        
        # Generate new sign-in code
        signin_code = generate_signin_code()
        
        # Store sign-in code in memory (expires in 5 minutes)
        signin_codes[user['username']] = {
            'code': signin_code,
            'expires_at': datetime.utcnow() + timedelta(minutes=5)
        }
        
        logger.info(f"Generated sign-in code for {user['username']}: {signin_code}")
        
        return jsonify({
            'success': True,
            'username': user['username'],
            'signin_code': signin_code,
            'expires_in_minutes': 5,
            'message': 'Sign-in code generated successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating sign-in code: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to generate sign-in code'
        }), 500

@app.route('/quicksignin/<username>/<code>', methods=['POST'])
def quick_signin(username, code):
    """Quick sign-in using generated code"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    if not username or not code:
        return jsonify({
            'success': False,
            'message': 'Username and code are required'
        }), 400
    
    try:
        # Find user (case insensitive)
        user = users_collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}})
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
        
        actual_username = user['username']
        
        # Check if sign-in code exists and is valid
        if actual_username not in signin_codes:
            return jsonify({
                'success': False,
                'message': 'No active sign-in code found'
            }), 400
        
        signin_data = signin_codes[actual_username]
        
        # Check if code has expired
        if datetime.utcnow() > signin_data['expires_at']:
            del signin_codes[actual_username]
            return jsonify({
                'success': False,
                'message': 'Sign-in code has expired'
            }), 400
        
        # Check if code matches
        if signin_data['code'].upper() != code.upper():
            return jsonify({
                'success': False,
                'message': 'Invalid sign-in code'
            }), 400
        
        # Remove used sign-in code
        del signin_codes[actual_username]
        
        # Successful quick sign-in
        return jsonify({
            'success': True,
            'message': 'Quick sign-in successful',
            'username': actual_username,
            'user_id': str(user['_id']),
            'verified': True,
            'email': user['email']
        }), 200
        
    except Exception as e:
        logger.error(f"Quick sign-in error: {e}")
        return jsonify({
            'success': False,
            'message': 'Quick sign-in failed'
        }), 500

@app.route('/login', methods=['POST'])
def login_user():
    """Login user with username and password (secure POST method)"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    # Get JSON data from request body
    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'message': 'No data provided'
        }), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({
            'success': False,
            'message': 'Username and password are required'
        }), 400
    
    try:
        # Find user (case insensitive)
        user = users_collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}})
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'Invalid username or password'  # Don't reveal if user exists
            }), 401
        
        # Check if user is verified
        if not user.get('verified', False):
            return jsonify({
                'success': False,
                'message': 'Account not verified. Please check your email.',
                'verified': False
            }), 403
        
        # Check if password matches (using werkzeug's check_password_hash)
        password_matches = check_password_hash(user['password'], password)
        
        if not password_matches:
            return jsonify({
                'success': False,
                'message': 'Invalid username or password'  # Don't reveal if user exists
            }), 401
        
        # Successful login
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'username': user['username'],  # Return actual username (preserving case)
            'user_id': str(user['_id']),
            'verified': True,
            'email': user['email']
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Login failed. Please try again.'
        }), 500

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
        
        # Store verification code in memory
        verification_codes[username] = {
            'code': verification_code,
            'email': email,
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
        
        # Send verification email
        logger.info(f"Attempting to send verification email to {email}")
        email_sent = send_verification_email(email, username, verification_code)
        
        if not email_sent:
            # If email fails, remove the user and verification code
            users_collection.delete_one({'_id': result.inserted_id})
            if username in verification_codes:
                del verification_codes[username]
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

@app.route('/verify/<username>/<code>', methods=['POST'])
def verify_user(username, code):
    """Verify user with verification code"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        # Check in-memory verification codes
        if username not in verification_codes:
            return jsonify({
                'success': False,
                'message': 'Invalid verification code'
            }), 400
        
        verification_data = verification_codes[username]
        
        # Check if code has expired
        if datetime.utcnow() > verification_data['expires_at']:
            # Remove expired code
            del verification_codes[username]
            return jsonify({
                'success': False,
                'message': 'Verification code has expired'
            }), 400
        
        # Check if code matches
        if verification_data['code'] != code:
            return jsonify({
                'success': False,
                'message': 'Invalid verification code'
            }), 400
        
        # Update user as verified
        users_collection.update_one(
            {'username': username},
            {'$set': {'verified': True}}
        )
        
        # Initialize empty data document for the verified user
        user_data_doc = {
            'username': username,
            'data': {},
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        user_data_collection.insert_one(user_data_doc)
        
        # Remove verification code from memory
        del verification_codes[username]
        
        return jsonify({
            'success': True,
            'message': 'Account verified successfully',
            'username': username
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Verification failed: {str(e)}'
        }), 500

@app.route('/resend-verification/<username>', methods=['POST'])
def resend_verification(username):
    """Resend verification email"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        # Find user
        user = users_collection.find_one({'username': username})
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
        
        if user.get('verified', False):
            return jsonify({
                'success': False,
                'message': 'Account is already verified'
            }), 400
        
        # Generate new verification code
        verification_code = generate_verification_code()
        
        # Store new verification code in memory
        verification_codes[username] = {
            'code': verification_code,
            'email': user['email'],
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
        
        # Send verification email
        email_sent = send_verification_email(user['email'], username, verification_code)
        
        if not email_sent:
            return jsonify({
                'success': False,
                'message': 'Failed to send verification email'
            }), 500
        
        return jsonify({
            'success': True,
            'message': 'Verification email sent successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to resend verification: {str(e)}'
        }), 500

@app.route('/<username>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def handle_user_data(username):
    """Handle JSON data storage and retrieval for users"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        # Check if user exists (case insensitive)
        user = users_collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}})
        if not user:
            return jsonify({
                'error': 'User not found'
            }), 404
        
        if not user.get('verified', False):
            return jsonify({
                'error': 'Account not verified. Please verify your email first.'
            }), 403
        
        # Get the actual username from database (preserving case)
        actual_username = user['username']
        
        if request.method == 'GET':
            # Return user's data
            user_data_doc = user_data_collection.find_one({'username': actual_username})
            data = user_data_doc['data'] if user_data_doc else {}
            
            return jsonify({
                'username': actual_username,
                'data': data
            })
        
        elif request.method in ['POST', 'PUT']:
            # Store/update user's data
            json_data = request.get_json()
            
            if json_data is None:
                return jsonify({
                    'error': 'No JSON data provided'
                }), 400
            
            # Update or create user data document
            user_data_collection.update_one(
                {'username': actual_username},
                {
                    '$set': {
                        'data': json_data,
                        'updated_at': datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            return jsonify({
                'success': True,
                'message': 'Data saved successfully',
                'username': actual_username
            })
        
        elif request.method == 'DELETE':
            # Clear user's data
            user_data_collection.update_one(
                {'username': actual_username},
                {
                    '$set': {
                        'data': {},
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            
            return jsonify({
                'success': True,
                'message': 'User data cleared',
                'username': actual_username
            })
            
    except Exception as e:
        return jsonify({
            'error': f'Database operation failed: {str(e)}'
        }), 500

@app.route('/users', methods=['GET'])
def list_users():
    """List all registered users (without sensitive info)"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        users_cursor = users_collection.find({}, {'password': 0})  # Exclude password field
        user_list = []
        
        for user in users_cursor:
            user_list.append({
                'username': user['username'],
                'email': user['email'],
                'verified': user.get('verified', False),
                'created_at': user.get('created_at', 'Unknown'),
                'user_id': str(user['_id'])
            })
        
        return jsonify({
            'users': user_list,
            'total': len(user_list)
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to retrieve users: {str(e)}'
        }), 500

@app.route('/', methods=['GET'])
def root():
    """Root endpoint for basic health check"""
    return jsonify({
        'status': 'Lockdown API is running',
        'version': '1.0.0',
        'endpoints': [
            '/health',
            '/stats', 
            '/users',
            '/usernamecheck/<username>',
            '/checkcode/<username>',
            '/getsignincode/<username>',
            '/quicksignin/<username>/<code>',
            '/login (POST)',
            '/registeruser/<username>/<email>/<password>',
            '/verify/<username>/<code>',
            '/resend-verification/<username>',
            '/<username>'
        ]
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    db_status = 'connected' if db_connected else 'disconnected'
    
    db_info = {}
    if db_connected:
        try:
            # Get database stats
            user_count = users_collection.count_documents({})
            data_count = user_data_collection.count_documents({})
            db_info = {
                'users_count': user_count,
                'user_data_count': data_count,
                'verification_codes_in_memory': len(verification_codes),
                'signin_codes_in_memory': len(signin_codes)
            }
        except:
            db_info = {'error': 'Could not retrieve stats'}
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat(),
        'database_info': db_info
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get database statistics"""
    if not db_connected:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        stats = {
            'total_users': users_collection.count_documents({}),
            'verified_users': users_collection.count_documents({'verified': True}),
            'unverified_users': users_collection.count_documents({'verified': False}),
            'total_user_data_records': user_data_collection.count_documents({}),
            'users_with_data': user_data_collection.count_documents({'data': {'$ne': {}}}),
            'verification_codes_in_memory': len(verification_codes),
            'signin_codes_in_memory': len(signin_codes),
            'recent_registrations': users_collection.count_documents({
                'created_at': {'$gte': datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)}
            })
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to retrieve stats: {str(e)}'
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error'
    }), 500

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
    
    print("\nMemory-based verification and sign-in codes initialized")
    print("Background cleanup thread started for expired codes")
    
    print("\nAvailable endpoints:")
    print("- POST /email-test (test email configuration)")
    print("- GET  /usernamecheck/<username>")
    print("- GET  /checkcode/<username>")
    print("- GET  /getsignincode/<username> (NEW: generate sign-in code)")
    print("- POST /quicksignin/<username>/<code> (NEW: quick sign-in with code)")
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
