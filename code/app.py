from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import hashlib
import json
import time
from datetime import datetime
from cryptography.fernet import Fernet
import re
import bcrypt

app = Flask(__name__)
app.secret_key = hashlib.sha256(str(time.time()).encode()).hexdigest()  # Dynamic secure secret key
csrf = CSRFProtect(app)  # Enable CSRF protection
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Encryption setup
key = Fernet.generate_key()
cipher = Fernet(key)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username, password_hash, role='user'):
        self.id = username
        self.password_hash = password_hash
        self.role = role

# In-memory user storage (use a database in production)
users = {}

# Blockchain setup
class Block:
    def __init__(self, index, transactions, previous_hash, timestamp=None, nonce=0):
        """Initialize a block with a nonce for added security."""
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculate block hash including nonce."""
        block_string = json.dumps({
            "index": self.index,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        """Initialize blockchain with genesis block."""
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """Create the first block in the chain."""
        return Block(0, "Genesis Block", "0", time.time(), 0)

    def get_latest_block(self):
        """Return the most recent block."""
        return self.chain[-1]

    def add_block(self, transactions):
        """Add a new block with proof-of-work simulation."""
        previous_block = self.get_latest_block()
        nonce = self.proof_of_work(previous_block.hash)
        new_block = Block(len(self.chain), transactions, previous_block.hash, nonce=nonce)
        self.chain.append(new_block)

    def proof_of_work(self, previous_hash):
        """Simple proof-of-work by finding a nonce."""
        nonce = 0
        while True:
            test_hash = hashlib.sha256((str(previous_hash) + str(nonce)).encode()).hexdigest()
            if test_hash.startswith("0000"):  # Difficulty: 4 leading zeros
                return nonce
            nonce += 1

    def is_chain_valid(self):
        """Validate the blockchain integrity."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

# Initialize blockchain and in-memory storage
blockchain = Blockchain()
vehicles = {}  # Changed from properties to vehicles
audit_log = []

def sanitize_input(input_str):
    """Sanitize input to prevent injection attacks."""
    return re.sub(r'[^\w\s,.]', '', input_str)

def encrypt_owner(owner):
    """Encrypt owner name for storage."""
    return cipher.encrypt(owner.encode()).decode()

def decrypt_owner(encrypted_owner):
    """Decrypt owner name for display."""
    return cipher.decrypt(encrypted_owner.encode()).decode()

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username, users[username]['password_hash'], users[username]['role'])
    return None

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    """Register a new user with hashed password."""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        role = 'user'  # Default role; admins set manually in production

        if not (username and password):
            flash('Username and password are required.', 'error')
            return redirect(url_for('register_user'))

        if username in users:
            flash('Username already exists.', 'error')
            return redirect(url_for('register_user'))

        # Hash password
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users[username] = {'password_hash': password_hash, 'role': role}
        audit_log.append(f"[{datetime.now()}] User {username} registered")
        flash('User registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')

        if username in users and bcrypt.checkpw(password.encode(), users[username]['password_hash']):
            user = User(username, users[username]['password_hash'], users[username]['role'])
            login_user(user)
            audit_log.append(f"[{datetime.now()}] User {username} logged in")
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    audit_log.append(f"[{datetime.now()}] User {current_user.id} logged out")
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    """Render the homepage with vehicles, blockchain, and audit log."""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    decrypted_vehicles = {}
    for vid, vehicle in vehicles.items():
        decrypted_vehicles[vid] = vehicle.copy()
        decrypted_vehicles[vid]["owner"] = decrypt_owner(vehicle["owner"])
    return render_template('index.html', vehicles=decrypted_vehicles, blockchain=blockchain, audit_log=audit_log, user_role=current_user.role)

@app.route('/register', methods=['POST'])
@login_required
def register_vehicle():
    """Register a new vehicle with validation and encryption."""
    try:
        registration_number = sanitize_input(request.form.get("registration_number"))
        model = request.form.get("model")
        owner = sanitize_input(request.form.get("owner"))
        price = request.form.get("price")

        # Validate inputs
        if not (registration_number and model and owner and price):
            flash("All fields are required to register a vehicle.", "error")
            return redirect(url_for('index'))
        if not model.isdigit() or int(model) < 1900 or int(model) > 2025:
            flash("Model year must be between 1900 and 2025.", "error")
            return redirect(url_for('index'))
        if not price.isdigit() or int(price) <= 0:
            flash("Price must be a positive number.", "error")
            return redirect(url_for('index'))

        vehicle_id = len(vehicles) + 1
        encrypted_owner = encrypt_owner(owner)
        vehicles[vehicle_id] = {
            "id": vehicle_id,
            "registration_number": registration_number,
            "model": int(model),
            "owner": encrypted_owner,
            "price": int(price)
        }

        # Log action
        audit_log.append(f"[{datetime.now()}] Vehicle {vehicle_id} registered by {current_user.id}")
        flash(f"Vehicle {vehicle_id} registered successfully!", "success")
    except Exception as e:
        flash(f"An error occurred while registering the vehicle: {str(e)}", "error")
    return redirect(url_for('index'))

@app.route('/transfer', methods=['POST'])
@login_required
def transfer_ownership():
    """Transfer vehicle ownership with role-based access."""
    try:
        if current_user.role != 'admin':
            flash("Only admins can transfer ownership.", "error")
            return redirect(url_for('index'))

        vehicle_id = int(request.form.get("vehicle_id"))
        new_owner = sanitize_input(request.form.get("new_owner"))

        if not (vehicle_id and new_owner):
            flash("Vehicle ID and New Owner are required.", "error")
            return redirect(url_for('index'))
        if vehicle_id not in vehicles:
            flash(f"Vehicle {vehicle_id} does not exist!", "error")
            return redirect(url_for('index'))

        old_owner = decrypt_owner(vehicles[vehicle_id]["owner"])
        vehicles[vehicle_id]["owner"] = encrypt_owner(new_owner)

        # Record transaction in blockchain
        transaction = {
            "vehicle_id": vehicle_id,
            "old_owner": old_owner,
            "new_owner": new_owner,
            "timestamp": time.time()
        }
        blockchain.add_block(transaction)

        # Log action
        audit_log.append(f"[{datetime.now()}] Ownership of Vehicle {vehicle_id} transferred from {old_owner} to {new_owner} by {current_user.id}")
        flash(f"Ownership of Vehicle {vehicle_id} transferred to {new_owner}!", "success")
    except Exception as e:
        flash(f"An error occurred during ownership transfer: {str(e)}", "error")
    return redirect(url_for('index'))

@app.route('/transactions', methods=['POST'])
@login_required
def view_transactions():
    """View transaction history for a specific vehicle."""
    try:
        vehicle_id = int(request.form.get("vehicle_id"))
        if vehicle_id not in vehicles:
            flash(f"Vehicle {vehicle_id} does not exist!", "error")
            return redirect(url_for('index'))

        transactions = []
        for block in blockchain.chain:
            if isinstance(block.transactions, dict) and block.transactions.get("vehicle_id") == vehicle_id:
                transactions.append(f"Transferred from {block.transactions['old_owner']} to {block.transactions['new_owner']} at {datetime.fromtimestamp(block.transactions['timestamp'])}")

        return render_template('index.html', vehicles=vehicles, blockchain=blockchain, audit_log=audit_log, transactions={"vehicle_id": vehicle_id, "transactions": transactions}, user_role=current_user.role)
    except Exception as e:
        flash(f"An error occurred while fetching transactions: {str(e)}", "error")
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Create a default admin user for testing
    admin_password = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
    users['admin'] = {'password_hash': admin_password, 'role': 'admin'}
    app.run(debug=True)