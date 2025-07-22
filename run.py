from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from pymongo import MongoClient
import re
from datetime import datetime

app = Flask(__name__)
CORS(app)
app.secret_key = 'your_secret_key_here'  # Add a secret key for session management

client = MongoClient('mongodb://localhost:27017/')
db = client['zepto_clone']

def is_valid_password(password):
    # At least 8 characters, one uppercase, one lowercase, one digit, one special character
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

@app.route('/')
def home():
    products = []
    if session.get('username'):
        product_collection = db['products']
        products = list(product_collection.find())
    return render_template('base.html', year=datetime.now().year, products=products)

@app.route('/register/user', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400
    valid, msg = is_valid_password(password)
    if not valid:
        return jsonify({"message": msg}), 400
    user_collection = db['users']
    if user_collection.find_one({"username": username}):
        return jsonify({"message": "User already exists"}), 409
    user_collection.insert_one({"username": username, "password": password})
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/register/admin', methods=['POST'])
def register_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400
    valid, msg = is_valid_password(password)
    if not valid:
        return jsonify({"message": msg}), 400
    admin_collection = db['admins']
    if admin_collection.find_one({"username": username}):
        return jsonify({"message": "Admin already exists"}), 409
    admin_collection.insert_one({"username": username, "password": password})
    return jsonify({"message": "Admin registered successfully"}), 201

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if not username or not password or not role:
            return render_template('login.html', error='All fields are required.')
        if role == 'user':
            user_collection = db['users']
            user = user_collection.find_one({"username": username, "password": password})
            if user:
                session['username'] = username
                session['role'] = 'user'
                return redirect(url_for('home'))
            else:
                return render_template('login.html', error='Invalid user credentials.')
        elif role == 'admin':
            admin_collection = db['admins']
            admin = admin_collection.find_one({"username": username, "password": password})
            if admin:
                session['username'] = username
                session['role'] = 'admin'
                return redirect(url_for('home'))
            else:
                return render_template('login.html', error='Invalid admin credentials.')
        else:
            return render_template('login.html', error='Invalid role selected.')
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(debug=True, port=4000)