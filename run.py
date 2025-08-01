from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response, flash, session, abort
from flask_cors import CORS
from pymongo import MongoClient
import re
from datetime import datetime, timedelta
import jwt
import os
import secrets
import requests
from functools import lru_cache
import smtplib
from email.mime.text import MIMEText
import random
from cart_utils import add_to_cart, get_cart, remove_from_cart, clear_cart, mongo_to_dict
from bson.objectid import ObjectId
import razorpay
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

llm = HuggingFaceEndpoint(
    repo_id="deepseek-ai/DeepSeek-R1-0528",
    task="text-generation"
)
model = ChatHuggingFace(llm=llm)

# Updated system prompt to always respond in English
system_prompt = (
    "You are ShopLore's helpful chat assistant. "
    "You only answer questions related to ShopLore, its products, services, delivery, and support. "
    "If a user asks something unrelated, politely refuse and guide them back to ShopLore topics. "
    "Always respond in English, even if the user types in another language."
)

model = ChatGoogleGenerativeAI(
    model="gemini-1.5-flash",
    temperature=0.1,
    system_prompt=system_prompt
)

RAZORPAY_KEY_ID = 'rzp_test_y7fTfE3rLFUTtA'
RAZORPAY_KEY_SECRET = 'PvMuimFudbmE2q0TZxKSmIOL'

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_urlsafe(32))
CORS(app)


client = MongoClient('mongodb://localhost:27017/')
db = client['zepto_clone']

JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET:
    JWT_SECRET = secrets.token_urlsafe(32)
    print('WARNING: Using a randomly generated JWT secret key. Sessions will not persist across restarts. Set JWT_SECRET env variable for production.')
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour

OPENFOODFACTS_API = 'https://world.openfoodfacts.org/cgi/search.pl'

EMAIL_ADDRESS = "ShopLore8@gmail.com"
EMAIL_PASSWORD = "shzt ymcs omgu stha"

@lru_cache(maxsize=1)
def fetch_openfoodfacts_products(query=None, category=None):
    params = {
        'action': 'process',
        'json': 1,
        'page_size': 50,
        'fields': 'product_name,image_url,brands,nutrition_grades_tags,code,generic_name,ingredients_text,categories',
        'sort_by': 'unique_scans_n',
    }
    if query:
        params['search_terms'] = query
    if category:
        params['tagtype_0'] = 'categories'
        params['tag_contains_0'] = 'contains'
        params['tag_0'] = category
    try:
        resp = requests.get(OPENFOODFACTS_API, params=params, timeout=5)
        data = resp.json()
        products = []
        for p in data.get('products', []):
            if not p.get('product_name') or not p.get('image_url'):
                continue
            # Compose a long description
            long_desc = p.get('generic_name')
            if not long_desc:
                long_desc = p.get('ingredients_text')
            if not long_desc:
                long_desc = p.get('categories')
            if not long_desc:
                long_desc = f"Brand: {p.get('brands', 'N/A')} | Nutri-Grade: {','.join(p.get('nutrition_grades_tags', []))}"
            products.append({
                'name': p['product_name'],
                'description': f"Brand: {p.get('brands', 'N/A')} | Nutri-Grade: {','.join(p.get('nutrition_grades_tags', []))}",
                'long_description': long_desc,
                'image_url': p['image_url'],
                'price': round(50 + 200 * (hash(p['code']) % 100) / 100, 2)
            })
        return products
    except Exception as e:
        print('OpenFoodFacts API error:', e)
        return []

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

# Helper to get user info from JWT cookie
def get_logged_in_user():
    token = request.cookies.get('access_token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

@app.context_processor
def inject_user():
    user = get_logged_in_user()
    return dict(jwt_user=user)

@app.route('/')
def home():
    user = get_logged_in_user()
    if user and user.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    products = []
    q = request.args.get('q', '').strip().lower()
    category = None
    if q:
        # Try to infer a category from the query for common food types
        if 'water' in q:
            category = 'waters'
        elif 'fruit' in q or 'banana' in q or 'apple' in q:
            category = 'fruits'
        elif 'milk' in q:
            category = 'milks'
        elif 'bread' in q:
            category = 'breads'
        elif 'snack' in q or 'chips' in q:
            category = 'snacks'
        # Add more mappings as needed
    # Always fetch API products
    api_products = fetch_openfoodfacts_products(q if q else None, category)
    local_products = []
    if user:
        product_collection = db['products']
        local_products = [mongo_to_dict(p) for p in product_collection.find()]
    all_products = local_products + api_products
    if q:
        products = [p for p in all_products if q in p.get('name', '').lower() or q in p.get('description', '').lower()]
    else:
        products = all_products
    return render_template('home.html', year=datetime.now().year, products=products)

@app.route('/dashboard')
def user_dashboard():
    user = get_logged_in_user()
    if not user or user.get('role') != 'user':
        return redirect(url_for('login_page'))
    products = []
    q = request.args.get('q', '').strip().lower()
    category = None
    if q:
        # Try to infer a category from the query for common food types
        if 'water' in q:
            category = 'waters'
        elif 'fruit' in q or 'banana' in q or 'apple' in q:
            category = 'fruits'
        elif 'milk' in q:
            category = 'milks'
        elif 'bread' in q:
            category = 'breads'
        elif 'snack' in q or 'chips' in q:
            category = 'snacks'
        # Add more mappings as needed
    product_collection = db['products']
    local_products = [mongo_to_dict(p) for p in product_collection.find()]
    api_products = fetch_openfoodfacts_products(q if q else None, category)
    all_products = local_products + api_products
    if q:
        products = [p for p in all_products if q in p.get('name', '').lower() or q in p.get('description', '').lower()]
    else:
        products = all_products
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

# Helper to send OTP email
def send_otp_email(to_email, otp):
    subject = "ShopLore Email Verification"
    body = f"Your ShopLore verification code is: <b>{otp}</b>\n\nIf you did not request this, please ignore this email."
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        return True
    except Exception as e:
        print('Email send error:', e)
        return False

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        if not username or not password or not role or not email:
            return render_template('register.html', error='All fields are required.')
        valid, msg = is_valid_password(password)
        if not valid:
            return render_template('register.html', error=msg)
        # Check for existing user/admin/delivery by username or email
        if role == 'user':
            user_collection = db['users']
            if user_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
                return render_template('register.html', error='User with this username or email already exists.')
        elif role == 'admin':
            admin_collection = db['admins']
            if admin_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
                return render_template('register.html', error='Admin with this username or email already exists.')
        elif role == 'delivery':
            delivery_collection = db['delivery']
            if delivery_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
                return render_template('register.html', error='Delivery guy with this username or email already exists.')
        else:
            return render_template('register.html', error='Invalid role selected.')
        # Generate OTP and send email
        otp = str(random.randint(100000, 999999))
        if not send_otp_email(email, otp):
            return render_template('register.html', error='Failed to send verification email. Please try again.')
        session['pending_registration'] = {
            'username': username,
            'email': email,
            'password': password,
            'role': role,
            'otp': otp
        }
        return render_template('verify_otp.html', email=email)
    return render_template('register.html', error=None)

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    user_otp = request.form.get('otp')
    pending = session.get('pending_registration')
    if not pending:
        return redirect(url_for('register_page'))
    if user_otp == pending['otp']:
        # Save user/admin/delivery to DB
        if pending['role'] == 'user':
            db['users'].insert_one({
                'username': pending['username'],
                'email': pending['email'],
                'password': pending['password']
            })
        elif pending['role'] == 'admin':
            db['admins'].insert_one({
                'username': pending['username'],
                'email': pending['email'],
                'password': pending['password']
            })
        elif pending['role'] == 'delivery':
            db['delivery'].insert_one({
                'username': pending['username'],
                'email': pending['email'],
                'password': pending['password']
            })
        session.pop('pending_registration', None)
        return redirect(url_for('login_page'))
    else:
        return render_template('verify_otp.html', email=pending['email'], error='Invalid OTP. Please try again.')

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
                payload = {
                    'username': username,
                    'role': 'user',
                    'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
                }
                token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
                resp = make_response(redirect(url_for('home')))
                resp.set_cookie('access_token', token, httponly=True, samesite='Lax')
                return resp
            else:
                return render_template('login.html', error='Invalid user credentials.')
        elif role == 'admin':
            admin_collection = db['admins']
            admin = admin_collection.find_one({"username": username, "password": password})
            if admin:
                payload = {
                    'username': username,
                    'role': 'admin',
                    'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
                }
                token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
                resp = make_response(redirect(url_for('admin_dashboard')))
                resp.set_cookie('access_token', token, httponly=True, samesite='Lax')
                return resp
            else:
                return render_template('login.html', error='Invalid admin credentials.')
        elif role == 'delivery':
            delivery_collection = db['delivery']
            delivery = delivery_collection.find_one({"username": username, "password": password})
            if delivery:
                payload = {
                    'username': username,
                    'role': 'delivery',
                    'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
                }
                token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
                resp = make_response(redirect(url_for('delivery_dashboard')))
                resp.set_cookie('access_token', token, httponly=True, samesite='Lax')
                return resp
            else:
                return render_template('login.html', error='Invalid delivery credentials.')
        else:
            return render_template('login.html', error='Invalid role selected.')
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.set_cookie('access_token', '', expires=0)
    return resp

@app.route('/add-to-cart', methods=['POST'])
def add_to_cart_route():
    user = get_logged_in_user()
    if not user:
        return jsonify({'success': False, 'message': 'Login required'}), 401
    product = request.get_json()
    if not product or not product.get('name'):
        return jsonify({'success': False, 'message': 'Invalid product'}), 400
    # Store cart items in session until payment
    cart_items = session.get('cart_items', [])
    # Convert product in case it has _id
    cart_items.append(mongo_to_dict(product))
    session['cart_items'] = cart_items
    return jsonify({'success': True, 'message': 'Added to cart'})

@app.route('/cart')
def cart_page():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login_page'))
    cart_items = session.get('cart_items', [])
    # Convert all items in case any have _id
    cart_items = [mongo_to_dict(item) for item in cart_items]
    return render_template('cart.html', cart_items=cart_items, year=datetime.now().year)

@app.route('/remove-from-cart', methods=['POST'])
def remove_from_cart_route():
    user = get_logged_in_user()
    if not user:
        return jsonify({'success': False, 'message': 'Login required'}), 401
    data = request.get_json()
    code = data.get('code')
    name = data.get('name')
    if not code and not name:
        return jsonify({'success': False, 'message': 'Invalid product identifier'}), 400
    remove_from_cart(user['username'], code=code, name=name)
    return jsonify({'success': True, 'message': 'Removed from cart'})

@app.route('/payment', methods=['POST'])
def payment_page():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login_page'))
    cart_items = session.get('cart_items', [])
    total = sum(item.get('price', 0) for item in cart_items)
    amount_paise = int(total * 100)
    client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    order = client.order.create({'amount': amount_paise, 'currency': 'INR', 'payment_capture': 1})
    return render_template('payment.html', total=round(total, 2), year=datetime.now().year,
                           razorpay_key=RAZORPAY_KEY_ID, razorpay_order_id=order['id'], amount=amount_paise)

@app.route('/payment', methods=['GET'])
def payment_get():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login_page'))
    payment_id = request.args.get('payment_id')
    if not payment_id:
        return "Payment failed: No payment_id", 400
    cart_items = session.get('cart_items', [])
    db['cart'].update_one(
        {'username': user['username']},
        {'$set': {'items': cart_items, 'status': False, 'payment_id': payment_id}},
        upsert=True
    )
    session['cart_items'] = []
    return redirect(url_for('delivery_page'))

@app.route('/delivery')
def delivery_page():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login_page'))
    # Simulate delivery guy and timing
    delivery_guy = {
        'name': 'Ravi Sharma',
        'phone': '+91-9876543210',
        'photo': 'https://randomuser.me/api/portraits/men/75.jpg'
    }
    eta = 15  # minutes
    # Example delivery location (ShopLore HQ to user, static for demo)
    shop_coords = {'lat': 28.6139, 'lng': 77.2090}  # Delhi
    user_coords = {'lat': 28.7041, 'lng': 77.1025}  # Delhi (random)
    return render_template('delivery.html', delivery_guy=delivery_guy, eta=eta, shop_coords=shop_coords, user_coords=user_coords, year=datetime.now().year)

@app.route('/save-location', methods=['POST'])
def save_location():
    user = get_logged_in_user()
    if not user or user.get('role') != 'user':
        return jsonify({'success': False, 'message': 'Login required'}), 401
    data = request.get_json()
    lat = data.get('lat')
    lng = data.get('lng')
    if lat is None or lng is None:
        return jsonify({'success': False, 'message': 'Missing coordinates'}), 400
    db['users'].update_one({'username': user['username']}, {'$set': {'location': [lat, lng]}})
    return jsonify({'success': True, 'message': 'Location saved'})

@app.route('/delivery-dashboard', methods=['GET'])
def delivery_dashboard():
    import random
    user = get_logged_in_user()
    if not user or user.get('role') != 'delivery':
        return redirect(url_for('login_page'))
    # Only assign carts with status == False and non-empty items
    carts = list(db['cart'].find({'status': False}))
    valid_carts = [c for c in carts if c.get('items')]
    if not valid_carts:
        deliveries = []
    else:
        assigned_cart = random.choice(valid_carts)
        assigned_cart = mongo_to_dict(assigned_cart)
        assigned_user = db['users'].find_one({'username': assigned_cart['username']})
        user_coords = assigned_user['location'] if assigned_user and 'location' in assigned_user else [28.7041, 77.1025]
        deliveries = [{
            'username': assigned_cart['username'],
            'items': [mongo_to_dict(item) for item in assigned_cart['items']],
            'user_coords': user_coords
        }]
    return render_template('delivery_dashboard.html', deliveries=deliveries, year=datetime.now().year)

@app.route('/admin', methods=['GET'])
def admin_dashboard():
    user = get_logged_in_user()
    if not user or user.get('role') != 'admin':
        return redirect(url_for('home'))
    products = [mongo_to_dict(p) for p in db['products'].find()]
    ratings = [mongo_to_dict(r) for r in db['ratings'].find()]
    for r in ratings:
        r['date'] = r.get('date', '')
    return render_template('admin_dashboard.html', products=products, ratings=ratings, year=datetime.now().year)

@app.route('/admin/add-product', methods=['POST'])
def admin_add_product():
    user = get_logged_in_user()
    if not user or user.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    if not data.get('name') or not data.get('description') or not data.get('price'):
        return jsonify({'success': False, 'message': 'Missing fields'}), 400
    db['products'].insert_one({
        'name': data['name'],
        'description': data['description'],
        'price': float(data['price']),
        'image_url': data.get('image_url', '')
    })
    return jsonify({'success': True, 'message': 'Product added successfully'})

@app.route('/admin/remove-product', methods=['POST'])
def admin_remove_product():
    user = get_logged_in_user()
    if not user or user.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    if not data.get('name'):
        return jsonify({'success': False, 'message': 'Missing product name'}), 400
    db['products'].delete_one({'name': data['name']})
    return jsonify({'success': True, 'message': 'Product removed successfully'})

# Save rating from delivery page
@app.route('/save-rating', methods=['POST'])
def save_rating():
    user = get_logged_in_user()
    if not user:
        return jsonify({'success': False, 'message': 'Login required'}), 401
    data = request.get_json()
    value = int(data.get('value', 0))
    db['ratings'].insert_one({
        'username': user['username'],
        'value': value,
        'date': datetime.now().strftime('%Y-%m-%d %H:%M')
    })
    # Send order delivered confirmation email
    user_doc = db['users'].find_one({'username': user['username']})
    if user_doc and user_doc.get('email'):
        try:
            subject = "Order delivered"
            body = f"Your order has been delivered. Thank you for shopping with ShopLore!"
            msg = MIMEText(body, 'html')
            msg['Subject'] = subject
            msg['From'] = EMAIL_ADDRESS
            msg['To'] = user_doc['email']
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                smtp.sendmail(EMAIL_ADDRESS, user_doc['email'], msg.as_string())
        except Exception as e:
            print('Order delivered email send error:', e)
    return jsonify({'success': True, 'message': 'Thank you for your feedback!'})

@app.route('/finish-booking', methods=['POST'])
def finish_booking():
    user = get_logged_in_user()
    if not user or user.get('role') != 'delivery':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'Missing username'}), 400
    db['cart'].update_one({'username': username}, {'$set': {'status': True, 'items': []}})
    return jsonify({'success': True, 'message': 'Booking finished'})

@app.route('/product/<product_id>')
def product_detail(product_id):
    from bson.objectid import ObjectId
    product = None
    # Try to find in local DB by _id if possible
    try:
        product = db['products'].find_one({'_id': ObjectId(product_id)})
        if product:
            product = mongo_to_dict(product)
    except Exception:
        pass
    if not product:
        # Fallback: try to find in API products by name (since API products have no _id)
        all_products = fetch_openfoodfacts_products()
        # Decode product_id if it was urlencoded
        from urllib.parse import unquote
        product_name = unquote(product_id)
        product = next((p for p in all_products if p['name'] == product_name), None)
    if not product:
        return render_template('product.html', not_found=True)
    return render_template('product.html', product=product, year=datetime.now().year)

@app.route('/api/langchain-chat', methods=['POST'])
def langchain_chat():
    data = request.get_json()
    user_message = data.get('message', '')
    if not user_message:
        return jsonify({'success': False, 'error': 'No message provided'}), 400
    result = model.invoke(user_message)
    return jsonify({'success': True, 'response': result.content})

if __name__ == '__main__':
    app.run(debug=True, port=4000)