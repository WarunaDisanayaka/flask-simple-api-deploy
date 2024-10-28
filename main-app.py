from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint
from datetime import datetime
import pytz
import jwt
from functools import wraps


from flask_cors import CORS  # Import CORS

app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

# Configuration
app.config['SECRET_KEY'] = '56314fbd3c16bf6b128cd3e70bd12236a19b43b5c2998a1d180783364448bc86'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:adminpwd123@worker.cdw0c4uairxc.eu-north-1.rds.amazonaws.com/work'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'warunadesigns@gmail.com'
app.config['MAIL_PASSWORD'] = 'gxnu znaq luof auom'

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)

# Models
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    user_email = db.Column(db.String(191), unique=True, nullable=False)
    user_pw = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=False)

    def __init__(self, username, user_email, user_pw):
        self.username = username
        self.user_email = user_email
        self.user_pw = generate_password_hash(user_pw)

    def check_password(self, password):
        return check_password_hash(self.user_pw, password)
    
class Worker(db.Model):
    __tablename__ = 'workers'
    worker_id = db.Column(db.Integer, primary_key=True)
    worker_name = db.Column(db.String(255), nullable=False)
    worker_email = db.Column(db.String(191), unique=True, nullable=False)
    worker_password = db.Column(db.String(255), nullable=False)
    worker_contact = db.Column(db.String(10), unique=True, nullable=False)
    worker_city = db.Column(db.Integer, nullable=False)
    worker_type = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=False)

    def __init__(self, worker_name, worker_email, worker_password, worker_contact, worker_city, worker_type):
        self.worker_name = worker_name
        self.worker_email = worker_email
        self.worker_password = generate_password_hash(worker_password)
        self.worker_contact = worker_contact
        self.worker_city = worker_city
        self.worker_type = worker_type

    def check_password(self, password):
        return check_password_hash(self.worker_password, password)

class OTP(db.Model):
    __tablename__ = 'otps'
    otp_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    otp = db.Column(db.Integer, nullable=False)
    created_date = db.Column(db.DateTime)

    def __init__(self, user_id, otp):
        self.user_id = user_id
        self.otp = otp
        self.created_date = datetime.now(pytz.timezone('Asia/Colombo'))

class WorkerOTP(db.Model):
    __tablename__ = 'worker_otps'
    otp_id = db.Column(db.Integer, primary_key=True)
    worker_id = db.Column(db.Integer, db.ForeignKey('workers.worker_id'), nullable=False)
    otp = db.Column(db.Integer, nullable=False)
    created_date = db.Column(db.DateTime)

    def __init__(self, worker_id, otp):
        self.worker_id = worker_id
        self.otp = otp
        self.created_date = datetime.now(pytz.timezone('Asia/Colombo'))

class City(db.Model):
    __tablename__ = 'cities'
    id = db.Column(db.Integer, primary_key=True)
    city_name = db.Column(db.String(45), nullable=False, unique=True)

# Order model
class Order(db.Model):
    __tablename__ = 'orders'
    order_id = db.Column(db.Integer, primary_key=True)
    problem_type = db.Column(db.String(255), nullable=False)
    problem_details = db.Column(db.Text, nullable=False)
    address = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    worker_id = db.Column(db.Integer, db.ForeignKey('workers.worker_id'), nullable=False)
    order_status = db.Column(db.String(50), nullable=False, default='Pending')
    rating = db.Column(db.Integer)
    remarks = db.Column(db.Text)
    selected_date = db.Column(db.Date, nullable=False)
    created_date = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    updated_date = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp(), nullable=False)
    
    worker = db.relationship('Worker', backref=db.backref('orders', lazy=True))

    def __init__(self, problem_type, problem_details, address, user_id, worker_id, selected_date):
        self.problem_type = problem_type
        self.problem_details = problem_details
        self.address = address
        self.user_id = user_id
        self.worker_id = worker_id
        self.selected_date = selected_date

    def to_dict(self):
        return {
            'order_id': self.order_id,
            'problem_type': self.problem_type,
            'problem_details': self.problem_details,
            'address': self.address,
            'username': User.query.get(self.user_id).username,
            'worker_name': self.worker.worker_name,  
            'order_status': self.order_status,
            'rating': self.rating,
            'remarks': self.remarks,
            'selected_date': self.selected_date.isoformat(),
            'created_date': self.created_date.isoformat(),
            'updated_date': self.updated_date.isoformat()
        }

# Function to verify JWT token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user_id, *args, **kwargs)

    return decorated

def worker_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Worker token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if 'worker_id' in data:
                current_worker_id = data['worker_id']
                return f(current_worker_id, *args, **kwargs)
            else:
                return jsonify({'message': 'Worker token is invalid'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Worker token is expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid worker token'}), 401

    return decorated

# Routes

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user_email = data.get('user_email')
    user_pw = data.get('user_pw')

    # Find user by email
    user = User.query.filter_by(user_email=user_email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Check password
    if not user.check_password(user_pw):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Check if user is active
    if not user.is_active:
        return jsonify({'message': 'User is not active'}), 403

    # Generate JWT token
    token = jwt.encode({'user_id': user.user_id}, app.config['SECRET_KEY'], algorithm='HS256')

    # Return token and success message
    return jsonify({'token': token, 'message': 'Login successful'}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    user_email = data['user_email']
    user_pw = data['user_pw']

    # Check if user already exists
    user = User.query.filter_by(user_email=user_email).first()
    if user:
        return jsonify({'message': 'User already exists'}), 400

    # Create new user with hashed password
    new_user = User(username=username, user_email=user_email, user_pw=user_pw)
    db.session.add(new_user)
    db.session.commit()

    # Generate OTP
    otp_code = randint(100000, 999999)
    new_otp = OTP(user_id=new_user.user_id, otp=otp_code)
    db.session.add(new_otp)
    db.session.commit()

    # Send OTP via email
    send_otp_email(user_email, otp_code)

    return jsonify({'message': 'User registered successfully. Please check your email for the OTP.', 'user_id': new_user.user_id}), 201

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data['user_id']
    otp_code = data['otp']

    # Find user
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Verify OTP
    otp = OTP.query.filter_by(user_id=user_id, otp=otp_code).order_by(OTP.created_date.desc()).first()
    if not otp:
        return jsonify({'message': 'Invalid OTP'}), 400

    # Update user status
    user.is_active = True
    db.session.commit()

    return jsonify({'message': 'OTP verified successfully. User is now active.'}), 200

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    data = request.json
    user_id = data['user_id']

    # Find user
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Generate new OTP
    otp_code = randint(100000, 999999)
    new_otp = OTP(user_id=user_id, otp=otp_code)
    db.session.add(new_otp)
    db.session.commit()

    # Send OTP via email
    send_otp_email(user.user_email, otp_code)

    return jsonify({'message': 'New OTP sent successfully. Please check your email.'}), 200

@app.route('/worker/login', methods=['POST'])
def worker_login():
    data = request.json
    worker_email = data.get('worker_email')
    worker_password = data.get('worker_password')

    # Find worker by email
    worker = Worker.query.filter_by(worker_email=worker_email).first()
    if not worker:
        return jsonify({'message': 'Worker not found'}), 404

    # Check password
    if not worker.check_password(worker_password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Check if worker is active
    if not worker.is_active:
        return jsonify({'message': 'Worker is not active'}), 403

    # Generate JWT token
    token = jwt.encode({'worker_id': worker.worker_id}, app.config['SECRET_KEY'], algorithm='HS256')

    # Return token and success message
    return jsonify({'token': token, 'message': 'Login successful'}), 200

@app.route('/worker/register', methods=['POST'])
def worker_register():
    data = request.json
    worker_name = data['worker_name']
    worker_email = data['worker_email']
    worker_password = data['worker_password']
    worker_contact = data['worker_contact']
    worker_city = data['worker_city']
    worker_type = data['worker_type']

    # Check if worker already exists
    worker = Worker.query.filter_by(worker_email=worker_email).first()
    if worker:
        return jsonify({'message': 'Worker already exists'}), 400

    # Create new worker with hashed password
    new_worker = Worker(worker_name=worker_name, worker_email=worker_email, worker_password=worker_password,
                        worker_contact=worker_contact, worker_city=worker_city, worker_type=worker_type)
    db.session.add(new_worker)
    db.session.commit()

    # Generate OTP
    otp_code = randint(100000, 999999)
    new_otp = WorkerOTP(worker_id=new_worker.worker_id, otp=otp_code)
    db.session.add(new_otp)
    db.session.commit()

    # Send OTP via email
    send_otp_email(worker_email, otp_code)

    return jsonify({'message': 'Worker registered successfully. Please check your email for the OTP.', 'worker_id': new_worker.worker_id}), 201

@app.route('/worker/verify_otp', methods=['POST'])
def worker_verify_otp():
    data = request.json
    worker_id = data['worker_id']
    otp_code = data['otp']

    # Find worker
    worker = Worker.query.filter_by(worker_id=worker_id).first()
    if not worker:
        return jsonify({'message': 'Worker not found'}), 404

    # Verify OTP
    otp = WorkerOTP.query.filter_by(worker_id=worker_id, otp=otp_code).order_by(WorkerOTP.created_date.desc()).first()
    if not otp:
        return jsonify({'message': 'Invalid OTP'}), 400

    # Update worker status
    worker.is_active = True
    db.session.commit()

    return jsonify({'message': 'OTP verified successfully. Worker is now active.'}), 200

@app.route('/worker/resend_otp', methods=['POST'])
def worker_resend_otp():
    data = request.json
    worker_id = data['worker_id']

    # Find worker
    worker = Worker.query.filter_by(worker_id=worker_id).first()
    if not worker:
        return jsonify({'message': 'Worker not found'}), 404

    # Generate new OTP
    otp_code = randint(100000, 999999)
    new_otp = WorkerOTP(worker_id=worker_id, otp=otp_code)
    db.session.add(new_otp)
    db.session.commit()

    # Send OTP via email
    send_otp_email(worker.worker_email, otp_code)

    return jsonify({'message': 'New OTP sent successfully. Please check your email.'}), 200

@app.route('/cities', methods=['GET'])
def get_cities():
    search_term = request.args.get('q', '')
    if not search_term.strip():
        return jsonify({"error": "Search term cannot be empty"}), 400

    cities = City.query.filter(City.city_name.ilike(f'%{search_term}%')).all()
    city_list = [{'id': city.id, 'city_name': city.city_name} for city in cities]
    return jsonify(city_list), 200

@app.route('/search/plumber', methods=['GET'])
def search_plumbers():
    city_id = request.args.get('city_id')
    selected_date = request.args.get('selected_date')

    # Parse selected_date string to datetime object
    selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d').date()

    # Find all plumbers in the given city
    plumbers = Worker.query.filter_by(worker_city=city_id, worker_type='Plumber').all()

    # Exclude plumbers with pending or ongoing orders on selected_date
    available_plumbers = []
    for plumber in plumbers:
        orders_count = Order.query.filter_by(worker_id=plumber.worker_id)\
                                  .filter(Order.order_status.in_(['Pending', 'Confirmed', 'Ongoing']))\
                                  .filter(Order.selected_date == selected_date_obj)\
                                  .count()
        if orders_count == 0:
            # Calculate overall rating
            avg_rating = calculate_worker_rating(plumber.worker_id)
            available_plumbers.append({
                'worker_id': plumber.worker_id,
                'worker_name': plumber.worker_name,
                'worker_contact': plumber.worker_contact,
                'rating': avg_rating
            })

    return jsonify(available_plumbers), 200


@app.route('/search/electrician', methods=['GET'])
def search_electricians():
    city_id = request.args.get('city_id')
    selected_date = request.args.get('selected_date')

    # Parse selected_date string to datetime object
    selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d').date()

    # Find all electricians in the given city
    electricians = Worker.query.filter_by(worker_city=city_id, worker_type='Electrician').all()

    # Exclude electricians with pending or ongoing orders on selected_date
    available_electricians = []
    for electrician in electricians:
        orders_count = Order.query.filter_by(worker_id=electrician.worker_id)\
                                  .filter(Order.order_status.in_(['Pending', 'Confirmed', 'Ongoing']))\
                                  .filter(Order.selected_date == selected_date_obj)\
                                  .count()
        if orders_count == 0:
            # Calculate overall rating
            avg_rating = calculate_worker_rating(electrician.worker_id)
            available_electricians.append({
                'worker_id': electrician.worker_id,
                'worker_name': electrician.worker_name,
                'worker_contact': electrician.worker_contact,
                'rating': avg_rating
            })

    return jsonify(available_electricians), 200


@app.route('/search/carpenter', methods=['GET'])
def search_carpenters():
    city_id = request.args.get('city_id')
    selected_date = request.args.get('selected_date')

    # Parse selected_date string to datetime object
    selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d').date()

    # Find all carpenters in the given city
    carpenters = Worker.query.filter_by(worker_city=city_id, worker_type='Carpenter').all()

    # Exclude carpenters with pending or ongoing orders on selected_date
    available_carpenters = []
    for carpenter in carpenters:
        orders_count = Order.query.filter_by(worker_id=carpenter.worker_id)\
                                  .filter(Order.order_status.in_(['Pending', 'Confirmed', 'Ongoing']))\
                                  .filter(Order.selected_date == selected_date_obj)\
                                  .count()
        if orders_count == 0:
            # Calculate overall rating
            avg_rating = calculate_worker_rating(carpenter.worker_id)
            available_carpenters.append({
                'worker_id': carpenter.worker_id,
                'worker_name': carpenter.worker_name,
                'worker_contact': carpenter.worker_contact,
                'rating': avg_rating
            })

    return jsonify(available_carpenters), 200


@app.route('/search/mechanic', methods=['GET'])
def search_mechanics():
    city_id = request.args.get('city_id')
    selected_date = request.args.get('selected_date')

    # Parse selected_date string to datetime object
    selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d').date()

    # Find all mechanics in the given city
    mechanics = Worker.query.filter_by(worker_city=city_id, worker_type='Mechanic').all()

    # Exclude mechanics with pending or ongoing orders on selected_date
    available_mechanics = []
    for mechanic in mechanics:
        orders_count = Order.query.filter_by(worker_id=mechanic.worker_id)\
                                  .filter(Order.order_status.in_(['Pending', 'Confirmed', 'Ongoing']))\
                                  .filter(Order.selected_date == selected_date_obj)\
                                  .count()
        if orders_count == 0:
            # Calculate overall rating
            avg_rating = calculate_worker_rating(mechanic.worker_id)
            available_mechanics.append({
                'worker_id': mechanic.worker_id,
                'worker_name': mechanic.worker_name,
                'worker_contact': mechanic.worker_contact,
                'rating': avg_rating
            })

    return jsonify(available_mechanics), 200


# Place order endpoint with authentication and user ID retrieval
@app.route('/place_order', methods=['POST'])
@token_required
def place_order(current_user_id):
    data = request.json
    problem_type = data.get('problem_type')
    problem_details = data.get('problem_details')
    address = data.get('address')
    worker_id = data.get('worker_id')
    selected_date = data.get('selected_date')

    # Validate input
    if not problem_type or not problem_details or not address or not worker_id or not selected_date:
        return jsonify({'message': 'Missing required fields'}), 400

    # Check if the worker is available on the selected date
    orders_count = Order.query.filter_by(worker_id=worker_id)\
                              .filter(Order.order_status.in_(['Pending', 'Ongoing']))\
                              .filter(Order.selected_date == selected_date)\
                              .count()
    if orders_count > 0:
        return jsonify({'message': 'Worker is not available on the selected date'}), 400

    # Create new order
    new_order = Order(
        problem_type=problem_type,
        problem_details=problem_details,
        address=address,
        user_id=current_user_id,  # Use current_user_id obtained from JWT
        worker_id=worker_id,
        selected_date=selected_date
    )

    db.session.add(new_order)
    db.session.commit()

    return jsonify({'message': 'Order placed successfully', 'order_id': new_order.order_id}), 201

# Route to get my orders
@app.route('/my_orders', methods=['GET'])
@token_required
def get_my_orders(current_user_id):
    try:
        # Query orders for the current user
        orders = Order.query.filter_by(user_id=current_user_id).all()

        # Convert orders to a list of dictionaries
        orders_list = [order.to_dict() for order in orders]

        return jsonify(orders_list), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/order/<int:order_id>', methods=['GET'])
@token_required
def get_order(current_user_id, order_id):
    # Find the order by order_id
    order = Order.query.filter_by(order_id=order_id, user_id=current_user_id).first()

    if not order:
        return jsonify({'message': 'Order not found or access denied'}), 404

    # Return the order details in dictionary form
    return jsonify(order.to_dict()), 200


@app.route('/worker/my_orders', methods=['GET'])
@worker_token_required
def get_worker_orders(current_worker_id):
    try:
        # Query orders assigned to the current worker
        orders = Order.query.filter_by(worker_id=current_worker_id).all()

        # Convert orders to a list of dictionaries
        orders_list = [order.to_dict() for order in orders]

        return jsonify(orders_list), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Route to update order status (worker token required)
@app.route('/worker/update_order_status', methods=['PUT'])
@worker_token_required
def update_order_status(current_worker_id):
    data = request.json
    order_id = data.get('order_id')
    new_status = data.get('order_status')

    if not order_id or not new_status:
        return jsonify({'message': 'Missing required fields'}), 400

    # Find the order
    order = Order.query.filter_by(order_id=order_id).first()
    if not order:
        return jsonify({'message': 'Order not found'}), 404

    # Check if the worker is assigned to this order
    if order.worker_id != current_worker_id:
        return jsonify({'message': 'You are not authorized to update this order'}), 403

    # Update order status
    order.order_status = new_status
    db.session.commit()

    # Find the user associated with the order
    user = User.query.filter_by(user_id=order.user_id).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Prepare email content
    subject = f'Taskmaster Order Status Update: Order ID {order_id}'
    recipient = user.user_email
    body = (f'Hello {user.username},\n\n'
            f'We are writing to inform you that your order with Taskmaster (Order ID: {order_id}) has been {new_status}.\n\n'
            f'Order Details:\n'
            f'Problem Type: {order.problem_type}\n'
            f'Problem Details: {order.problem_details}\n'
            f'Address: {order.address}\n'
            f'Selected Date: {order.selected_date}\n\n'
            f'Thank you for choosing Taskmaster for your service needs. We are here to help!')


    # Send email
    send_email(subject, recipient, body)

    return jsonify({'message': 'Order status updated successfully, and notification email sent to the user.'}), 200

@app.route('/order/rate', methods=['POST'])
@token_required
def rate_order(current_user_id):
    data = request.json
    order_id = data.get('order_id')
    rating = data.get('rating')
    
    # Validate input
    if not order_id or not rating:
        return jsonify({'message': 'Order ID and rating are required'}), 400

    if not (1 <= rating <= 5):  # Assuming ratings are between 1 and 5
        return jsonify({'message': 'Rating must be between 1 and 5'}), 400

    # Find the order
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'message': 'Order not found'}), 404

    if order.user_id != current_user_id:
        return jsonify({'message': 'You are not authorized to rate this order'}), 403

    # Update the order with the rating
    order.rating = rating
    db.session.commit()

    return jsonify({'message': 'Rating added successfully'}), 200


def send_otp_email(email, otp_code):
    msg = Message('Your OTP Code', sender='warunadesigns@gmail.com', recipients=[email])
    msg.body = f'Your OTP code for Task Master is {otp_code}.'
    mail.send(msg)

def send_email(subject, recipient, body):
    msg = Message(subject=subject,
                  recipients=[recipient],
                  body=body,
                  sender=app.config['MAIL_USERNAME'])
    try:
        mail.send(msg)
    except Exception as e:
        print(f'Error sending email: {e}')
        
def calculate_worker_rating(worker_id):
    """Calculate the average rating for a worker."""
    ratings = Order.query.filter_by(worker_id=worker_id).all()
    
    if not ratings:
        return 'N/A'
    
    total_rating = sum(order.rating for order in ratings if order.rating is not None)
    count = len([order for order in ratings if order.rating is not None])
    
    if count == 0:
        return 'N/A'
    
    avg_rating = total_rating / count
    return round(avg_rating, 1)  # rounding to 1 decimal place

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
