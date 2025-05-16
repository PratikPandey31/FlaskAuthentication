from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import uuid
import os
from sqlalchemy import Text
from dotenv import load_dotenv
import os

load_dotenv() 

app = Flask(__name__)

CORS(app, origins="http://localhost:3000", supports_credentials=True)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=True)
    password = db.Column(db.Text, nullable=True) 



    
    def __repr__(self):
        return f"<User {self.email}>"

with app.app_context():
    db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            
            if not current_user:
                return jsonify({'message': 'Invalid token!'}), 401
                
        except:
            return jsonify({'message': 'Invalid token!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# Routes
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'message': 'Missing required fields!'}), 400
    
    user_exists = User.query.filter_by(email=data['email']).first()
    if user_exists:
        return jsonify({'message': 'User already exists!'}), 409
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    public_id = str(uuid.uuid4())
    
    new_user = User(
        public_id=public_id,
        name=data['name'],
        email=data['email'],
        password=hashed_password
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password!'}), 400

    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    if check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'token': token,
            'name': user.name,
            'email': user.email
        })
    
    return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/dashboard', methods=['GET'])
@token_required
def get_dashboard_data(current_user):
    return jsonify({
        'name': current_user.name,
        'email': current_user.email,
        'message': 'Welcome to your dashboard!'
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5500, debug=True)
