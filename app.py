import pymysql
import jwt
import datetime
import os
from functools import wraps
from flask import Flask, jsonify, request, current_app, render_template, abort
from flask_cors import CORS
from werkzeug.utils import secure_filename 

app = Flask(__name__)
CORS(app)

# MySQL database connection
conn = pymysql.connect(host='localhost',
                       user='root',
                       password='1234567890',
                       db='449_db')


# User model
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    @staticmethod
    def get_user_by_username(username):
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = %s', (username))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data:
            return User(username, user_data[0])
        else:
            return None

    def check_password(self, password):
        return self.password == password


# JWT authentication
app.config['SECRET_KEY'] = 'your_secret_key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        if not token:
            abort(401)
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.get_user_by_username(data['username'])
        except Exception:
            abort(401)
        return f(current_user, *args, **kwargs)
    return decorated


def authenticate(username, password):
    user = User.get_user_by_username(username)
    if user and user.check_password(password):
        return user


def create_token(user):
    payload = {
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


def decode_token(token):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return User.get_user_by_username(payload['sub'])
    except jwt.ExpiredSignatureError:
        return None


# File handling
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'jpg'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_uploaded_files():
    return [f for f in os.listdir(UPLOAD_FOLDER) if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]


@app.route('/api/v1/protec',methods=['GET'])
@token_required
def protec(user):
    return render_template('protected.html',user=user)

@app.route('/api/v1/upload', methods=['POST'])
@token_required
def upload():
    if 'file' not in request.files:
        return jsonify({'error':'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error':'No file selected'}) , 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return jsonify({'message':'File successfully uploaded'})
    else:
        return jsonify({'error':'Invalid file'}), 415


@app.route('/api/v1/files', methods=['GET'])
@token_required
def get_files(current_user):
    files = []
    for filename in os.listdir(current_app.config['UPLOAD_FOLDER']):
        if allowed_file(filename):
            files.append(filename)
    return jsonify(files)


@app.route('/api/v1/public/items', methods=['GET'])
def get_public_items():
    public_items = ['item 1', 'item 2', 'item 3']
    return jsonify(public_items)


@app.route('/api/v1/users', methods=['GET'])
@token_required
def users_get(current_user):
    cursor = conn.cursor()
    cursor.execute('SELECT username, email FROM users')
    users_data = cursor.fetchall()
    cursor.close()
    return jsonify(users_data)


@app.route('/api/v1/users', methods=['POST'])
def user_add():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']
    cursor = conn.cursor()
    errors = []
    # check for existing users
    cursor.execute('SELECT username FROM users WHERE username = %s', (username))
    if cursor.fetchone():
        errors.append('User already exists')
    
    # check for existing email
    cursor.execute('SELECT email FROM users WHERE email = %s', (email))
    if cursor.fetchone():
        return jsonify({'error':'Email already exists'})
    
    # return all errors
    if len(errors) > 0:
        return jsonify({'errors':errors})

    cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)', (username, email, password))
    conn.commit()
    cursor.close()
    user = User(username=username, password=password)
    token = create_token(user)
    return jsonify({'token': token, 'message': 'User added successfully'})

@app.route('/api/v1/users/login',methods=['POST'])
def user_login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = authenticate(username, password)
    if user:
        token = create_token(user)
        response = jsonify({'token': token, 'message': 'User logged in successfully'})
        return response, 200
    else:
        response = jsonify({'error': 'Invalid user/pass combo'})
        return response, 401

# error handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(415)
def bad_media_type(error):
    return jsonify({'error': 'Bad Media Type'}), 415


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# Routes
@app.route('/')
def index():
    return 'Hello, World!'


@app.route('/public')
def public():
    public_items = ['Public item 1', 'Public item 2', 'Public item 3']
    return render_template('public.html', public_items=public_items)


@app.route('/signup')
def signup():
    e = request.args.get('error')
    username = request.args.get('username')
    email = request.args.get('email')
    return render_template('signup.html',e=e,username=username,email=email)


@app.route('/login', methods=['GET', 'POST'])
def login():
    e = request.args.get('error')
    username = request.args.get('username')
    return render_template('login.html', error=e, username=username)


@app.route('/protected')
def protected():
    user = None
    auth_header = request.headers.get('Authorization')
    if auth_header:
        token = auth_header.split(' ')[1]
        user = decode_token(token)
    
    if not user:
        user = 'Not logged in'

    return render_template('protec.html', user=user)


def create_tables():
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username Varchar(100) NOT NULL UNIQUE,
            password Varchar(256) NOT NULL,
            email Varchar(320) UNIQUE
        )''')

def clear_tables():
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS users;''')


if __name__ == '__main__':
    import sys
    print(sys.argv)
    if '--init' in sys.argv:
        clear_tables()
        create_tables()
        print('Cleared and recreated tables!')
        sys.argv.remove('--init')
    
    if '--cleanup' in sys.argv:
        clear_tables()
        print('Removed our database tables!')
        sys.argv.remove('--cleanup')

    if len(sys.argv) > 1:
        raise ValueError(f'Unhandled arguements: {sys.argv[1:]}')

    app.run(debug=True)
