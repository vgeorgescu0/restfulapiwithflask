import pymysql
import jwt
import datetime
import os
from functools import wraps
from flask import Flask, jsonify, request, current_app, render_template
from flask_cors import CORS

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
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data:
            return User(user_data[1], user_data[3])
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
            return jsonify({'error': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.get_user_by_username(data['username'])
        except Exception:
            return jsonify({'error': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


def authenticate(username, password):
    user = User.get_user_by_username(username)
    if user and user.check_password(password):
        return user


def create_token(user):
    payload = {
        'sub': user.username,
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


@app.route('/api/v1/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'Only JPG files are allowed'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File successfully uploaded'})


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
def get_users(current_user):
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users_data = cursor.fetchall()
    cursor.close()
    return jsonify(users_data)


@app.route('/api/v1/users', methods=['POST'])
def add_user():
    data = request.get_json()
    name = data['name']
    email = data['email']
    password = data['password']
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (name, email, password) VALUES (%s, %s, %s)', (name, email, password))
    conn.commit()
    cursor.close()
    return jsonify({'message': 'User added successfully'})


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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate(username, password)
        if user:
            token = create_token(user)
            response = jsonify({'access_token': token})
            return response, 200
        else:
            return render_template('login.html', error='Invalid username or password'), 401
    else:
        return render_template('login.html')


@app.route('/protected')
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        abort(401)

    token = auth_header.split(' ')[1]
    user = decode_token(token)

    if not user:
        abort(401)

    return render_template('protected.html', user=user)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html', error='No file part')

        file = request.files['file']

        # if user does not select file, browser also submit an empty part without filename
        if file.filename == '':
            return render_template('upload.html', error='No selected file')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            return render_template('upload.html', success='File successfully uploaded')
        else:
            return render_template('upload.html', error='Invalid file')
    else:
        return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)