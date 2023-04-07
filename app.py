from flask import Flask, jsonify, request, abort
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import pymysql
import os
from flask_cors import CORS
from werkzeug.utils import secure_filename


app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = '449supersecretkey'

jwt = JWTManager(app)

# MySQL connection
conn = pymysql.connect(
        host='localhost',
        user='root',
        password="1234567890",
        db='449_db',
        cursorclass=pymysql.cursors.DictCursor
        )


# User model
class User:

    # Get user by username
    def get_user_by_name(username):
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = % s', (username))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data:
            return user_data
        else:
            abort(404, 'User not found')

    # Get user by id
    def get_user_by_id(id):
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = % s', (id))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data:
            return user_data
        else:
            abort(404, 'User not found')


# File model
class JpgFileCheck:

    # Check if file is allowed
    def allowed_file(filename):
        return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg'}

    # Check if file size is allowed
    def allowed_file_size(file):
        return file <= 5 * 1024 * 1024


# Login endpoint
@app.route('/api/v1/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # Obtain user data
    if request.method == 'POST':
        user_data = User.get_user_by_name(username)
    else:
        abort(404, 'User not found')

    # Validate credentials
    if user_data["username"] is None or not user_data["password"] == password:
        abort(401, 'Invalid username or password')

    access_token = create_access_token(identity=user_data['id'])
    return jsonify({'access_token': access_token})


# Protected endpoint
@app.route('/api/v1/protected', methods=['GET'])
@jwt_required()  # Only authenticated users can access this endpoint
def protected():
    user_id = get_jwt_identity()
    user_data = User.get_user_by_id(user_id)
    return jsonify({'message': f'Hello {user_data["username"]}! You are logged in!'})


# Upload file to uploads folder
@app.route('/api/v1/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        abort(404, 'No file part')

    file = request.files['file']

    if file.filename == '':
        abort(404, 'No selected file')

    file_size = request.headers.get('Content-Length', type=int)
    if not JpgFileCheck.allowed_file_size(file_size):
        abort(413, 'File size too large')

    if file and JpgFileCheck.allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads/', filename)
        file.save(file_path)
        return jsonify({'message': 'File successfully uploaded'})
    else:
        abort(415, 'File type not supported')


# Public endpoint
@app.route('/api/v1/movies', methods=['GET'])
def get_movies():
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM movies")
    movies = cursor.fetchall()
    conn.close()

    # Create a list of movies
    movies_list = []
    for movie in movies:
        movies_list.append([f'Movie: {movie["movie"]}',
                            f'Description: {movie["description"]}',
                            f'Rating: {movie["rating"]}'])
    return movies_list


# Error handler
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'message': '400 ERROR: Bad request'}), 400


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'message': '401 ERROR: Unauthorized'}), 401


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'message': '404 ERROR: Not found'}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'message': '405 ERROR: Method not allowed'}), 405


@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'message': '413 ERROR: Request entity too large'}), 413


@app.errorhandler(415)
def unsupported_media_type(e):
    return jsonify({'message': '415 ERROR: Unsupported media type'}), 415


@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'message': '500 ERROR: Internal server error'}), 500


if __name__ == '__main__':
    app.config['UPLOAD_FOLDER'] = 'uploads'

    # ensure the uploads folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    app.run(debug=True)
