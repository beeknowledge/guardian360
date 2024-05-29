import logging
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from PIL import Image
from datetime import datetime
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['THUMBNAIL_FOLDER'] = 'static/thumbnails'
app.config['FAVICON_PATH'] = 'static/favicon.ico'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'resamtoedo8'
db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4'}
SECRET_KEYWORD = 'Himitsudayo'
ADMIN_ID = 'beesan'
ADMIN_PASSWORD = '8355'

# Ensure directories exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['THUMBNAIL_FOLDER']):
    os.makedirs(app.config['THUMBNAIL_FOLDER'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    access_count = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, nullable=True)

class Hotspot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_id = db.Column(db.String(256), nullable=False)
    pitch = db.Column(db.Float, nullable=False)
    yaw = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(1000), nullable=True)
    additional_text = db.Column(db.String(300), nullable=True)
    url = db.Column(db.String(500), nullable=True)
    thumbnail_path = db.Column(db.String(500), nullable=True)
    shared = db.Column(db.Boolean, default=False)  # Shared flag
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # User ID

    def to_dict(self):
        return {
            'id': self.id,
            'image_id': self.image_id,
            'pitch': self.pitch,
            'yaw': self.yaw,
            'description': self.description,
            'additional_text': self.additional_text,
            'url': self.url,
            'thumbnail_path': self.thumbnail_path,
            'shared': self.shared,
            'user_id': self.user_id  # Added
        }

@app.before_first_request
def create_tables():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/secret', methods=['GET', 'POST'])
def secret():
    if request.method == 'POST':
        secret_key = request.form['secret_key']
        if secret_key == SECRET_KEYWORD:
            session['can_register'] = True
            return redirect(url_for('register'))
        else:
            flash('Invalid secret key. Please try again.', 'danger')
    return render_template('secret.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'can_register' not in session or not session['can_register']:
        return redirect(url_for('secret'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session.pop('can_register', None)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            user.access_count += 1
            user.last_login = datetime.now()
            db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            
            # Create user-specific upload directory
            user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], user.username)
            if not os.path.exists(user_upload_folder):
                os.makedirs(user_upload_folder)
            
            flash('Login successful!', 'success')
            return redirect(url_for('user_index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_ID and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin_panel')
@admin_required
def admin_panel():
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/admin_add_user', methods=['POST'])
@admin_required
def admin_add_user():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already exists.', 'danger')
    else:
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            filename = secure_filename(file.filename)
            user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
            filepath = os.path.join(user_upload_folder, filename)
            file.save(filepath)
            if allowed_file(filename):
                if filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
                    compress_image(filepath, filename)
                    thumbnail_path = generate_thumbnail(filepath, filename, user_upload_folder)
                    flash(f'Image {filename} uploaded and compressed successfully!', 'success')
                elif filename.lower().endswith('.mp4'):
                    thumbnail_path = app.config['FAVICON_PATH']
                    flash(f'Video {filename} uploaded successfully!', 'success')

                # Extract meaningful hotspot data from request form
                provided_pitch = float(request.form.get('pitch', 0))
                provided_yaw = float(request.form.get('yaw', 0))
                provided_description = request.form.get('description', '')

                # Only create a hotspot if there is meaningful data
                if provided_pitch != 0 or provided_yaw != 0 or provided_description != '':
                    new_hotspot = Hotspot(
                        image_id=filename,
                        pitch=provided_pitch,
                        yaw=provided_yaw,
                        description=provided_description,
                        additional_text=request.form.get('additional_text', ''),
                        url=request.form.get('url', ''),
                        thumbnail_path=thumbnail_path,
                        shared=False,
                        user_id=session['user_id']
                    )
                    db.session.add(new_hotspot)
                    db.session.commit()

                return redirect(url_for('user_index'))
            else:
                flash('Unsupported file type', 'error')
    return redirect(url_for('user_index'))

def compress_image(filepath, filename, quality=50):
    with Image.open(filepath) as img:
        img.save(filepath, quality=quality)

def generate_thumbnail(filepath, filename, user_upload_folder, size=(150, 150)):
    thumbnail_folder = os.path.join(app.config['THUMBNAIL_FOLDER'], session['username'])
    if not os.path.exists(thumbnail_folder):
        os.makedirs(thumbnail_folder)
    thumbnail_path = os.path.join(thumbnail_folder, filename)
    with Image.open(filepath) as img:
        img.thumbnail(size)
        img.save(thumbnail_path)
    return thumbnail_path

@app.route('/hotspots', methods=['GET'])
@login_required
def get_hotspots():
    image_id = request.args.get('image_id')
    if image_id:
        hotspots = Hotspot.query.filter_by(image_id=image_id).all()
        return jsonify([hotspot.to_dict() for hotspot in hotspots])
    else:
        return jsonify({'error': 'Image ID is required'}), 400

@app.route('/delete_file/<filename>', methods=['GET'])
@login_required
def delete_file(filename):
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    file_path = os.path.join(user_upload_folder, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return redirect(url_for('user_index'))
    else:
        return "File not found", 404

@app.route('/update_hotspot/<int:id>', methods=['POST'])
@login_required
def update_hotspot(id):
    data = request.get_json()
    hotspot = Hotspot.query.get(id)
    if hotspot:
        hotspot.description = data.get('text')
        hotspot.pitch = data.get('pitch')
        hotspot.yaw = data.get('yaw')
        hotspot.additional_text = data.get('additional_text')
        hotspot.url = data.get('url')
        db.session.commit()
        return jsonify({"success": True, "message": "Hotspot updated successfully"})
    else:
        return jsonify({"success": False, "message": "Hotspot not found"}), 404

@app.route('/save_hotspot', methods=['POST'])
@login_required
def save_hotspot():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON data.'}), 400
        
        image_id = data.get('imageId')
        pitch = data.get('pitch')
        yaw = data.get('yaw')
        description = data.get('text')
        additional_text = data.get('additional_text')
        url = data.get('url')

        if not image_id:
            return jsonify({'success': False, 'message': 'Image ID is required.'}), 400

        new_hotspot = Hotspot(image_id=image_id, pitch=pitch, yaw=yaw, description=description, additional_text=additional_text, url=url, user_id=session['user_id'])
        db.session.add(new_hotspot)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Hotspot saved successfully.'})
    except Exception as e:
        app.logger.error(f"Error saving hotspot: {e}")
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    return send_from_directory(user_upload_folder, filename)

@app.route('/view/<filename>')
@login_required
def view_image(filename):
    file_ext = os.path.splitext(filename)[1].lower()
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    if file_ext in ['.png', '.jpg', '.jpeg']:
        return render_template('view.html', filename=filename)
    elif file_ext == '.mp4':
        return render_template('viewmovie.html', filename=filename)
    else:
        return "Unsupported file type", 400

@app.route('/user_index')
@login_required
def user_index():
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    files = os.listdir(user_upload_folder)
    shared_files = [hotspot.image_id for hotspot in Hotspot.query.filter_by(shared=True).all()]
    thumbnails = {file: app.config['FAVICON_PATH'] if file.lower().endswith('.mp4') else url_for('static', filename=f'thumbnails/{session["username"]}/{file}') for file in files if allowed_file(file)}
    return render_template('user_index.html', files=files, thumbnails=thumbnails, shared_files=shared_files)

@app.route('/update_share', methods=['POST'])
@login_required
def update_share():
    try:
        data = request.get_json()
        filename = data.get('filename')
        shared = data.get('shared')
        user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
        file_path = os.path.join(user_upload_folder, filename)

        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File not found'})

        hotspot = Hotspot.query.filter_by(image_id=filename).first()
        if hotspot:
            hotspot.shared = shared
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Hotspot not found'})
    except Exception as e:
        app.logger.error(f"Error updating share status: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/public_gallery')
@login_required
def public_gallery():
    shared_hotspots = Hotspot.query.filter_by(shared=True).all()
    files = [hotspot.image_id for hotspot in shared_hotspots]
    thumbnails = {file: app.config['FAVICON_PATH'] if file.lower().endswith('.mp4') else url_for('static', filename=f'thumbnails/{User.query.get(hotspot.user_id).username}/{file}') for file, hotspot in zip(files, shared_hotspots)}
    user_ids = {file: User.query.get(hotspot.user_id).username for file, hotspot in zip(files, shared_hotspots)}
    return render_template('public_gallery.html', files=files, thumbnails=thumbnails, user_ids=user_ids)

@app.route('/view_movie/<filename>')
@login_required
def view_movie(filename):
    if filename.lower().endswith('.mp4'):
        return render_template('viewmovie.html', filename=filename)
    else:
        return "Unsupported file type", 400

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)
