from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, send_from_directory, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from functools import wraps
from PIL import Image
from datetime import datetime
import os
import zipfile
from io import BytesIO
import pandas as pd
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['THUMBNAIL_FOLDER'] = 'static/hotspotuploads/hotspot_thumbnails'
app.config['HOTSPOT_IMAGE_FOLDER'] = 'static/hotspotuploads/hotspot_images'
app.config['FAVICON_PATH'] = 'static/favicon.ico'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'resamtoedo8'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4'}
SECRET_KEYWORD = 'Himitsudayo'
ADMIN_ID = 'beesan'
ADMIN_PASSWORD = '8355'
# Dummy user data for simplicity
USER_DATA = {
    "public_user": "public_password"
}


# ディレクトリの存在確認と作成
for folder in [app.config['UPLOAD_FOLDER'], app.config['THUMBNAIL_FOLDER'], app.config['HOTSPOT_IMAGE_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    access_count = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, nullable=True)
    projects = db.relationship('Project', backref='user', lazy=True)

class Hotspot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_id = db.Column(db.String(256), nullable=False)
    pitch = db.Column(db.Float, nullable=False)
    yaw = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(1000), nullable=True)
    additional_text = db.Column(db.String(300), nullable=True)
    url = db.Column(db.String(500), nullable=True)
    thumbnail_path = db.Column(db.String(500), nullable=True)
    shared = db.Column(db.Boolean, default=False)
    public = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_comment = db.Column(db.String(300), nullable=True)
    image_filename = db.Column(db.String(256), nullable=True)

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
            'public': self.public,
            'user_id': self.user_id,
            'upload_comment': self.upload_comment,
            'image_filename': self.image_filename
        }

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    files = db.relationship('ProjectFile', backref='project', lazy=True)

class ProjectFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

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

@app.before_first_request
def create_tables():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    user_stats = []

    for user in users:
        user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], user.username)
        if os.path.exists(user_upload_folder):
            total_files = len(os.listdir(user_upload_folder))
            total_data = sum(os.path.getsize(os.path.join(user_upload_folder, f)) for f in os.listdir(user_upload_folder)) / (1024 * 1024)  # MB単位
        else:
            total_files = 0
            total_data = 0
        user_stats.append({
            'id': user.id,
            'username': user.username,
            'access_count': user.access_count,
            'last_login': user.last_login,
            'total_files': total_files,
            'total_data': round(total_data, 2)  # 小数点以下2桁に丸める
        })

    return render_template('admin_panel.html', users=user_stats)

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
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('user_index'))
    
    files = request.files.getlist('file')
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
            if not os.path.exists(user_upload_folder):
                os.makedirs(user_upload_folder)
            filepath = os.path.join(user_upload_folder, filename)
            file.save(filepath)

            if filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
                compress_image(filepath, filename)
                thumbnail_path = generate_thumbnail(filepath, filename)
                flash(f'Image {filename} uploaded and compressed successfully!', 'success')
            elif filename.lower().endswith('.mp4'):
                thumbnail_path = app.config['FAVICON_PATH']
                flash(f'Video {filename} uploaded successfully!', 'success')

            provided_pitch = float(request.form.get('pitch', 0))
            provided_yaw = float(request.form.get('yaw', 0))
            provided_description = request.form.get('description', '')

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
                    public=False,
                    user_id=session['user_id']
                )
                db.session.add(new_hotspot)
                db.session.commit()

    return redirect(url_for('user_index'))

def compress_image(filepath, filename, quality=50):
    with Image.open(filepath) as img:
        img.save(filepath, quality=quality)

def generate_thumbnail(filepath, filename, size=(100, 100), return_url_for_view=True):
    thumbnail_folder = os.path.join(app.config['THUMBNAIL_FOLDER'])
    if not os.path.exists(thumbnail_folder):
        os.makedirs(thumbnail_folder)
    thumbnail_path = os.path.join(thumbnail_folder, filename)
    with Image.open(filepath) as img:
        img.thumbnail(size)
        img.save(thumbnail_path)
    
    if return_url_for_view:
        return url_for('static', filename=f'hotspotuploads/hotspot_thumbnails/{filename}')
    else:
        return f'hotspotuploads/hotspot_thumbnails/{filename}'
    
def check_auth(username, password):
    return USER_DATA.get(username) == password

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.args.get('auth')
        if not auth:
            return abort(401)
        try:
            username, password = auth.split(':')
        except ValueError:
            return abort(401)
        if not check_auth(username, password):
            return abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route('/hotspots', methods=['GET'])
@login_required
def get_hotspots():
    image_id = request.args.get('image_id')
    if image_id:
        hotspots = Hotspot.query.filter_by(image_id=image_id).all()
        return jsonify([hotspot.to_dict() for hotspot in hotspots])
    else:
        return jsonify({'error': 'Image ID is required'}), 400
    
@app.route('/delete_file/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    try:
        logging.debug(f"Attempting to delete file: {filename}")
        user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
        file_path = os.path.join(user_upload_folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            Hotspot.query.filter_by(image_id=filename).delete()
            ProjectFile.query.filter_by(filename=filename).delete()
            db.session.commit()
            logging.debug(f"Successfully deleted file: {filename}")
            return jsonify({'success': True})
        else:
            logging.error(f"File not found: {filename}")
            return jsonify({'success': False, 'message': 'File not found'}), 404
    except Exception as e:
        logging.exception(f"Error deleting file: {filename}")
        response = jsonify({'success': False, 'message': str(e)})
        response.status_code = 500
        return response


@app.route('/update_hotspot/<int:id>', methods=['POST'])
@login_required
def update_hotspot(id):
    data = request.form
    hotspot = Hotspot.query.get(id)
    if hotspot:
        description = data.get('text')
        additional_text = data.get('additional_text')
        url = data.get('url')
        if not description and not additional_text and not url:
            db.session.delete(hotspot)
            db.session.commit()
            return jsonify({"success": True, "message": "Hotspot deleted successfully."})
        
        hotspot.description = description
        hotspot.pitch = data.get('pitch')
        hotspot.yaw = data.get('yaw')
        hotspot.additional_text = additional_text
        hotspot.url = url
        
        if 'image_file' in request.files and request.files['image_file'].filename != '':
            image_file = request.files['image_file']
            if allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['HOTSPOT_IMAGE_FOLDER'], image_filename)
                image_file.save(image_path)
                
                thumbnail_path = generate_thumbnail(image_path, image_filename, return_url_for_view=True)
                hotspot.thumbnail_path = thumbnail_path
                hotspot.image_filename = image_filename
            else:
                return jsonify({"success": False, "message": "Unsupported file type"}), 400

        db.session.commit()
        return jsonify({"success": True, "message": "Hotspot updated successfully"})
    else:
        return jsonify({"success": False, "message": "Hotspot not found"}), 404

@app.route('/save_hotspot', methods=['POST'])
@login_required
def save_hotspot():
    try:
        data = request.form
        image_id = data.get('image_id')
        pitch = data.get('pitch')
        yaw = data.get('yaw')
        text = data.get('text')
        additional_text = data.get('additional_text')
        url = data.get('url')
        upload_comment = data.get('upload_comment')

        if not image_id:
            return jsonify({'success': False, 'message': 'Image ID is required.'}), 400

        new_hotspot = Hotspot(
            image_id=image_id,
            pitch=pitch,
            yaw=yaw,
            description=text,
            additional_text=additional_text,
            url=url,
            user_id=session['user_id'],
            upload_comment=upload_comment
        )

        if 'image_file' in request.files:
            image_file = request.files['image_file']
            if allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['HOTSPOT_IMAGE_FOLDER'], filename)
                image_file.save(image_path)

                thumbnail_path = generate_thumbnail(image_path, filename, return_url_for_view=True)
                new_hotspot.thumbnail_path = thumbnail_path
                new_hotspot.image_filename = filename
            else:
                return jsonify({'success': False, 'message': 'Unsupported file type.'}), 400

        db.session.add(new_hotspot)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Hotspot saved successfully.'})
    except Exception as e:
        app.logger.error(f"Error saving hotspot: {e}")
        return jsonify({'success': False, 'message': 'Internal Server Error.'}), 500

@app.route('/hotspot/<int:id>')
@login_required
def view_hotspot(id):
    hotspot = Hotspot.query.get(id)
    if hotspot:
        user = User.query.get(hotspot.user_id)
        return render_template('hotspot.html', hotspot=hotspot, username=user.username)
    else:
        return "Hotspot not found", 404

@app.route('/uploads/<username>/<filename>')
@login_required
def uploaded_file(username, filename):
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    return send_from_directory(user_upload_folder, filename)

@app.route('/view_image/<username>/<filename>')
@login_required
def view_image(username, filename):
    file_ext = os.path.splitext(filename)[1].lower()
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    file_path = os.path.join(user_upload_folder, filename)
    if os.path.exists(file_path):
        if file_ext in ['.png', '.jpg', '.jpeg']:
            return render_template('view.html', username=username, filename=filename)
        elif file_ext == '.mp4':
            return render_template('viewmovie.html', username=username, filename=filename)
        else:
            return "Unsupported file type", 400
    else:
        return "File not found", 404

@app.route('/get_project_files/<project_id>', methods=['GET'])
@login_required
def get_project_files(project_id):
    if project_id == "None":
        return jsonify({'success': False, 'message': 'No project selected'}), 404

    project = Project.query.get(project_id)
    if project and project.user_id == session['user_id']:
        project_files = ProjectFile.query.filter_by(project_id=project.id).all()
        files = []
        for project_file in project_files:
            file_info = {
                'filename': project_file.filename,
                'shared': project_file.filename in [hotspot.image_id for hotspot in Hotspot.query.filter_by(shared=True).all()],
                'public': project_file.filename in [hotspot.image_id for hotspot in Hotspot.query.filter_by(public=True).all()],
                'thumbnail': url_for('static', filename=generate_thumbnail(os.path.join(app.config['UPLOAD_FOLDER'], session['username'], project_file.filename), project_file.filename, return_url_for_view=False)),
                'username': session['username']
            }
            files.append(file_info)
        return jsonify({'success': True, 'files': files, 'project': {'name': project.name}})
    else:
        return jsonify({'success': False, 'message': 'Project not found or access denied'}), 404



@app.route('/user_index')
@login_required
def user_index():
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    files = os.listdir(user_upload_folder)
    shared_files = [hotspot.image_id for hotspot in Hotspot.query.filter_by(shared=True).all()]
    public_files = [hotspot.image_id for hotspot in Hotspot.query.filter_by(public=True).all()]
    thumbnails = {file: url_for('static', filename=generate_thumbnail(os.path.join(user_upload_folder, file), file, return_url_for_view=False)) if file.lower().endswith(('png', 'jpg', 'jpeg', 'gif')) else app.config['FAVICON_PATH'] for file in files if allowed_file(file)}

    projects = Project.query.filter_by(user_id=session['user_id']).all()
    project_files_dict = {}
    all_project_files = []

    for project in projects:
        project_files = [pf.filename for pf in ProjectFile.query.filter_by(project_id=project.id).all()]
        project_files_dict[project.name] = project_files
        all_project_files.extend(project_files)

    unprojected_files = [file for file in files if file not in all_project_files]

    selected_project_id = request.args.get('project_id')

    return render_template('user_index.html', files=unprojected_files, thumbnails=thumbnails, shared_files=shared_files, public_files=public_files, projects=projects, project_files=project_files_dict, selected_project_id=selected_project_id)




@app.route('/create_project', methods=['POST'])
@login_required
def create_project():
    try:
        data = request.get_json()
        files = data.get('files', [])
        if not files:
            return jsonify({'success': False, 'message': 'No files selected'})

        project_name = f"Project_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        new_project = Project(name=project_name, user_id=session['user_id'])
        db.session.add(new_project)
        db.session.commit()

        for file in files:
            new_project_file = ProjectFile(filename=file, project_id=new_project.id)
            db.session.add(new_project_file)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error creating project: {e}")
        return jsonify({'success': False, 'message': 'Internal Server Error'})


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
            new_hotspot = Hotspot(
                image_id=filename,
                pitch=0,
                yaw=0,
                description='',
                additional_text='',
                url='',
                thumbnail_path=file_path,
                shared=shared,
                user_id=session['user_id']
            )
            db.session.add(new_hotspot)
            db.session.commit()
            return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error updating share status: {e}")
        return jsonify({'success': False, 'message': str(e)})
    
@app.route('/update_open', methods=['POST'])
@login_required
def update_open():
    try:
        data = request.get_json()
        filename = data.get('filename')
        public = data.get('public')
        user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
        file_path = os.path.join(user_upload_folder, filename)

        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File not found'})

        hotspot = Hotspot.query.filter_by(image_id=filename).first()
        if hotspot:
            hotspot.public = public
            db.session.commit()
            return jsonify({'success': True})
        else:
            new_hotspot = Hotspot(
                image_id=filename,
                pitch=0,
                yaw=0,
                description='',
                additional_text='',
                url='',
                thumbnail_path=file_path,
                public=public,
                user_id=session['user_id']
            )
            db.session.add(new_hotspot)
            db.session.commit()
            return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error updating public status: {e}")
        return jsonify({'success': False, 'message': str(e)})   
    
@app.route('/update_project_name/<int:project_id>', methods=['POST'])
@login_required
def update_project_name(project_id):
    data = request.get_json()
    new_name = data.get('name')
    if new_name:
        project = db.session.get(Project, project_id)
        if project and project.user_id == session['user_id']:
            project.name = new_name
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Project not found or access denied'})
    else:
        return jsonify({'success': False, 'message': 'No new name provided'})



@app.route('/update_additional_info/<int:id>', methods=['POST'])
@login_required
def update_additional_info(id):
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    
    hotspot = Hotspot.query.get(id)
    if hotspot:
        hotspot.additional_text = data.get('additional_text', hotspot.additional_text)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Additional information updated successfully'})
    else:
        return jsonify({'success': False, 'message': 'Hotspot not found'}), 404

@app.route('/public_gallery')
def public_gallery():
    public_files = Hotspot.query.filter_by(shared=True).all()
    file_data = []
    for file in public_files:
        file_info = {
            'filename': file.image_id,
            'thumbnail': url_for('static', filename=f'hotspotuploads/hotspot_thumbnails/{file.image_id}'),
            'username': User.query.get(file.user_id).username
        }
        file_data.append(file_info)
    return render_template('public_gallery.html', files=file_data)

@app.route('/open_gallery')
def open_gallery():
    open_files = Hotspot.query.filter_by(public=True).all()
    file_data = []
    for file in open_files:
        file_info = {
            'filename': file.image_id,
            'thumbnail': url_for('static', filename=f'hotspotuploads/hotspot_thumbnails/{file.image_id}'),
            'username': User.query.get(file.user_id).username
        }
        file_data.append(file_info)
    return render_template('open_gallery.html', files=file_data)

@app.route('/hotspot_info/<int:hotspot_id>')
@login_required
def show_hotspot(hotspot_id):
    hotspot = Hotspot.query.get_or_404(hotspot_id)
    user = User.query.get(hotspot.user_id)
    return render_template('hotspot.html', hotspot=hotspot, user=user)

@app.route('/download_project/<int:project_id>', methods=['GET'])
@login_required
def download_project(project_id):
    project_files = ProjectFile.query.filter_by(project_id=project_id).all()
    if not project_files:
        flash('No files found for this project.', 'danger')
        return redirect(url_for('user_index'))
    
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        for project_file in project_files:
            filename = project_file.filename
            user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
            file_path = os.path.join(user_upload_folder, filename)
            if os.path.exists(file_path):
                zf.write(file_path, filename)
    
    memory_file.seek(0)
    return send_file(memory_file, download_name=f'project_{project_id}.zip', as_attachment=True)

@app.route('/download_report', methods=['GET'])
@login_required
def download_report():
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    files = os.listdir(user_upload_folder)
    report_data = []
    for file in files:
        hotspot = Hotspot.query.filter_by(image_id=file).first()
        if hotspot:
            report_data.append({
                'Filename': file,
                'Thumbnail': hotspot.thumbnail_path,
                'Description': hotspot.description,
                'Shared': 'Yes' if hotspot.shared else 'No'
            })
        else:
            report_data.append({
                'Filename': file,
                'Thumbnail': url_for('static', filename=generate_thumbnail(os.path.join(user_upload_folder, file), file, return_url_for_view=False)) if file.lower().endswith(('png', 'jpg', 'jpeg', 'gif')) else app.config['FAVICON_PATH'],
                'Description': '',
                'Shared': 'No'
            })
    
    df = pd.DataFrame(report_data)
    excel_file = BytesIO()
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Report')
    
    excel_file.seek(0)
    return send_file(excel_file, download_name='report.xlsx', as_attachment=True)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@app.route('/delete_project/<int:project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    try:
        project = db.session.get(Project, project_id)
        if project and project.user_id == session['user_id']:
            # プロジェクトに関連するファイルを削除
            project_files = ProjectFile.query.filter_by(project_id=project_id).all()
            for project_file in project_files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], session['username'], project_file.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                # Hotspotエントリを削除
                Hotspot.query.filter_by(image_id=project_file.filename).delete()
                db.session.delete(project_file)

            db.session.delete(project)
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Project not found or access denied'})
    except Exception as e:
        app.logger.error(f"Error deleting project: {e}")
        return jsonify({'success': False, 'message': 'Internal Server Error'})


@app.route('/view_public/<filename>')
@requires_auth
def view_public(filename):
    return render_template('view.html', filename=filename)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)
