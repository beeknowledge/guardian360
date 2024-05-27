from flask import Flask, request, render_template, send_from_directory, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.utils import secure_filename
from flask import flash

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'resamtoedo8'  # セッションおよびフラッシュメッセージに必要
db = SQLAlchemy(app)



class Hotspot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_id = db.Column(db.String(256), nullable=False)
    pitch = db.Column(db.Float, nullable=False)
    yaw = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(1000), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'image_id': self.image_id,
            'pitch': self.pitch,
            'yaw': self.yaw,
            'description': self.description
        }



@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # アップロードされたファイルのタイプに基づいてフラッシュメッセージを設定
            if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                flash(f'Image {filename} uploaded successfully!', 'success')
            elif filename.lower().endswith('.mp4'):
                flash(f'Video {filename} uploaded successfully!', 'success')
            else:
                flash('Unsupported file type', 'error')
    return redirect(url_for('index'))



@app.route('/hotspots', methods=['GET'])
def get_hotspots():
    image_id = request.args.get('image_id')
    if image_id:
        hotspots = Hotspot.query.filter_by(image_id=image_id).all()
        return jsonify([hotspot.to_dict() for hotspot in hotspots])
    else:
        return jsonify({'error': 'Image ID is required'}), 400




@app.route('/delete_file/<filename>', methods=['GET'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return redirect(url_for('index'))
    else:
        return "File not found", 404
    
@app.route('/update_hotspot/<int:id>', methods=['POST'])
def update_hotspot(id):
    data = request.get_json()
    hotspot = Hotspot.query.get(id)
    if hotspot:
        hotspot.description = data.get('text')
        hotspot.pitch = data.get('pitch')
        hotspot.yaw = data.get('yaw')
        db.session.commit()
        return jsonify({"success": True, "message": "Hotspot updated successfully"})
    else:
        return jsonify({"success": False, "message": "Hotspot not found"}), 404


@app.route('/save_hotspot', methods=['POST'])
def save_hotspot():
    data = request.get_json()
    image_id = data.get('imageId')  # JSONからimageIdを取得
    pitch = data['pitch']
    yaw = data['yaw']
    description = data['text']

    if not image_id:
        return jsonify({'success': False, 'message': 'Image ID is required.'}), 400

    new_hotspot = Hotspot(image_id=image_id, pitch=pitch, yaw=yaw, description=description)
    db.session.add(new_hotspot)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Hotspot saved successfully.'})


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/view/<filename>')
def view_image(filename):
    file_ext = os.path.splitext(filename)[1].lower()
    if file_ext in ['.png', '.jpg', '.jpeg']:
        return render_template('view.html', filename=filename)
    elif file_ext == '.mp4':
        return render_template('viewmovie.html', filename=filename)
    else:
        return "Unsupported file type", 400

@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=files)


@app.route('/view_movie/<filename>')
def view_movie(filename):
    # 動画ファイルの拡張子が.mp4であることを確認する
    if filename.lower().endswith('.mp4'):
        return render_template('viewmovie.html', filename=filename)
    else:
        return "Unsupported file type", 400

if __name__ == '__main__':
    app.run(debug=True)
