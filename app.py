from flask import Flask, request, render_template, send_from_directory, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from flask_cors import CORS
from flask import request  # requestをインポート


app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hotspot_id = db.Column(db.String(120), nullable=False)
    text = db.Column(db.Text, nullable=False)

class Hotspot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pitch = db.Column(db.Float, nullable=False)
    yaw = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(300), nullable=False)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/hotspots', methods=['GET'])
def get_hotspots():
    print("Attempting to fetch hotspots...")
    try:
        hotspots = Hotspot.query.all()
        print(f"Fetched {len(hotspots)} hotspots.")
        return jsonify([{'id': hotspot.id, 'pitch': hotspot.pitch, 'yaw': hotspot.yaw, 'description': hotspot.description} for hotspot in hotspots])
    except Exception as e:
        print(f"Error fetching hotspots: {e}")
        return jsonify({'error': str(e)}), 500




@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=files)

@app.route('/view/<filename>')
def view_image(filename):
    return render_template('view.html', filename=filename)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        return redirect(url_for('index'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete_file/<filename>', methods=['GET'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return redirect(url_for('index'))
    else:
        return "File not found", 404

@app.route('/save_hotspot', methods=['POST'])
def save_hotspot():
    data = request.get_json()
    pitch = float(data['pitch'])
    yaw = float(data['yaw'])
    text = data['text']
    new_hotspot = Hotspot(pitch=pitch, yaw=yaw, description=text)
    db.session.add(new_hotspot)
    db.session.commit()
    return jsonify({"success": True, "message": "Hotspot saved successfully"})

if __name__ == '__main__':
    app.run(debug=True)
