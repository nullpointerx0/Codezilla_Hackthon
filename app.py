from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import csv
import io
from attack_detector import AttackDetector


app = Flask(__name__)


detector = AttackDetector()

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'File must be a CSV'}), 400

    

if __name__ == '__main__':
    app.run(debug=True, port=5000)
