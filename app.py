from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import csv
import io
# from attack_detector import AttackDetector


app = Flask(__name__)


# detector = AttackDetector()

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
    
    try:
        # Read CSV content
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        results = []
        row_num = 0
            for row in csv_reader:
            if not row or len(row) == 0: # Skip empty rows
                continue 
            row_num += 1



            url = ''
            status_code_int = 0
            

            def safe_str(val):
                if val is None:
                    return ''
                try:
                    result = str(val).strip()
                    return result if result and result != 'None' else ''
                except:
                    return ''
            

            def safe_contains(text, substring):
                if not text or not substring:
                    return False
                try:
                    return substring.lower() in text.lower()
                except:
                    return False




    

if __name__ == '__main__':
    app.run(debug=True, port=5000)
