from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import csv
import io
import os
import re
from attack_detector import AttackDetector
from elastic_client import ElasticClient

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'  # Required for sessions

detector = AttackDetector()
elastic = ElasticClient()

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
        session_stats = {}
        
        for row in csv_reader:
            # Skip empty rows
            if not row or len(row) == 0:
                continue
                
            row_num += 1
            
            # Safely extract URL and status code with comprehensive None handling
            url = ''
            status_code_int = 0
            
            # Helper function to safely convert to string
            def safe_str(val):
                if val is None:
                    return ''
                try:
                    result = str(val).strip()
                    return result if result and result != 'None' else ''
                except:
                    return ''
            
            # Helper function to safely check if string contains substring
            def safe_contains(text, substring):
                if not text or not substring:
                    return False
                try:
                    return substring.lower() in text.lower()
                except:
                    return False
            
            # Try common CSV column names for URL
            for col_name in ['url', 'URL', 'request_url', 'path', 'request', 'Request-URL']:
                val = row.get(col_name)
                url = safe_str(val)
                if url:
                    break
            
            # If URL not found, try to extract from other fields
            if not url:
                for key, value in row.items():
                    if key is None:
                        continue
                    key_str = safe_str(key)
                    if not key_str:
                        continue
                    
                    value_str = safe_str(value)
                    if not value_str:
                        continue
                    
                    key_lower = key_str.lower()
                    if ('url' in key_lower or 'path' in key_lower or 'request' in key_lower):
                        if safe_contains(value_str, 'http') or '/' in value_str:
                            url = value_str
                            break
            
            # Ensure URL is always a non-None string
            url = url if url else ''
            
            # Try common CSV column names for status code
            status_code_str = ''
            for col_name in ['status', 'status_code', 'HTTP Status', 'code', 'http_status', 'response_code']:
                val = row.get(col_name)
                status_code_str = safe_str(val)
                if status_code_str:
                    break
            
            # Convert status code to integer if possible
            if status_code_str:
                try:
                    status_code_int = int(status_code_str)
                except (ValueError, TypeError):
                    status_code_int = 0
            else:
                status_code_int = 0
            
            # Extract HTTP method
            method = ''
            for col_name in ['method', 'http_method', 'verb', 'HTTP Method', 'request_method']:
                val = row.get(col_name)
                method = safe_str(val)
                if method:
                    break

            # Collect key headers if present
            headers = {}
            header_candidates = [
                'User-Agent','user_agent','user-agent',
                'Referer','Referrer','referer',
                'Host','host',
                'Content-Type','content_type','content-type',
                'Authorization','authorization',
                'Cookie','cookie',
                'X-Forwarded-For','x-forwarded-for',
                'X-Real-IP','x-real-ip',
                'Accept','accept',
                'Accept-Language','accept-language'
            ]
            for key in header_candidates:
                v = safe_str(row.get(key))
                if v:
                    headers[key] = v

            # Final safety check - ensure url is definitely a string
            if url is None:
                url = ''
            url = str(url)
            
            detection_result = detector.analyze_url(url, status_code_int, method, headers)
            
            # Create result entry - ensure all values are JSON-serializable
            result_entry = {
                'row': int(row_num),
                'method': str(method) if method else '',
                'url': str(url) if url is not None else '',
                'status_code': int(status_code_int),
                'classification': str(detection_result.get('classification', 'Normal')),
                'attack_type': str(detection_result.get('attack_type', '')) if detection_result.get('attack_type') else None,
                'severity': str(detection_result.get('severity', 'Low')),
                'indicators': [str(i) for i in detection_result.get('indicators', []) if i is not None],
                'raw_data': {str(k): str(v) if v is not None else '' for k, v in row.items() if k is not None}
            }

            results.append(result_entry)

            ip = ''
            ip_candidates = ['ip','client_ip','remote_ip','source_ip','src_ip','IP']
            for col_name in ip_candidates:
                val = row.get(col_name)
                ip = str(val).strip() if val is not None else ''
                if ip:
                    break
            if not ip:
                xf = headers.get('X-Forwarded-For') or headers.get('x-forwarded-for')
                if xf:
                    ip = xf.split(',')[0].strip()
            if not ip:
                xr = headers.get('X-Real-IP') or headers.get('x-real-ip')
                if xr:
                    ip = xr.strip()

            cookie_val = headers.get('Cookie') or headers.get('cookie')
            session_id = ''
            if cookie_val:
                m = re.search(r'(?:^|;\s*)([A-Za-z0-9_\-]*session|JSESSIONID|PHPSESSID|ASP\.NET_SessionId|sid|sessid)\s*=\s*([^;]+)', cookie_val, re.IGNORECASE)
                if m:
                    session_id = f"{m.group(1)}={m.group(2).strip()}"
                else:
                    session_id = cookie_val[:64]
            if not session_id:
                auth = headers.get('Authorization') or headers.get('authorization')
                if auth:
                    session_id = auth[:64]
            if not session_id:
                ua = headers.get('User-Agent') or headers.get('user-agent') or headers.get('user_agent') or ''
                base = ip if ip else 'unknown'
                session_id = f"{base}|{ua[:32]}"

            s = session_stats.get(session_id)
            if not s:
                s = {
                    'session': session_id,
                    'requests': 0,
                    'normal': 0,
                    'attempted': 0,
                    'successful': 0,
                    'unique_urls': set(),
                    'methods': set()
                }
                session_stats[session_id] = s
            s['requests'] += 1
            s['unique_urls'].add(result_entry['url'])
            if result_entry['method']:
                s['methods'].add(result_entry['method'])
            if result_entry['classification'] == 'Normal':
                s['normal'] += 1
            elif result_entry['classification'] == 'Attempted Attack':
                s['attempted'] += 1
            elif result_entry['classification'] == 'Likely Successful Attack':
                s['successful'] += 1
        
        # Calculate statistics
        total_requests = len(results)
        normal_count = sum(1 for r in results if r['classification'] == 'Normal')
        attempted_count = sum(1 for r in results if r['classification'] == 'Attempted Attack')
        successful_count = sum(1 for r in results if r['classification'] == 'Likely Successful Attack')
        
        stats = {
            'total': total_requests,
            'normal': normal_count,
            'attempted': attempted_count,
            'successful': successful_count
        }
        
        ingest = None
        if elastic.available and os.getenv('ELASTIC_INGEST', 'true').lower() in ('1', 'true', 'yes'):
            ingest = elastic.index_documents(results)
        sessions = []
        for sid, s in session_stats.items():
            sessions.append({
                'session': s['session'],
                'requests': int(s['requests']),
                'normal': int(s['normal']),
                'attempted': int(s['attempted']),
                'successful': int(s['successful']),
                'unique_urls': int(len(s['unique_urls'])),
                'methods': sorted(list(s['methods']))
            })
        sessions.sort(key=lambda x: x['requests'], reverse=True)
        return jsonify({'success': True, 'results': results, 'stats': stats, 'sessions': sessions, 'elastic': ingest})
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error details: {error_details}")
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500


@app.route('/data/sample_logs.csv')
def download_sample():
    """Serve sample CSV file"""
    from flask import send_from_directory
    import os
    return send_from_directory(os.path.join(app.root_path, 'data'), 'sample_logs.csv', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
