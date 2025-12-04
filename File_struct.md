# HTTP Log Analyzer - File Structure

## Project Structure

```
http-log-analyzer/
│
├── app.py                      # Flask backend application
├── attack_detector.py          # Attack detection engine (LLM + regex)
├── llm_detector.py             # Zero-shot LLM detector (Transformers)
├── elastic_client.py           # Optional Elasticsearch ingestion client
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── FILE_STRUCTURE.md          # This file
│
├── data/
│   └── sample_logs.csv        # Sample CSV file with test attack patterns (200+ entries)
│
├── static/                     # Static files (CSS, JavaScript)
│   ├── style.css              # Shared styles for the application
│   └── script.js              # Combined JavaScript (upload + results functionality)
│
├── templates/                  # HTML templates
│   └── index.html             # Single-page application (upload + results)
│
└── venv/                      # Python virtual environment (dependencies)
    └── ...
```

## File Descriptions

### Backend Files

**`app.py`** - Main Flask application
- Route: `/` - Serves the main page
- Route: `/upload` (POST) - Handles CSV file upload and processing
- Route: `/data/sample_logs.csv` (GET) - Downloads sample CSV file
- Processes CSV files, detects attacks, returns JSON response
- No redirects - single page application

**`attack_detector.py`** - Attack detection module
- Contains `AttackDetector` class
- Detects 6 types of attacks:
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - Command Injection
  - SSRF (Server-Side Request Forgery)
  - Directory Traversal
  - Credential Stuffing
- Detection engines:
  - LLM zero-shot classifier (preferred) using headers + method + URL
  - Regex fallback and optional ensemble mode
- Classifies requests: Normal, Attempted Attack, Likely Successful Attack

**`llm_detector.py`** - Zero-shot LLM detector
- Uses `transformers` pipeline with configurable model
- Incorporates `method` and selected `headers` as context
- Threshold-based multi-label attack detection with indicators

**`elastic_client.py`** - Elasticsearch integration
- Creates index if needed and performs bulk ingestion
- Controlled via env: `ELASTICSEARCH_URL`, `ELASTIC_INDEX`, `ELASTIC_INGEST`

### Frontend Files

**`templates/index.html`** - Single-page application
- Upload section: File upload interface with drag & drop
- Statistics section: Dashboard showing attack statistics
- Results section: Interactive table with search and filter
- All functionality on one page - no redirects

**`static/script.js`** - Combined JavaScript
- File upload handling (drag & drop, file selection)
- AJAX form submission
- Results display (statistics and table)
- Search and filter functionality
- CSV export functionality
- Session table rendering

**`static/style.css`** - Application styles
- Modern, responsive design
- Gradient header
- Interactive components
- Table styling
- Mobile-friendly

### Data Files

**`data/sample_logs.csv`** - Sample test data
- Contains 200+ log entries
- Various attack patterns for testing
- Mix of normal and malicious requests
- Columns supported: `url`, `status_code`, `method`, `headers`, common header names

### Configuration Files

**`requirements.txt`** - Python dependencies
```
Flask==3.0.0
Werkzeug==3.0.1
elasticsearch==8.13.0
transformers==4.44.2
torch>=2.1.0
```

**`README.md`** - Project documentation
- Setup instructions
- Usage guide
- Feature descriptions
- CSV format requirements

## Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Main page (upload + results) |
| `/upload` | POST | Process CSV file, return JSON |
| `/data/sample_logs.csv` | GET | Download sample CSV file |

## Application Flow

1. User visits `/` → Sees upload form
2. User uploads CSV → Form submits via AJAX to `/upload`
3. Server processes file → Detects attacks
4. Server returns JSON → Results and sessions displayed on same page
5. User can search/filter → Results table updates
6. User can export → Downloads filtered results as CSV

## Key Features

- **LLM detection**: Zero-shot classification using URL + headers + method
- **Regex fallback/ensemble**: Optional hybrid detection via env config
- **Method and headers**: Signals used during detection and displayed
- **Session analysis**: Groups requests by session token/IP+UA with metrics
- **Elasticsearch ingestion**: Optional bulk indexing of analyzed results
- **Single-page application**: Upload, stats, results, sessions—no redirects
- **Interactive UI**: Search, filter, and export CSV
- **Responsive design**: Works on desktop and mobile

## Configuration

- `DETECTOR_MODE` = `llm` | `regex` | `ensemble`
- `USE_LLM_DETECTOR` = `true` to prefer LLM when available
- `ELASTICSEARCH_URL`, `ELASTIC_INDEX`, `ELASTIC_INGEST`
- `LLM_MODEL`, `LLM_ATTACK_THRESHOLD`, `LLM_HYPOTHESIS_CLS`, `LLM_HYPOTHESIS_ATTACK`

## References

- Flask: https://flask.palletsprojects.com/en/3.0.x/
- Transformers zero-shot classification: https://huggingface.co/docs/transformers/tasks/zero_shot_classification
- DeBERTa zero-shot model: https://huggingface.co/MoritzLaurer/deberta-v3-large-zeroshot-v2
- Elasticsearch Python client: https://www.elastic.co/guide/en/elasticsearch/client/python/current/index.html
- Bulk API: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
- OWASP Core Rule Set: https://coreruleset.org/
- Elastic Common Schema: https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
- Ollama (local LLMs): https://ollama.com/

## Dependencies

- Python 3.7+
- Flask 3.0.0
- Werkzeug 3.0.1
