from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import sys
import google.generativeai as genai
import folium
from folium.plugins import HeatMap, MarkerCluster
from xhtml2pdf import pisa
import os
import json
import time
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from ipwhois import IPWhois
import pycountry_convert as pc
import whois
import shodan
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import subprocess
import re
import requests
from base64 import urlsafe_b64encode



app = Flask(__name__)

CONFIG_FILE = 'config.json'

# Config functions
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)


# Database setup
def init_db():
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY,
                    type TEXT,
                    value TEXT,
                    source TEXT,
                    lat REAL,
                    lon REAL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    asn TEXT,
                    country TEXT,
                    ports TEXT
                )''')
    
    # Simple migration for existing databases
    try:
        c.execute("ALTER TABLE findings ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN asn TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN country TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN ports TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists
    try:
        c.execute("ALTER TABLE findings ADD COLUMN details TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists

    conn.commit()
    conn.close()



init_db()

# Real OSINT Functions
def shodan_search(query):
    config = load_config()
    api_key = config.get('shodan_api_key')
    if not api_key:
        return [{'type': 'Error', 'value': 'Shodan API key not configured', 'source': 'System'}]
    
    try:
        api = shodan.Shodan(api_key)
        host = api.host(query)
        
        # Data Enrichment for table view
        asn_info = host.get('asn', 'N/A')
        country_name = host.get('country_name', 'N/A')
        ports = ', '.join(str(p) for p in host.get('ports', []))
        
        # Create a more descriptive value for the main table
        hostnames = ', '.join(host.get('hostnames', []))
        value_summary = f"{host.get('ip_str')} | Hostnames: {hostnames}"

        findings = [{
            'type': 'IP',
            'value': value_summary,
            'source': 'Shodan',
            'lat': host.get('latitude'),
            'lon': host.get('longitude'),
            'asn': asn_info,
            'country': country_name,
            'ports': ports,
            'details': host # Add the full host object for the details view
        }]
        return findings
    except shodan.APIError as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'Shodan'}]




def google_dorks_search(query):
    config = load_config()
    api_key = config.get('google_api_key')
    cse_id = config.get('google_cse_id')

    if not api_key or not cse_id:
        return [{'type': 'Error', 'value': 'Google API key or CSE ID not configured', 'source': 'System'}]

    try:
        service = build("customsearch", "v1", developerKey=api_key)
        res = service.cse().list(q=query, cx=cse_id, num=10).execute()
        
        items = res.get('items', [])
        item_count = len(items)
        
        summary_value = f"Found {item_count} results for dork query"
        
        findings = [{
            'type': 'Google Dork',
            'value': summary_value,
            'source': 'Google Dorks',
            'details': res # The full API response
        }]
        return findings
    except HttpError as e:
        return [{'type': 'Error', 'value': f"Google API Error: {e.reason}", 'source': 'Google Dorks'}]
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'Google Dorks'}]

def whois_search(domain):
    try:
        w = whois.whois(domain)
        if not w.get('domain_name'):
            return [{'type': 'Error', 'value': 'WHOIS data not found for domain.', 'source': 'WHOIS'}]

        # Format the result for display in the main table
        info = f"Registrar: {w.registrar}, Created: {w.creation_date}, Expires: {w.expiration_date}"
        
        # The whois object is a dict-like object, but its values can include non-serializable datetime objects.
        # We create a serializable copy.
        details_copy = {}
        for key, value in w.items():
            if isinstance(value, datetime.datetime):
                details_copy[key] = value.isoformat()
            elif isinstance(value, list):
                # Handle lists that might contain datetimes
                details_copy[key] = [v.isoformat() if isinstance(v, datetime.datetime) else v for v in value]
            else:
                details_copy[key] = value

        findings = [{
            'type': 'WHOIS', 
            'value': info, 
            'source': 'WHOIS',
            'details': details_copy
        }]
        return findings
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'WHOIS'}]

def sherlock_search(username):
    try:
        # Add --no-color to prevent ANSI escape codes in the output
        # Add a timeout and run from the user's home directory for consistency
        command = [sys.executable, '-m', 'sherlock', '--no-color', username]
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=120,
            cwd=os.path.expanduser('~')
        )

        if result.returncode != 0:
            error_message = result.stderr or result.stdout
            return [{'type': 'Error', 'value': f"Sherlock exited with an error: {error_message}", 'source': 'Sherlock'}]

        # Count the number of found profiles for the summary
        found_lines = [line for line in result.stdout.splitlines() if line.startswith('[+]')]
        profile_count = len(found_lines)

        summary_value = f"Found {profile_count} profiles for username '{username}'"
        
        findings = [{
            'type': 'Sherlock Scan', 
            'value': summary_value, 
            'source': 'Sherlock',
            'details': result.stdout # Store the raw, formatted stdout
        }]

        return findings
    except FileNotFoundError:
        return [{'type': 'Error', 'value': 'Sherlock not found. Make sure it is installed and in your PATH.', 'source': 'System'}]
    except subprocess.TimeoutExpired:
        return [{'type': 'Error', 'value': 'Sherlock scan timed out after 2 minutes.', 'source': 'Sherlock'}]
    except Exception as e:
        return [{'type': 'Error', 'value': f"An unexpected error occurred: {e}", 'source': 'Sherlock'}]

def virustotal_search(query):
    config = load_config()
    api_key = config.get('virustotal_api_key')
    if not api_key:
        return [{'type': 'Error', 'value': 'VirusTotal API key not configured', 'source': 'System'}]

    headers = {
        "x-apikey": api_key
    }
    
    try:
        # Check if query is an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
            response = requests.get(url, headers=headers)
            response.raise_for_status() # Raise an exception for bad status codes
            resp = response.json()
            
            stats = resp.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            info = f"Malicious: {stats.get('malicious', 0)}, Harmless: {stats.get('harmless', 0)}, Suspicious: {stats.get('suspicious', 0)}"
            return [{'type': 'IP Reputation', 'value': info, 'source': 'VirusTotal', 'details': resp}]
        else: # Assume it's a domain/URL
            url_id = urlsafe_b64encode(query.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            resp = response.json()

            stats = resp.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            info = f"Malicious: {stats.get('malicious', 0)}, Harmless: {stats.get('harmless', 0)}, Suspicious: {stats.get('suspicious', 0)}"
            return [{'type': 'Domain Reputation', 'value': info, 'source': 'VirusTotal', 'details': resp}]
    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors (like 404 Not Found) gracefully
        return [{'type': 'Error', 'value': f"VirusTotal API Error: {e.response.status_code} {e.response.reason}", 'source': 'VirusTotal'}]
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'VirusTotal'}]

def censys_search(query):
    config = load_config()
    token = config.get('censys_api_id') 
    if not token:
        return [{'type': 'Error', 'value': 'Censys Personal Access Token not configured', 'source': 'System'}]

    # Headers for the new Censys Platform API v3
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json"
    }
    
    # The new Censys Platform API v3 endpoint for hosts
    url = f"https://api.platform.censys.io/v3/global/asset/host/{query}"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        resp = response.json()

        # Correctly parse the new v3 response structure
        services = []
        resource = resp.get('result', {}).get('resource', {})
        for service in resource.get('services', []):
            # Use 'transport_protocol' as confirmed by the JSON response
            services.append(f"{service.get('port')}/{service.get('transport_protocol')}")
        
        info = f"Services: {', '.join(services)}"
        
        return [{'type': 'Censys Host', 'value': info, 'source': 'Censys', 'details': resp.get('result', {})}]
    except requests.exceptions.HTTPError as e:
        # The new API might return a more detailed error message in the response body
        try:
            error_details = e.response.json().get('error', str(e))
        except json.JSONDecodeError:
            error_details = str(e)
        return [{'type': 'Error', 'value': f"Censys API Error: {e.response.status_code} - {error_details}", 'source': 'Censys'}]
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'Censys'}]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/collect', methods=['POST'])
def collect():
    query = request.form['query']
    tool = request.form['tool']
    findings = []
    if tool == 'shodan':
        findings = shodan_search(query)

    elif tool == 'google_dorks':
        findings = google_dorks_search(query)
    elif tool == 'whois':
        findings = whois_search(query)
    elif tool == 'sherlock':
        findings = sherlock_search(query)
    elif tool == 'virustotal':
        findings = virustotal_search(query)
    elif tool == 'censys':
        findings = censys_search(query)
    
    # Store in DB
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    for f in findings:
        # Need to serialize the details dict to a JSON string for DB storage
        details_json = json.dumps(f.get('details'), indent=4) if f.get('details') else None
        c.execute("INSERT INTO findings (type, value, source, lat, lon, asn, country, ports, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (f['type'], f.get('value'), f.get('source'), f.get('lat'), f.get('lon'), f.get('asn'), f.get('country'), f.get('ports'), details_json))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'findings': findings})

@app.route('/search', methods=['GET'])
def search():
    keyword = request.args.get('keyword', '')
    port = request.args.get('port', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    query_parts = ["SELECT id, type, value, source, lat, lon, timestamp, asn, country, ports, details FROM findings WHERE value LIKE ?"]
    params = ['%' + keyword + '%']
    
    if port:
        query_parts.append("AND ports LIKE ?")
        params.append('%' + port + '%')
    
    if start_date:
        query_parts.append("AND timestamp >= ?")
        params.append(start_date)
        
    if end_date:
        query_parts.append("AND timestamp <= ?")
        params.append(end_date + ' 23:59:59') # Include the entire end day
        
    query_parts.append("ORDER BY timestamp DESC")
    
    query = ' '.join(query_parts)
    c.execute(query, params)
    
    results = c.fetchall()
    conn.close()
    return jsonify(results)

@app.route('/heatmap')
def heatmap():
    port = request.args.get('port', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    conn = sqlite3.connect('osint.db')
    c = conn.cursor()

    query_parts = ["SELECT lat, lon, value, asn, country FROM findings WHERE lat IS NOT NULL AND lon IS NOT NULL"]
    params = []

    if port:
        query_parts.append("AND ports LIKE ?")
        params.append('%' + port + '%')

    if start_date:
        query_parts.append("AND timestamp >= ?")
        params.append(start_date)
        
    if end_date:
        query_parts.append("AND timestamp <= ?")
        params.append(end_date + ' 23:59:59')

    query = ' '.join(query_parts)
    c.execute(query, params)

    points = c.fetchall()
    conn.close()
    
    heatmap_html_path = 'static/heatmap.html'

    if points:
        m = folium.Map(location=[20, 0], zoom_start=2)
        heat_data = [[point[0], point[1]] for point in points]
        HeatMap(heat_data).add_to(m)
        marker_cluster = MarkerCluster().add_to(m)
        for lat, lon, value, asn, country in points:
            popup_html = f"<b>IP:</b> {value}<br><b>Country:</b> {country}<br><b>ASN:</b> {asn}"
            folium.Marker(
                location=[lat, lon],
                popup=popup_html,
            ).add_to(marker_cluster)
        m.save(heatmap_html_path)
    else:
        no_data_html = """
        <!DOCTYPE html>
        <html>
        <head><title>No Data</title></head>
        <body><h3>No geolocation data available for the current filter.</h3></body>
        </html>
        """
        with open(heatmap_html_path, 'w') as f:
            f.write(no_data_html)

    return send_file(heatmap_html_path)

@app.route('/export_pdf')
def export_pdf():
    conn = sqlite3.connect('osint.db')
    # Use a dictionary cursor to make data handling easier
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM findings ORDER BY timestamp DESC")
    db_findings = c.fetchall()
    
    c.execute("SELECT lat, lon, value FROM findings WHERE lat IS NOT NULL AND lon IS NOT NULL")
    points = c.fetchall()
    conn.close()

    # Process findings for the template
    findings_for_template = []
    for finding in db_findings:
        finding_dict = dict(finding)
        if finding_dict['details']:
            try:
                # Parse and re-stringify for pretty printing in the report
                details_obj = json.loads(finding_dict['details'])
                finding_dict['details'] = json.dumps(details_obj, indent=4)
            except (json.JSONDecodeError, TypeError):
                # If it's not a valid JSON string (like for theHarvester), just pass it as is
                pass
        findings_for_template.append(finding_dict)

    heatmap_path = None
    heatmap_filename = f"static/heatmap_{int(time.time())}.png"
    map_html_filename = f"static/map_{int(time.time())}.html"

    try:
        if points:
            # 1. Generate hybrid heatmap HTML
            m = folium.Map(location=[20, 0], zoom_start=2)
            heat_data = [[point['lat'], point['lon']] for point in points]
            HeatMap(heat_data).add_to(m)
            marker_cluster = MarkerCluster().add_to(m)
            for lat, lon, value in points:
                folium.Marker(location=[lat, lon], popup=value).add_to(marker_cluster)
            m.save(map_html_filename)

            # 2. Take screenshot with Selenium
            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            
            service = ChromeService()
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_window_size(1200, 800) # Set window size to prevent cut-off map
            
            driver.get(f"file://{os.path.abspath(map_html_filename)}")
            time.sleep(2) # Allow map to render
            driver.save_screenshot(heatmap_filename)
            driver.quit()
            heatmap_path = os.path.abspath(heatmap_filename)

        # 3. Render HTML for PDF
        rendered_html = render_template(
            'report_template.html',
            findings=findings_for_template,
            generation_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            heatmap_path=heatmap_path
        )
        
        # 4. Create PDF
        output_filename = 'report.pdf'
        with open(output_filename, "w+b") as pdf_file:
            pisa_status = pisa.CreatePDF(rendered_html, dest=pdf_file)

        if pisa_status.err:
            return "Error generating PDF", 500
            
        return send_file(output_filename, as_attachment=True)
    finally:
        # 5. Cleanup
        if heatmap_path and os.path.exists(heatmap_filename):
            os.remove(heatmap_filename)
        if os.path.exists(map_html_filename):
            os.remove(map_html_filename)

@app.route('/analyze', methods=['GET'])
def analyze():
    config = load_config()
    api_key = config.get('gemini_api_key')
    
    if not api_key:
        return jsonify({'error': 'Gemini API key not configured. Please add it in Settings.'}), 400

    # Fetch recent findings to summarize
    conn = sqlite3.connect('osint.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # Limit to last 50 findings to avoid overflowing context window
    c.execute("SELECT type, value, source, country, ports FROM findings ORDER BY timestamp DESC LIMIT 50")
    findings = [dict(row) for row in c.fetchall()]
    conn.close()

    if not findings:
        return jsonify({'error': 'No findings available to analyze.'}), 400

    findings_text = json.dumps(findings, indent=2)
    
    prompt = f"""
    You are an expert Cyber Threat Intelligence Analyst. 
    Analyze the following OSINT findings and provide a comprehensive summary.
    
    Focus on:
    1. Key Threats: Identify any high-risk findings (e.g., open sensitive ports, malicious IPs).
    2. Geographic Distribution: Where are the targets located?
    3. Recommendations: What specific actions should be taken?

    Format your response in Markdown.
    
    Findings:
    {findings_text}
    """

    if api_key == 'dummy':
        return jsonify({'analysis': '# AI Analysis (Mock)\n\n**Threat Level:** Low\n\nThis is a simulated analysis using a dummy API key.\n- No high-risk findings detected.\n- **Recommendation**: Configure a real Gemini API key for actual analysis.'})

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        return jsonify({'analysis': response.text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/settings')
def settings():
    return render_template('settings.html')



@app.route('/clean_db', methods=['POST'])
def clean_db():
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    c.execute("DELETE FROM findings")
    conn.commit()
    conn.close()
    return jsonify({'message': 'Database cleaned successfully!'})

@app.route('/delete_findings', methods=['POST'])
def delete_findings():
    data = request.get_json()
    ids_to_delete = data.get('ids', [])
    
    if not ids_to_delete:
        return jsonify({'status': 'error', 'message': 'No IDs provided'}), 400
        
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    # Using placeholders to prevent SQL injection
    placeholders = ','.join('?' for _ in ids_to_delete)
    query = f"DELETE FROM findings WHERE id IN ({placeholders})"
    
    c.execute(query, ids_to_delete)
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': f'Deleted {len(ids_to_delete)} findings.'})

@app.route('/get_date_range', methods=['GET'])
def get_date_range():
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    c.execute("SELECT MIN(timestamp), MAX(timestamp) FROM findings")
    result = c.fetchone()
    conn.close()
    
    # Convert to YYYY-MM-DD format for date inputs
    min_date = result[0].split(' ')[0] if result[0] else ''
    max_date = result[1].split(' ')[0] if result[1] else ''
    
    return jsonify({'min_date': min_date, 'max_date': max_date})

if __name__ == '__main__':
    app.run(debug=True)
