from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import sys
import google.genai as genai
import folium
from folium.plugins import HeatMap, MarkerCluster
from xhtml2pdf import pisa
import os
import json
import time
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from utils import load_config, save_config
from tools.shodan_tool import shodan_search
from tools.google_dorks_tool import google_dorks_search
from tools.whois_tool import whois_search
from tools.sherlock_tool import sherlock_search
from tools.virustotal_tool import virustotal_search
from tools.censys_tool import censys_search



app = Flask(__name__)




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
    
    Findings:
    {findings_text}
    """

    if api_key == 'dummy':
        return jsonify({'analysis': '# AI Analysis (Mock)\n\n**Threat Level:** Low\n\nThis is a simulated analysis using a dummy API key.\n- No high-risk findings detected.\n- **Recommendation**: Configure a real Gemini API key for actual analysis.'})

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
    model='gemini-2.5-flash', contents=prompt
)
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
