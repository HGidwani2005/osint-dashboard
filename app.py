from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import folium
import pdfkit
import os

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'osint.db')

# Ensure DB/schema
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    value TEXT,
                    source TEXT,
                    lat REAL,
                    lon REAL
                )''')
    conn.commit()
    conn.close()

init_db()

# ---------------- Simulators ----------------
def simulate_shodan(query):
    return [
        ('IP', '8.8.8.8', 'Shodan', 37.3861, -122.0839),
        ('IP', '192.168.1.1', 'Shodan', 37.7749, -122.4194),
        ('IP', '203.0.113.1', 'Shodan', 35.6762, 139.6503)
    ]

def simulate_theharvester(query):
    # produce an email based on query or a generic
    domain = query.split('@')[-1] if '@' in query else 'example.com'
    return [('Email', f'admin@{domain}', 'theHarvester', None, None)]

def simulate_googledorks(query):
    return [('Domain', f'{query}.example', 'Google Dorks', None, None)]

def simulate_maltego(query):
    # Maltego often returns linked entities (domains, emails, IPs). Simulate a mix
    return [
        ('Domain', f'{query}', 'Maltego', None, None),
        ('IP', '203.0.113.5', 'Maltego', 35.6895, 139.6917),
        ('Email', f'contact@{query}', 'Maltego', None, None)
    ]

# ---------------- Utilities ----------------
def regenerate_heatmap():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT lat, lon, value FROM findings WHERE lat IS NOT NULL AND lon IS NOT NULL")
    rows = c.fetchall()
    conn.close()

    # If there are coordinates, generate folium map. Otherwise create minimal placeholder
    m = folium.Map(location=[20, 0], zoom_start=2)
    for lat, lon, val in rows:
        folium.Marker([lat, lon], popup=val).add_to(m)

    os.makedirs('static', exist_ok=True)
    m.save(os.path.join('static', 'heatmap.html'))

# ---------------- Routes ----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/collect', methods=['POST'])
def collect():
    """
    Expects JSON body: {"query": "...", "tool": "shodan"|"theharvester"|"googledorks"|"maltego"}
    Returns JSON: {'status': 'success', 'inserted': n} or {'error': ...}
    """
    try:
        data = request.get_json(force=True)
        query = data.get('query')
        tool = data.get('tool')

        if not query or not tool:
            return jsonify({'error': 'Missing query or tool'}), 400

        # choose simulator
        if tool == 'shodan':
            results = simulate_shodan(query)
        elif tool == 'theharvester':
            results = simulate_theharvester(query)
        elif tool == 'googledorks' or tool == 'google_dorks':
            results = simulate_googledorks(query)
        elif tool == 'maltego':
            results = simulate_maltego(query)
        else:
            return jsonify({'error': 'Invalid tool specified'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        inserted = 0
        # Insert if not duplicate (same type+value+source)
        for rec in results:
            rtype, rvalue, rsource, rlat, rlon = rec
            c.execute("SELECT 1 FROM findings WHERE type=? AND value=? AND source=? LIMIT 1", (rtype, rvalue, rsource))
            if c.fetchone():
                # skip duplicate
                continue
            c.execute("INSERT INTO findings (type, value, source, lat, lon) VALUES (?, ?, ?, ?, ?)",
                      (rtype, rvalue, rsource, rlat, rlon))
            inserted += 1

        conn.commit()
        conn.close()

        # regenerate map
        regenerate_heatmap()

        return jsonify({'status': 'success', 'inserted': inserted, 'requested': len(results)}), 200

    except Exception as e:
        print("Error in /collect:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/findings', methods=['GET'])
def findings():
    # returns list of objects with id, type, value, source, lat, lon
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, type, value, source, lat, lon FROM findings ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            'id': r[0],
            'type': r[1],
            'value': r[2],
            'source': r[3],
            'lat': r[4],
            'lon': r[5]
        })
    return jsonify(out)

@app.route('/delete', methods=['POST'])
def delete_entry():
    """
    Expects JSON: {"id": 123}
    """
    try:
        data = request.get_json(force=True)
        fid = data.get('id')
        if fid is None:
            return jsonify({'error': 'Missing id'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM findings WHERE id = ?", (fid,))
        deleted = c.rowcount
        conn.commit()
        conn.close()

        # regenerate map in case lat/lon removed
        regenerate_heatmap()

        if deleted:
            return jsonify({'status': 'success', 'deleted': deleted}), 200
        else:
            return jsonify({'status': 'not_found'}), 404

    except Exception as e:
        print("Error in /delete:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/heatmap', methods=['GET'])
def heatmap_route():
    path = os.path.join('static', 'heatmap.html')
    if os.path.isfile(path):
        return send_file(path)
    else:
        # generate one on the fly (empty map)
        regenerate_heatmap()
        return send_file(path)

@app.route('/export', methods=['GET'])
def export_route():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT type, value, source FROM findings ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    html = "<h1>OSINT Findings Report</h1><table border='1' cellpadding='6'><tr><th>Type</th><th>Value</th><th>Source</th></tr>"
    for r in rows:
        html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>"
    html += "</table>"

    pdf_path = os.path.join('osint_report.pdf')
    pdfkit.from_string(html, pdf_path)
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
